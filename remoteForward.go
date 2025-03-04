package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
)

const (
	httpBindPort            = 80
	forwardedTCPChannelType = "forwarded-tcpip"
)

const bufferSize = 32 << 10 // 32 kB buffer.
var bufPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, bufferSize)
		return &buffer
	},
}

func forwardHandler(conn *sshConnection, req *ssh.Request, execRequestCompleted chan execRequestCompletedData, cancellationCtx context.Context) (bool, []byte) {
	var reqPayload remoteForwardRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		log.Printf("error in tcpip-forward: %s", err)
		return false, []byte{}
	}

	log.Printf("Session %s started", hex.EncodeToString(conn.SessionID()))

	// Wait for SSH session handler to finish or connection close
	session := <-execRequestCompleted
	if session.channel == nil {
		log.Printf("Session %s channel is nil", hex.EncodeToString(conn.SessionID()))
		return false, []byte{}
	}

	// Cache channel for communication with client upon receiving HTTP requests
	conn.SetSessionChannel(&session.channel)

	// For retaining the same tunnelName name in case of an SHH client interruption,
	// Firstly, the tunnelName must not be taken.
	// The client must send its tunnelName name via a channel along with an id (id=dhskjdshf24343,tunnelName=tunnel)
	// TODO: Move to another func
	cmdParts := strings.Split(session.request, ",")
	clientID := ""
	tunnelName := ""
	header := ""
	connectionType := ""
	headerSpecified := false

	for _, p := range cmdParts {
		p = strings.ToLower(strings.TrimSpace(p))
		idIndex := strings.Index(p, "id=")
		tunnelNameIndex := strings.Index(p, "tunnelname=")
		connTypeIndex := strings.Index(p, "type=")
		headerIndex := strings.Index(p, "header=")

		if idIndex == 0 {
			// Found id
			clientID = p[idIndex+len("id="):]
		} else if tunnelNameIndex == 0 {
			// Found tunnelName
			tunnelName = p[tunnelNameIndex+len("tunnelname="):]
		} else if connTypeIndex == 0 {
			// Found connectio type
			connectionType = p[connTypeIndex+len("type="):]

			if connectionType != "https" && connectionType != "http" && connectionType != "tcp" {
				log.Printf("invalid connectionType %s", connectionType)
				return false, []byte(fmt.Sprintf("invalid connectionType %s", connectionType))
			}
		} else if headerIndex == 0 {
			// Found header
			header = p[headerIndex+len("header="):]
			headerSpecified = true
		}
	}

	if clientID == "" {
		log.Printf("id empty setting equal to session id %s", hex.EncodeToString(conn.SessionID()))
		clientID = hex.EncodeToString(conn.SessionID())
	}

	// Server localhost:port to listen for http requests at
	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))

	// Update connection with tunnelName and payload
	conn.SetRequestForwardPayload(&reqPayload)

	// TCP or HTTP?
	// For TCP, the connection is one-to-one meaning the local listener is exclusively for this SSH client.
	// For HTTP (port 80/httpBindPort), the connection is shared and thus many-to-one meaning the local listener on server is shared across many HTTP Clients.
	if connectionType == "http" || connectionType == "https" {
		// Mimic ^[a-zA-Z0-9](?!.*--)[a-zA-Z0-9-]+[a-zA-Z0-9]$ as Go does not support lookarounds
		tunnelNameValid := tunnelNameValid(tunnelName)

		if tunnelName != "" && !tunnelNameValid {
			log.Printf("Specified tunnelName '%s' not valid", tunnelName)
			io.WriteString(session.channel, fmt.Sprintf("Specified tunnelName '%s' not valid\n", tunnelName))
		}

		var err error
		tunnelNameTakenOrInvalid := false

		sshTunnelListenersLock.Lock()
		if tunnelNameValid {
			s, ok := sshTunnelListeners[addr+tunnelName]
			if ok && s.clientID == clientID {
				log.Printf("Discarding existing tunnelName cache for same client id %s", clientID)
				tunnelNameTakenOrInvalid = false
			} else if ok && s.clientID != clientID {
				tunnelNameTakenOrInvalid = true
				io.WriteString(session.channel, fmt.Sprintf("Specified tunnelName '%s' already taken\n", tunnelName))
			}
		} else {
			tunnelNameTakenOrInvalid = true
		}

		for {
			if tunnelNameTakenOrInvalid {
				tunnelName, err = generateRandomTunnelName()
				if err != nil {
					log.Printf("error generating tunnelName: %s", err)
					return false, []byte("error generating tunnelName")
				}
				_, tunnelNameTakenOrInvalid = sshTunnelListeners[addr+tunnelName]
			} else {
				break
			}
		}

		// Cache context under tunnelName and local bind address (localhost:80)
		log.Printf("using tunnelName %s", tunnelName)

		conn.SetTunnelName(tunnelName)
		sshListenerData := sshTunnelsListenerData{
			conn:           conn,
			reqPayload:     &reqPayload,
			sessionID:      hex.EncodeToString(conn.SessionID()),
			clientID:       clientID,
			hostHeader:     nil,
			connectionType: connectionType,
		}
		if headerSpecified {
			sshListenerData.hostHeader = &header
		}

		sshTunnelListeners[addr+tunnelName] = sshListenerData

		sshTunnelListenersLock.Unlock()

		if domainPath {
			io.WriteString(session.channel, fmt.Sprintf("%s/%s\n", domainURL, tunnelName))
		} else {
			io.WriteString(session.channel, fmt.Sprintf("%s://%s.%s\n", domainURI.Scheme, tunnelName, domainURI.Hostname()))
		}

		log.Printf("Received tcpip-forward for session %s started", hex.EncodeToString(conn.SessionID()))

		// Initially, I tried using the Go built-in http server instead of peeking through TCP data.
		// However, that opened a can of wormholes. The default http implementation got in the way, so
		// I had to hijack the connection which ended up being the same result. In both cases, the TCP connection
		// is not being re-used. Actually, in the TCP mode (not http/hijacking), it is possible to re-use the connection,
		// but it requires a decent amount of work to figure out when the request body ended.

		// Does the single HTTP listener already exist?
		forwardsLock.Lock()
		var httpListener net.Listener
		httpListenerObject, ok := forwards[addr]
		if !ok {
			var err error
			httpListener, err = net.Listen("tcp", addr)
			if err != nil {
				forwardsLock.Unlock()
				log.Fatalf("error listening for address %s: %s", addr, err)
				return false, []byte{}
			}
			// Add this SSH client to the listeners list of HTTP
			// Keep http listener available until app shuts down.
			forwards[addr] = forwardsListenerData{listener: httpListener, conType: HTTPConnectionType}
		} else {
			httpListener = httpListenerObject.listener
		}
		forwardsLock.Unlock()

		// Only execute this the first time we open an HTTP listener
		if !ok {
			go func() {
				for {
					// Accept new connections from HTTP here
					httpConnection, err := httpListener.Accept()
					if err != nil {
						select {
						case <-cancellationCtx.Done():
							log.Println("Http listener: Cancellation requested")
							return
						default:
						}
						log.Printf("error accepting new HTTP connections at %s: %s", httpListener.Addr(), err)
						continue
					}

					go handleHttpConnection(httpConnection, addr)
				}
			}()
		}

		// Local listening address on server (eg localhost:80)
		_, destPortStr, _ := net.SplitHostPort(httpListener.Addr().String())
		destPort, _ := strconv.Atoi(destPortStr)

		return true, ssh.Marshal(&remoteForwardSuccess{uint32(destPort)})
	} else {

		var ln net.Listener
		var err error
		forwardsLock.Lock()
		// If port already taken and is the same client, take over.
		requestBindPort := int(reqPayload.BindPort)

		// 0 means allocate a random port
		if requestBindPort == 0 {
			// Find the 1st available port above 1000
			for p := 1000; p <= 1<<16; p++ {
				addr = net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(p))
				if _, ok := forwards[addr]; !ok {
					requestBindPort = p
					reqPayload.BindPort = uint32(p)
					break
				}
			}
		}

		o, ok := forwards[addr]
		if !ok || o.clientID == clientID {
			// Port not taken by taken same client
			// create a new listener
			if o.clientID == clientID {
				log.Printf("Discarding existing tunnelName cache for same client id %s", clientID)
				o.listener.Close()
			}

			ln, err = net.Listen("tcp", addr)
			if err != nil {
				log.Printf("error listening for TCP address %s: %s", addr, err)
				forwardsLock.Unlock()
				return false, []byte{}
			}
			forwards[addr] = forwardsListenerData{listener: ln, clientID: clientID, sessionID: hex.EncodeToString(conn.SessionID()), conType: TCPConnectionType}
		} else {
			// Port taken
			io.WriteString(session.channel, fmt.Sprintf("TCP port %d is already taken.\n", reqPayload.BindPort))
			forwardsLock.Unlock()
			return false, []byte{}
		}
		forwardsLock.Unlock()

		// Write server host:port to the SSH client.
		io.WriteString(session.channel, fmt.Sprintf("%s:%d\n", domainURI.Hostname(), requestBindPort))

		go func() {
			for {
				// Listen to local port N (ie other than httpBindPort)
				tcpConnection, err := ln.Accept()
				if err != nil {
					select {
					case <-cancellationCtx.Done():
						log.Println("TCP listener: Cancellation requested")
						return
					default:
					}
					log.Printf("error accepting new TCP connection at %s: %s", ln.Addr(), err)
					break
				}
				_, destPortStr, _ := net.SplitHostPort(ln.Addr().String())
				destPort, _ := strconv.Atoi(destPortStr)

				originAddr, orignPortStr, _ := net.SplitHostPort(tcpConnection.RemoteAddr().String())
				originPort, _ := strconv.Atoi(orignPortStr)
				payload := ssh.Marshal(&remoteForwardChannelData{
					DestAddr:   reqPayload.BindAddr,
					DestPort:   uint32(destPort),
					OriginAddr: originAddr,
					OriginPort: uint32(originPort),
				})

				go func() {
					io.WriteString(session.channel, fmt.Sprintf("Received tcp request from %s\n", tcpConnection.RemoteAddr().String()))
					ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
					if err != nil {
						log.Printf("error opening %s SSH channel: %s", forwardedTCPChannelType, err)
						tcpConnection.Close()
						return
					}
					go ssh.DiscardRequests(reqs)
					go func() {
						defer func() {
							if r := recover(); r != nil {
								log.Debugf("Recovered from %s", r)
							}
						}()

						defer ch.Close()
						defer tcpConnection.Close()
						buf := bufPool.Get().(*[]byte)
						defer bufPool.Put(buf)
						io.CopyBuffer(ch, tcpConnection, *buf)
					}()
					go func() {
						defer func() {
							if r := recover(); r != nil {
								log.Debugf("Recovered from %s", r)
							}
						}()

						defer ch.Close()
						defer tcpConnection.Close()
						buf := bufPool.Get().(*[]byte)
						defer bufPool.Put(buf)
						io.CopyBuffer(tcpConnection, ch, *buf)
					}()
				}()
			}

			forwardsLock.Lock()
			o, ok := forwards[addr]
			if ok && o.sessionID == hex.EncodeToString(conn.SessionID()) {
				log.Printf("Closing TCP listener for session %s", hex.EncodeToString(conn.SessionID()))
				delete(forwards, addr)
				o.listener.Close()
			}
			forwardsLock.Unlock()
		}()

		return true, ssh.Marshal(&remoteForwardSuccess{uint32(requestBindPort)})

	}

}

func handleHttpConnection(httpConnection net.Conn, addr string) {
	httpBuf := bufPool.Get().(*[]byte)
	defer bufPool.Put(httpBuf)
	defer httpConnection.Close()
	hadPreviousRequests := false

	defer func() {
		if r := recover(); r != nil {
			log.Debugf("Recovered from error handling http connection: %s", r)
		}
	}()

	for {
		log.Printf("Waiting for a new http request on TCP connection")

		// TODO: Reuse httpProcessor across multiple requests on the same TCP connection
		httpProcessor := newHttpProcessor(httpConnection, *httpBuf)

		// Extract http request headers to get tunnelName
		var tunnelName string
		var host string
		var path string
		var err error
		if domainPath {
			path, err = httpProcessor.GetURLPath()
		} else {
			host, err = httpProcessor.GetHost()
		}
		if err != nil && hadPreviousRequests && (err == io.EOF || strings.HasSuffix(err.Error(), ": EOF") ||
			strings.Contains(err.Error(), "use of closed network connection")) {
			// Expected error client only wanted one request
			log.Printf("Request TCP connection terminated")
			return
		}
		log.Printf("Http request started")
		if err != nil {
			if domainPath {
				log.Printf("could not find URL path: %s", err)
				io.WriteString(httpConnection, "HTTP/1.1 400 Bad Request\r\nContent-Type:text/html\r\n\r\nCould not find a valid URL path.")

			} else {
				log.Printf("could not find Host header: %s", err)
				io.WriteString(httpConnection, "HTTP/1.1 400 Bad Request\r\nContent-Type:text/html\r\n\r\nCould not find a valid Host.")
			}
			httpConnection.Close()

			return
		}
		if domainPath {
			tunnelName, err = extractTunnelNameFromURLPath(path, domainURI)

		} else {
			tunnelName, err = extractSubdomain(host, domainURI.Host)
		}
		if err != nil {
			if domainPath {
				log.Printf("could not find URL path: %s", err)
				io.WriteString(httpConnection, "HTTP/1.1 400 Bad Request\r\nContent-Type:text/html\r\n\r\nCould not find a valid URL path.")

			} else {
				log.Printf("could not find Host header: %s", err)
				io.WriteString(httpConnection, "HTTP/1.1 400 Bad Request\r\nContent-Type:text/html\r\n\r\nCould not find a valid Host.")
			}
			httpConnection.Close()

			return
		}

		hadPreviousRequests = true
		if _, ok := httpProcessor.GetContentLength(); !ok {
			// Invalid content-length
			io.WriteString(httpConnection, "HTTP/1.1 400 Bad Request\r\nContent-Type:text/html\r\n\r\nInvalid Content-Length header.")
			httpConnection.Close()

			return
		}

		log.Printf("Incoming http request from %s", httpConnection.RemoteAddr())

		log.Printf("Found tunnelName %q in http request", tunnelName)

		sshClient, ok := sshTunnelListeners[addr+tunnelName]
		if !ok {
			log.Printf("no listeners found for the tunnelName %s", tunnelName)
			io.WriteString(httpConnection, "HTTP/1.1 400 Bad Request\r\nContent-Type:text/html\r\n\r\nNo listeners found.")
			httpConnection.Close()

			return
		}
		sessionChannel := sshClient.conn.GetSessionChannel()
		if sessionChannel != nil {
			io.WriteString(*sessionChannel, fmt.Sprintf("Received http request from %s\n", httpConnection.RemoteAddr().String()))
		}
		sshReqPayload := sshClient.reqPayload
		if sshReqPayload == nil {
			log.Printf("no SSH clients found for the tunnelName %s", tunnelName)
			io.WriteString(httpConnection, "HTTP/1.1 400 Bad Request\r\nContent-Type:text/html\r\n\r\nNo SSH client found.")
			httpConnection.Close()

			return
		}
		conn := sshClient.conn

		if sshClient.hostHeader != nil {
			log.Printf("Setting Host header to %q", *sshClient.hostHeader)
			httpProcessor.SetHostHeader(*sshClient.hostHeader)
		}

		httpProcessor.ReadHeadersIfNeeded()
		if httpProcessor.request {

			stripUrlPrefix := ""
			if domainPath {
				stripUrlPrefix = domainURI.Path + "/" + tunnelName
			}
			newURL, _ := replaceRequestURL(httpProcessor.requestRawURI, sshClient.hostHeader, stripUrlPrefix)
			if newURL != httpProcessor.requestRawURI {
				log.Debugf("Adjusting http request URL from %q to %q", httpProcessor.requestRawURI, newURL)
				httpProcessor.replaceHttpRequestURL(newURL)
			}
		}

		originAddr, orignPortStr, _ := net.SplitHostPort(httpConnection.RemoteAddr().String())
		originPort, _ := strconv.Atoi(orignPortStr)
		payload := ssh.Marshal(&remoteForwardChannelData{
			DestAddr:   sshReqPayload.BindAddr,
			DestPort:   uint32(httpBindPort),
			OriginAddr: originAddr,
			OriginPort: uint32(originPort),
		})

		sshChannel, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)

		if err != nil {
			httpConnection.Close()

			log.Printf("error opening %s channel: %s", forwardedTCPChannelType, err)
			return
		}

		// If the client specified "https", wrap the connection with tls.
		// Need to wrap sshChannel with net.Conn methods.
		var sshChannelConn net.Conn

		if sshClient.connectionType == "https" {
			// No need to verify TLS chain as the user manually requested it and to allow self-signed certificates to work.
			// Also, this improves performance.
			sshChannelConn = tls.Client(newSSHChannelConnection(&sshChannel, conn.cancellationCtx), &tls.Config{InsecureSkipVerify: true})

		} else {
			// http
			sshChannelConn = newSSHChannelConnection(&sshChannel, conn.cancellationCtx)
		}

		// Remote http connection underlying TCP socket closed remotely
		remoteTCPConnectionClose := false
		var wg sync.WaitGroup
		wg.Add(2)
		go ssh.DiscardRequests(reqs)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Debugf("Recovered from %s", r)
				}
			}()

			defer wg.Done()
			buf := bufPool.Get().(*[]byte)
			defer bufPool.Put(buf)

			n, err := io.CopyBuffer(sshChannelConn, httpProcessor.GetReader(), *buf)
			if err != nil {
				log.Debugf("error copying to SSH channel: %s", err)
			}
			log.Debugf("Copied %v bytes from http request to SSH channel", n)

		}()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Debugf("Recovered from %s", r)
				}
			}()

			defer wg.Done()
			buf := bufPool.Get().(*[]byte)
			defer bufPool.Put(buf)
			buf2 := bufPool.Get().(*[]byte)
			defer bufPool.Put(buf2)

			defer sshChannelConn.Close()
			// Wrap sshChannel as well to avoid calling .Read multiple times. Otherwise, this will block.
			sshChannelWrapper := &eofReader{r: sshChannelConn}
			responseHttpProcessor := newHttpProcessor(sshChannelWrapper, *buf2)
			responseHttpProcessor.requestMethod = httpProcessor.requestMethod
			n, err := io.CopyBuffer(httpConnection, responseHttpProcessor.GetReader(), *buf)
			if err != nil {
				log.Debugf("error copying from SSH channel: %s", err)
			}
			log.Debugf("Copied %v bytes from SSH channel to http response", n)
			remoteTCPConnectionClose = sshChannelWrapper.EOF
			if remoteTCPConnectionClose {
				log.Debugln("remote TCP connection closed")
			}

		}()
		wg.Wait()

		log.Printf("Http request ended")

		if remoteTCPConnectionClose {
			// Do not wait for additional incoming HTTP requests by closing client/incoming TCP connection
			// since the destination closed their end
			break
		}
		httpProcessor.Close()
	}
}

func cancelForwardHandler(conn *sshConnection, req *ssh.Request, ctx context.Context) (bool, []byte) {
	var reqPayload remoteForwardCancelRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		log.Printf("error in cancel-tcpip-forward: %s", err)
		return false, []byte{}
	}
	if reqPayload.BindPort == httpBindPort {
		// We don't want to delete the only HTTP listener we have
		tunnelName := conn.GetTunnelName()
		if tunnelName != nil {
			cacheKey := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort))) + *conn.GetTunnelName()

			sshTunnelListenersLock.Lock()
			s, ok := sshTunnelListeners[cacheKey]
			if ok && s.sessionID == hex.EncodeToString(conn.SessionID()) {
				delete(sshTunnelListeners, cacheKey)
				log.Printf("Purged cache for session %s", s.sessionID)
			}
			sshTunnelListenersLock.Unlock()
		}
		return true, nil
	}
	// TCP only
	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	forwardsLock.Lock()
	lnO, ok := forwards[addr]
	forwardsLock.Unlock()
	if ok {
		lnO.listener.Close()
	}
	return true, nil
}
