package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	httpBindPort            = 80
	forwardedTCPChannelType = "forwarded-tcpip"
)

func formatTunnelLine(from, localTarget string) string {
	return fmt.Sprintf("Tunneling %s -> %s\n", from, localTarget)
}

const bufferSize = 32 << 10 // 32 kB buffer.
var bufPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, bufferSize)
		return &buffer
	},
}

type ctxKey int

const (
	ctxKeyTunnel ctxKey = iota
	ctxKeyOrigin
	ctxKeyTunnelName
)

type originInfo struct {
	addr string
	port uint32
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
	localTarget := ""
	headerSpecified := false

	for _, p := range cmdParts {
		p = strings.ToLower(strings.TrimSpace(p))
		idIndex := strings.Index(p, "id=")
		tunnelNameIndex := strings.Index(p, "tunnelname=")
		connTypeIndex := strings.Index(p, "type=")
		headerIndex := strings.Index(p, "header=")
		localTargetIndex := strings.Index(p, "localtarget=")

		if idIndex == 0 {
			clientID = p[idIndex+len("id="):]
		} else if tunnelNameIndex == 0 {
			tunnelName = p[tunnelNameIndex+len("tunnelname="):]
		} else if connTypeIndex == 0 {
			connectionType = p[connTypeIndex+len("type="):]

			if connectionType != "https" && connectionType != "http" && connectionType != "tcp" && connectionType != "udp" {
				log.Printf("invalid connectionType %s", connectionType)
				return false, []byte(fmt.Sprintf("invalid connectionType %s", connectionType))
			}
		} else if headerIndex == 0 {
			header = p[headerIndex+len("header="):]
			headerSpecified = true
		} else if localTargetIndex == 0 {
			localTarget = p[localTargetIndex+len("localtarget="):]
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
		requestedTunnelName := tunnelName
		var sameClientReuse, takenByOtherClient bool

		sshTunnelListenersLock.Lock()
		if tunnelNameValid {
			if s, ok := sshTunnelListeners[addr+tunnelName]; ok {
				if s.clientID == clientID {
					sameClientReuse = true
				} else {
					takenByOtherClient = true
					tunnelNameTakenOrInvalid = true
				}
			}
		} else {
			tunnelNameTakenOrInvalid = true
		}

		for tunnelNameTakenOrInvalid {
			tunnelName, err = generateRandomTunnelName()
			if err != nil {
				sshTunnelListenersLock.Unlock()
				log.Printf("error generating tunnelName: %s", err)
				return false, []byte("error generating tunnelName")
			}
			_, tunnelNameTakenOrInvalid = sshTunnelListeners[addr+tunnelName]
		}

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

		// Side effects now that the critical section is released.
		if sameClientReuse {
			log.Printf("Discarding existing tunnelName cache for same client id %s", clientID)
		}
		if takenByOtherClient {
			io.WriteString(session.channel, fmt.Sprintf("Specified tunnelName '%s' already taken\n", requestedTunnelName))
		}
		log.Printf("using tunnelName %s", tunnelName)
		conn.SetTunnelName(tunnelName)

		var publicURL string
		if domainPath {
			publicURL = fmt.Sprintf("%s/%s", domainURL, tunnelName)
		} else {
			publicURL = fmt.Sprintf("%s://%s.%s", domainURI.Scheme, tunnelName, domainURI.Hostname())
		}
		io.WriteString(session.channel, formatTunnelLine(publicURL, localTarget))

		log.Printf("Received tcpip-forward for session %s started", hex.EncodeToString(conn.SessionID()))

		// Ensure a shared http.Server exists for this bind address. The server
		// routes requests by tunnelName (subdomain or URL path) and forwards
		// them through an httputil.ReverseProxy whose Transport opens a new
		// SSH forwarded-tcpip channel per dial.
		httpListener, err := ensureHTTPServer(addr, cancellationCtx)
		if err != nil {
			log.Fatalf("error listening for address %s: %s", addr, err)
			return false, []byte{}
		}

		_, destPortStr, _ := net.SplitHostPort(httpListener.Addr().String())
		destPort, _ := strconv.Atoi(destPortStr)

		return true, ssh.Marshal(&remoteForwardSuccess{uint32(destPort)})
	}

	if connectionType == "udp" {
		var udpConn net.PacketConn
		var err error
		requestBindPort := int(reqPayload.BindPort)

		if requestBindPort == 0 {
			udpConn, err = net.ListenPacket("udp", net.JoinHostPort(reqPayload.BindAddr, "0"))
			if err != nil {
				log.Printf("error listening for UDP at %s:0: %s", reqPayload.BindAddr, err)
				return false, []byte{}
			}
			_, portStr, _ := net.SplitHostPort(udpConn.LocalAddr().String())
			p, _ := strconv.Atoi(portStr)
			requestBindPort = p
			reqPayload.BindPort = uint32(p)
			addr = net.JoinHostPort(reqPayload.BindAddr, portStr)
		} else {
			forwardsLock.Lock()
			if existing, ok := forwards[addr]; ok {
				if existing.clientID == clientID {
					log.Printf("Discarding existing UDP forward for same client id %s", clientID)
					existing.listener.Close()
					delete(forwards, addr)
				} else {
					forwardsLock.Unlock()
					io.WriteString(session.channel, fmt.Sprintf("UDP port %d is already taken.\n", reqPayload.BindPort))
					return false, []byte{}
				}
			}
			forwardsLock.Unlock()

			udpConn, err = net.ListenPacket("udp", addr)
			if err != nil {
				log.Printf("error listening for UDP address %s: %s", addr, err)
				return false, []byte{}
			}
		}

		forwardsLock.Lock()
		forwards[addr] = forwardsListenerData{
			listener:  udpConn,
			clientID:  clientID,
			sessionID: hex.EncodeToString(conn.SessionID()),
			conType:   UDPConnectionType,
		}
		forwardsLock.Unlock()
		conn.AddForwardAddr(addr)

		io.WriteString(session.channel, formatTunnelLine(fmt.Sprintf("UDP %s:%d", domainURI.Hostname(), requestBindPort), localTarget))

		go runUDPListener(conn, udpConn, &reqPayload, addr, cancellationCtx)

		return true, ssh.Marshal(&remoteForwardSuccess{uint32(requestBindPort)})
	}

	// TCP mode.
	var ln net.Listener
	var err error
	requestBindPort := int(reqPayload.BindPort)

	if requestBindPort == 0 {
		// Let the kernel pick a free port atomically — no need to hold
		// forwardsLock across a scan. The bound address is what we register.
		ln, err = net.Listen("tcp", net.JoinHostPort(reqPayload.BindAddr, "0"))
		if err != nil {
			log.Printf("error listening for TCP at %s:0: %s", reqPayload.BindAddr, err)
			return false, []byte{}
		}
		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		p, _ := strconv.Atoi(portStr)
		requestBindPort = p
		reqPayload.BindPort = uint32(p)
		addr = net.JoinHostPort(reqPayload.BindAddr, portStr)
	} else {
		// Caller-specified port. Briefly lock only to check for an existing
		// same-client takeover, then release before the listen syscall.
		forwardsLock.Lock()
		if existing, ok := forwards[addr]; ok {
			if existing.clientID == clientID {
				log.Printf("Discarding existing tunnelName cache for same client id %s", clientID)
				existing.listener.Close()
				delete(forwards, addr)
			} else {
				forwardsLock.Unlock()
				io.WriteString(session.channel, fmt.Sprintf("TCP port %d is already taken.\n", reqPayload.BindPort))
				return false, []byte{}
			}
		}
		forwardsLock.Unlock()

		ln, err = net.Listen("tcp", addr)
		if err != nil {
			log.Printf("error listening for TCP address %s: %s", addr, err)
			return false, []byte{}
		}
	}

	forwardsLock.Lock()
	forwards[addr] = forwardsListenerData{
		listener:  ln,
		clientID:  clientID,
		sessionID: hex.EncodeToString(conn.SessionID()),
		conType:   TCPConnectionType,
	}
	forwardsLock.Unlock()
	conn.AddForwardAddr(addr)

	io.WriteString(session.channel, formatTunnelLine(fmt.Sprintf("TCP %s:%d", domainURI.Hostname(), requestBindPort), localTarget))

	go func() {
		for {
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

// ensureHTTPServer returns the shared HTTP listener for addr, starting one if
// it does not yet exist. The http.Server services all tunnels bound to addr
// and routes per-request by tunnelName (subdomain or URL path).
func ensureHTTPServer(addr string, cancellationCtx context.Context) (net.Listener, error) {
	forwardsLock.Lock()
	if existing, ok := forwards[addr]; ok {
		forwardsLock.Unlock()
		l, ok := existing.listener.(net.Listener)
		if !ok {
			return nil, fmt.Errorf("address %s is already bound by a non-HTTP listener (%s)", addr, existing.conType)
		}
		return l, nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		forwardsLock.Unlock()
		return nil, err
	}
	forwards[addr] = forwardsListenerData{listener: ln, conType: HTTPConnectionType}
	forwardsLock.Unlock()

	server := &http.Server{
		Handler: newTunnelHandler(addr),
		BaseContext: func(_ net.Listener) context.Context {
			return cancellationCtx
		},
	}

	go func() {
		<-cancellationCtx.Done()
		server.Close()
	}()

	go func() {
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Debugf("HTTP server for %s exited: %v", addr, err)
		}
	}()

	return ln, nil
}

// newTunnelHandler builds the http.Handler that dispatches to the right
// tunnel by looking up sshTunnelListeners and forwards via httputil.ReverseProxy.
func newTunnelHandler(addr string) http.Handler {
	transport := &http.Transport{
		// Reuse SSH channels across HTTP requests. sshChannelConnection
		// implements real read/write deadlines, so IdleConnTimeout reaps
		// stale pooled channels. Flip DisableKeepAlives=true to get a fresh channel per request.
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialSSHChannel(ctx)
		},
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			c, err := dialSSHChannel(ctx)
			if err != nil {
				return nil, err
			}
			// InsecureSkipVerify mirrors the previous behavior: user explicitly
			// requested https, and we want self-signed upstreams to work.
			tlsConn := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				c.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	proxy := &httputil.ReverseProxy{
		Director:  tunnelDirector,
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Debugf("reverse proxy error for %s: %v", r.URL.Path, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tunnelName, err := resolveTunnelName(r)
		if err != nil {
			if domainPath {
				log.Printf("could not find URL path (path=%q, domainURI=%q): %s", r.URL.Path, domainURI.String(), err)
				http.Error(w, "Could not find a valid URL path.", http.StatusBadRequest)
			} else {
				log.Printf("could not find Host header (request host=%q, domainHost=%q): %s", r.Host, domainURI.Hostname(), err)
				http.Error(w, "Could not find a valid Host.", http.StatusBadRequest)
			}
			return
		}

		sshTunnelListenersLock.RLock()
		data, ok := sshTunnelListeners[addr+tunnelName]
		sshTunnelListenersLock.RUnlock()
		if !ok {
			log.Printf("no listeners found for the tunnelName %s", tunnelName)
			http.Error(w, "No listeners found.", http.StatusBadRequest)
			return
		}
		if data.reqPayload == nil {
			log.Printf("no SSH clients found for the tunnelName %s", tunnelName)
			http.Error(w, "No SSH client found.", http.StatusBadRequest)
			return
		}

		log.Printf("Incoming http request from %s", r.RemoteAddr)
		log.Printf("Found tunnelName %q in http request", tunnelName)

		if sessionChannel := data.conn.GetSessionChannel(); sessionChannel != nil {
			io.WriteString(*sessionChannel, fmt.Sprintf("Received http request from %s\n", r.RemoteAddr))
		}

		originAddr, originPortStr, _ := net.SplitHostPort(r.RemoteAddr)
		originPort, _ := strconv.Atoi(originPortStr)

		ctx := context.WithValue(r.Context(), ctxKeyTunnel, &data)
		ctx = context.WithValue(ctx, ctxKeyOrigin, originInfo{addr: originAddr, port: uint32(originPort)})
		ctx = context.WithValue(ctx, ctxKeyTunnelName, tunnelName)

		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolveTunnelName extracts the tunnelName from either the Host header
// (subdomain mode) or the URL path (domainPath mode).
func resolveTunnelName(r *http.Request) (string, error) {
	if domainPath {
		return extractTunnelNameFromURLPath(r.URL.Path, domainURI)
	}
	host := r.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return extractSubdomain(host, domainURI.Hostname())
}

// tunnelDirector rewrites the request before it is sent upstream. It sets the
// URL scheme, rewrites the Host/Origin headers when the client specified a
// custom header, and strips the tunnel prefix from the path in domainPath mode.
func tunnelDirector(r *http.Request) {
	data, _ := r.Context().Value(ctxKeyTunnel).(*sshTunnelsListenerData)
	tunnelName, _ := r.Context().Value(ctxKeyTunnelName).(string)

	if data == nil {
		return
	}

	if data.connectionType == "https" {
		r.URL.Scheme = "https"
	} else {
		r.URL.Scheme = "http"
	}

	if data.hostHeader != nil {
		log.Debugf("Setting Host header to %q", *data.hostHeader)
		r.Host = *data.hostHeader
		r.URL.Host = *data.hostHeader

		if origin := r.Header.Get("Origin"); origin != "" {
			if originURL, err := url.Parse(origin); err == nil && originURL.Host != "" {
				r.Header.Set("Origin", r.URL.Scheme+"://"+*data.hostHeader)
			}
		}
	} else if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	if domainPath && tunnelName != "" {
		stripPrefix := domainURI.Path + "/" + tunnelName
		r.URL.Path = stripPathPrefix(r.URL.Path, stripPrefix)
		if r.URL.RawPath != "" {
			r.URL.RawPath = stripPathPrefix(r.URL.RawPath, stripPrefix)
		}
	}
}

func stripPathPrefix(path, prefix string) string {
	p := strings.TrimLeft(path, "/")
	pre := strings.TrimLeft(prefix, "/")
	p = strings.TrimPrefix(p, pre)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// dialSSHChannel opens a new SSH forwarded-tcpip channel on the connection
// associated with the current request and returns it wrapped as a net.Conn.
func dialSSHChannel(ctx context.Context) (net.Conn, error) {
	data, ok := ctx.Value(ctxKeyTunnel).(*sshTunnelsListenerData)
	if !ok || data == nil || data.reqPayload == nil {
		return nil, errors.New("no tunnel data on request context")
	}
	origin, _ := ctx.Value(ctxKeyOrigin).(originInfo)

	payload := ssh.Marshal(&remoteForwardChannelData{
		DestAddr:   data.reqPayload.BindAddr,
		DestPort:   uint32(httpBindPort),
		OriginAddr: origin.addr,
		OriginPort: origin.port,
	})

	ch, reqs, err := data.conn.OpenChannel(forwardedTCPChannelType, payload)
	if err != nil {
		log.Printf("error opening %s channel: %s", forwardedTCPChannelType, err)
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	return newSSHChannelConnection(&ch, data.conn.cancellationCtx), nil
}

func cancelForwardHandler(conn *sshConnection, req *ssh.Request, ctx context.Context) (bool, []byte) {
	var reqPayload remoteForwardCancelRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		log.Printf("error in cancel-tcpip-forward: %s", err)
		return false, []byte{}
	}
	if reqPayload.BindPort == httpBindPort {
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
	// TCP/UDP: closing the listener (or PacketConn) makes the per-forward
	// goroutine exit and remove itself from the forwards map.
	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	forwardsLock.Lock()
	lnO, ok := forwards[addr]
	forwardsLock.Unlock()
	if ok {
		lnO.listener.Close()
	}
	return true, nil
}
