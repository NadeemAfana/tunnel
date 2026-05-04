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

// httpBindPort is the remote bind port that distinguishes HTTP/HTTPS forwards
// from raw TCP/UDP forwards. It is mutable so main.go can override the default
// at startup via the --httpPort flag. The client-side wrapper (tunnel.sh) and
// any raw `ssh -R` invocations must request the same port for HTTP traffic to
// be recognized.
var httpBindPort uint32 = 3000

const forwardedTCPChannelType = "forwarded-tcpip"

func formatTunnelLine(from, localTarget string) string {
	return fmt.Sprintf("Tunneling %s -> %s\n", from, localTarget)
}

const bufferSize = 32 << 10 // 32 kB buffer.
var bufPool = sync.Pool{
	New: func() any {
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

	// Authenticated identity from PublicKeyCallback. Used as the per-user
	// quota key in the port registry and for audit logging. Falls back to
	// sessionID if the auth layer somehow did not set it (defense-in-depth;
	// this should not happen in practice).
	owner := ""
	if conn.Permissions != nil {
		owner = conn.Permissions.Extensions["key-name"]
	}
	if owner == "" {
		owner = "session-" + hex.EncodeToString(conn.SessionID())
	}

	// For HTTP/HTTPS, the public port is server-controlled (httpBindPort) and
	// not a per-client choice. Reject explicit non-matching ports rather than
	// silently ignoring them, so a user passing `-p 800 --http` gets a clear
	// error instead of wondering why their port was discarded. Clients should
	// send 0 (or omit `-p`); httpBindPort is also accepted as a no-op.
	if connectionType == "http" || connectionType == "https" {
		if reqPayload.BindPort != 0 && reqPayload.BindPort != httpBindPort {
			msg := fmt.Sprintf("HTTP/HTTPS tunnels do not accept a custom remote port; "+
				"the server binds to --httpPort=%d. Send 0 (or omit -p) instead of %d.\n",
				httpBindPort, reqPayload.BindPort)
			io.WriteString(session.channel, msg)
			return false, []byte(msg)
		}
	}

	// Server localhost:port to listen for http requests at.
	// For HTTP/HTTPS, pin the shared listener to httpBindPort regardless of
	// what the client requested. HTTP discrimination is driven entirely by
	// `type=http|https` in the exec command. Rewrite reqPayload.BindPort to
	// the effective port so disconnect cleanup at main.go and the cancel
	// handler below build matching cache keys (mirrors the TCP/UDP pattern
	// where the server-allocated port is written back to reqPayload).
	var addr string
	if connectionType == "http" || connectionType == "https" {
		reqPayload.BindPort = httpBindPort
		addr = net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(httpBindPort)))
	} else {
		addr = net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	}

	// Update connection with tunnelName and payload
	conn.SetRequestForwardPayload(&reqPayload)

	// TCP or HTTP?
	// For TCP, the connection is one-to-one meaning the local listener is exclusively for this SSH client.
	// For HTTP (httpBindPort), the connection is shared and thus many-to-one meaning the local listener on server is shared across many HTTP Clients.
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
			// Bind failure is recoverable per-request: roll back the listener
			// entry we just inserted and reject this forward. Killing the whole
			// process here would take down every other live tunnel for what is
			// usually a port-collision (someone else is on httpBindPort).
			sshTunnelListenersLock.Lock()
			if cached, ok := sshTunnelListeners[addr+tunnelName]; ok && cached.sessionID == hex.EncodeToString(conn.SessionID()) {
				delete(sshTunnelListeners, addr+tunnelName)
			}
			sshTunnelListenersLock.Unlock()
			log.Printf("error listening for address %s: %s", addr, err)
			io.WriteString(session.channel, fmt.Sprintf("server failed to bind HTTP listener at %s: %s\n", addr, err))
			return false, []byte(fmt.Sprintf("listen %s: %s", addr, err))
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
			// Pick a free UDP port from the registry, retry on rare kernel
			// collision (some other process grabbed it for outbound between
			// our reserve and our listen).
			const maxBindRetries = 8
			for retry := 0; retry < maxBindRetries; retry++ {
				p, allocErr := ports.allocate(owner, protoUDP)
				if allocErr != nil {
					io.WriteString(session.channel, fmt.Sprintf("%s\n", allocErr))
					return false, []byte(allocErr.Error())
				}
				tryAddr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(p)))
				c, lerr := net.ListenPacket("udp", tryAddr)
				if lerr != nil {
					log.Printf("UDP bind retry: %s: %s", tryAddr, lerr)
					ports.release(p, protoUDP)
					continue
				}
				udpConn = c
				requestBindPort = int(p)
				reqPayload.BindPort = p
				addr = tryAddr
				break
			}
			if udpConn == nil {
				msg := "could not allocate a free UDP port; range may be saturated"
				io.WriteString(session.channel, msg+"\n")
				return false, []byte(msg)
			}
		} else {
			// Caller-specified port. Same-clientID takeover allowed; otherwise
			// validate against the registry (range / already-in-use / per-user
			// limit) before binding.
			forwardsLock.Lock()
			if existing, ok := forwards[addr]; ok {
				if existing.clientID == clientID {
					log.Printf("Discarding existing UDP forward for same client id %s", clientID)
					existing.listener.Close()
					delete(forwards, addr)
					ports.release(uint32(requestBindPort), protoUDP)
				} else {
					forwardsLock.Unlock()
					io.WriteString(session.channel, fmt.Sprintf("UDP port %d is already taken.\n", reqPayload.BindPort))
					return false, []byte{}
				}
			}
			forwardsLock.Unlock()

			if rerr := ports.reserve(uint32(requestBindPort), owner, protoUDP); rerr != nil {
				io.WriteString(session.channel, fmt.Sprintf("UDP port %d: %s\n", requestBindPort, rerr))
				return false, []byte(rerr.Error())
			}

			udpConn, err = net.ListenPacket("udp", addr)
			if err != nil {
				ports.release(uint32(requestBindPort), protoUDP)
				log.Printf("error listening for UDP address %s: %s", addr, err)
				io.WriteString(session.channel, fmt.Sprintf("UDP listen %s: %s\n", addr, err))
				return false, []byte(err.Error())
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
		// Pick a free TCP port from the registry (which enforces the
		// per-user quota and avoids ports we already handed out). Retry
		// on rare kernel-level collision: another process on the box may
		// have grabbed the port for an outbound connection between our
		// reserve and our listen.
		const maxBindRetries = 8
		for retry := 0; retry < maxBindRetries; retry++ {
			p, allocErr := ports.allocate(owner, protoTCP)
			if allocErr != nil {
				io.WriteString(session.channel, fmt.Sprintf("%s\n", allocErr))
				return false, []byte(allocErr.Error())
			}
			tryAddr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(p)))
			l, lerr := net.Listen("tcp", tryAddr)
			if lerr != nil {
				log.Printf("TCP bind retry: %s: %s", tryAddr, lerr)
				ports.release(p, protoTCP)
				continue
			}
			ln = l
			requestBindPort = int(p)
			reqPayload.BindPort = p
			addr = tryAddr
			break
		}
		if ln == nil {
			msg := "could not allocate a free TCP port; range may be saturated"
			io.WriteString(session.channel, msg+"\n")
			return false, []byte(msg)
		}
	} else {
		// Caller-specified port. Same-clientID takeover is allowed; otherwise
		// validate against the registry (range / already-in-use / per-user
		// limit) before binding.
		forwardsLock.Lock()
		if existing, ok := forwards[addr]; ok {
			if existing.clientID == clientID {
				log.Printf("Discarding existing tunnelName cache for same client id %s", clientID)
				existing.listener.Close()
				delete(forwards, addr)
				ports.release(uint32(requestBindPort), protoTCP)
			} else {
				forwardsLock.Unlock()
				io.WriteString(session.channel, fmt.Sprintf("TCP port %d is already taken.\n", reqPayload.BindPort))
				return false, []byte{}
			}
		}
		forwardsLock.Unlock()

		if rerr := ports.reserve(uint32(requestBindPort), owner, protoTCP); rerr != nil {
			io.WriteString(session.channel, fmt.Sprintf("TCP port %d: %s\n", requestBindPort, rerr))
			return false, []byte(rerr.Error())
		}

		ln, err = net.Listen("tcp", addr)
		if err != nil {
			ports.release(uint32(requestBindPort), protoTCP)
			log.Printf("error listening for TCP address %s: %s", addr, err)
			io.WriteString(session.channel, fmt.Sprintf("TCP listen %s: %s\n", addr, err))
			return false, []byte(err.Error())
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
		DestPort:   httpBindPort,
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
	// goroutine exit. Also release the registry slot so the user's quota and
	// the port itself are immediately reusable.
	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	forwardsLock.Lock()
	lnO, ok := forwards[addr]
	if ok {
		delete(forwards, addr)
	}
	forwardsLock.Unlock()
	if ok {
		lnO.listener.Close()
		releasePortFromRegistry(addr, lnO.conType)
	}
	return true, nil
}
