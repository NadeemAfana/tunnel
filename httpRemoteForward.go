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
	"time"

	"golang.org/x/crypto/ssh"
)

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

// setupHTTPForward registers a tunnel name for an HTTP/HTTPS forward and
// ensures the shared http.Server for the bind address is running. The public
// listener is shared across all HTTP tunnels on the same port; per-request
// routing happens in newTunnelHandler.
func setupHTTPForward(sc *forwardSetupContext) (bool, []byte) {
	conn := sc.conn
	session := sc.session
	reqPayload := sc.reqPayload
	addr := sc.addr
	clientID := sc.clientID
	tunnelName := sc.tunnelName
	cancellationCtx := sc.cancellationCtx

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
		reqPayload:     reqPayload,
		sessionID:      hex.EncodeToString(conn.SessionID()),
		clientID:       clientID,
		hostHeader:     nil,
		connectionType: sc.connectionType,
	}
	if sc.headerSpecified {
		sshListenerData.hostHeader = &sc.header
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
	io.WriteString(session.channel, formatTunnelLine(publicURL, sc.localTarget))

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
