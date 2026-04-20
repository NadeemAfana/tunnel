package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

// integrationTestSetup boots a fresh server on an ephemeral SSH port and
// returns the SSH listen address plus the client keypair authorized to
// register tunnels against it. Registered t.Cleanup tears everything down.
type integrationTestSetup struct {
	sshAddr   string
	clientKey ssh.Signer
	ctx       context.Context
	cancel    context.CancelFunc
}

// setupTestServer wires up the same server-side pieces that main() does, but
// with in-memory keys, an ephemeral port, and fresh package-level maps. Tests
// in this package run serially - setup resets the shared globals.
func setupTestServer(t *testing.T, domain string, usePath bool) *integrationTestSetup {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}

	domainURL = domain
	if uri, err := url.Parse(domain); err == nil {
		domainURI = *uri
	}
	domainPath = usePath

	forwardsLock.Lock()
	for _, l := range forwards {
		l.listener.Close()
	}
	forwards = make(map[string]forwardsListenerData)
	forwardsLock.Unlock()

	sshTunnelListenersLock.Lock()
	sshTunnelListeners = make(map[string]sshTunnelsListenerData)
	sshTunnelListenersLock.Unlock()

	authorizedKeys := map[string]bool{
		string(clientSigner.PublicKey().Marshal()): true,
	}
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeys[string(pub.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{"pubkey-fp": ssh.FingerprintSHA256(pub)},
				}, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	config.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ssh listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleIncomingSSHConn(nConn, config, ctx)
		}
	}()

	t.Cleanup(func() {
		cancel()
		ln.Close()
		forwardsLock.Lock()
		for _, l := range forwards {
			l.listener.Close()
		}
		forwards = make(map[string]forwardsListenerData)
		forwardsLock.Unlock()
		sshTunnelListenersLock.Lock()
		sshTunnelListeners = make(map[string]sshTunnelsListenerData)
		sshTunnelListenersLock.Unlock()
	})

	return &integrationTestSetup{
		sshAddr:   ln.Addr().String(),
		clientKey: clientSigner,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// testTunnelClient is a minimal SSH client that performs the exec +
// tcpip-forward handshake and serves the provided http.Handler on every
// incoming forwarded-tcpip channel the server pushes to it.
type testTunnelClient struct {
	sshClient *ssh.Client
	bindPort  uint32
	channels  atomic.Int64 // count of forwarded-tcpip channels received
}

// ChannelCount returns the number of forwarded-tcpip channels the server has
// opened against this client so far. Useful for asserting keep-alive reuse.
func (tc *testTunnelClient) ChannelCount() int64 { return tc.channels.Load() }

// connWrapper optionally wraps each accepted ssh.Channel before it's handed
// to http.Server. Used to layer tls.Server on top for HTTPS tunnels.
type connWrapper func(net.Conn) net.Conn

func connectAndRegister(t *testing.T, setup *integrationTestSetup, execCmd, bindAddr string, handler http.Handler, wrapConn connWrapper) *testTunnelClient {
	t.Helper()

	cfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(setup.clientKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", setup.sshAddr, cfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// The server's forwardHandler blocks on execRequestCompleted until the
	// exec arrives on the session channel. Send exec with wantReply=false so
	// this goroutine doesn't wait for a reply that only comes after the
	// forward handshake.
	ch, chReqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go ssh.DiscardRequests(chReqs)
	go io.Copy(io.Discard, ch)

	execPayload := struct{ Command string }{Command: execCmd}
	if _, err := ch.SendRequest("exec", false, ssh.Marshal(&execPayload)); err != nil {
		t.Fatalf("send exec: %v", err)
	}

	type fwdReq struct {
		BindAddr string
		BindPort uint32
	}
	type fwdReply struct {
		BindPort uint32
	}
	ok, reply, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(&fwdReq{BindAddr: bindAddr, BindPort: 0}))
	if err != nil {
		t.Fatalf("send tcpip-forward: %v", err)
	}
	if !ok {
		t.Fatalf("tcpip-forward rejected: %s", string(reply))
	}
	var fr fwdReply
	if err := ssh.Unmarshal(reply, &fr); err != nil {
		t.Fatalf("unmarshal fwd reply: %v", err)
	}

	tc := &testTunnelClient{sshClient: client, bindPort: fr.BindPort}

	channels := client.HandleChannelOpen("forwarded-tcpip")
	go func() {
		for newCh := range channels {
			c, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			tc.channels.Add(1)
			go ssh.DiscardRequests(reqs)
			go func(sshCh ssh.Channel) {
				// Reuse the server-side sshChannelConnection wrapper: it has
				// working SetReadDeadline, which http.Server.Hijack relies on
				// to abort the background read goroutine during a WebSocket
				// upgrade. A no-op deadline here deadlocks Hijack.
				var conn net.Conn = newSSHChannelConnection(&sshCh, setup.ctx)
				if wrapConn != nil {
					conn = wrapConn(conn)
				}
				l := &singleConnListener{c: conn}
				srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
				_ = srv.Serve(l)
			}(c)
		}
	}()

	return tc
}

// singleConnListener yields exactly one net.Conn to http.Server.Serve and
// then returns net.ErrClosed, which causes Serve to exit cleanly. The
// per-conn goroutine http.Server spawns handles all keep-alive requests.
type singleConnListener struct {
	c      net.Conn
	served bool
	mu     sync.Mutex
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.served {
		return nil, net.ErrClosed
	}
	l.served = true
	return l.c, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }

// generateSelfSignedCert produces a throwaway ECDSA cert for the HTTPS upstream
// tests. The server's Transport uses InsecureSkipVerify, so SAN/CN don't matter.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tunnel-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 keypair: %v", err)
	}
	return cert
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse url %s: %v", s, err)
	}
	return u
}

// --- tests ---

func TestHTTPTunnel_SubdomainRouting(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello host=%s path=%s", r.Host, r.URL.Path)
	})
	tc := connectAndRegister(t, setup, "id=test,tunnelname=hello,type=http", "127.0.0.1", handler, nil)

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/foo/bar", tc.bindPort), nil)
	req.Host = "hello.test.localhost"

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "path=/foo/bar") {
		t.Fatalf("path not propagated: %q", body)
	}
	if !strings.Contains(string(body), "host=hello.test.localhost") {
		t.Fatalf("host not propagated: %q", body)
	}
}

func TestHTTPTunnel_UnknownTunnelReturns400(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	tc := connectAndRegister(t, setup, "id=test,tunnelname=hello,type=http", "127.0.0.1",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }), nil)

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", tc.bindPort), nil)
	req.Host = "missing.test.localhost"
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d body=%s", resp.StatusCode, body)
	}
}

func TestHTTPTunnel_HostHeaderRewrite(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	var (
		mu        sync.Mutex
		gotHost   string
		gotOrigin string
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHost = r.Host
		gotOrigin = r.Header.Get("Origin")
		mu.Unlock()
		w.WriteHeader(204)
	})
	tc := connectAndRegister(t, setup,
		"id=test,tunnelname=hello,type=http,header=internal.svc",
		"127.0.0.1", handler, nil)

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", tc.bindPort), nil)
	req.Host = "hello.test.localhost"
	req.Header.Set("Origin", "http://test.localhost")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if gotHost != "internal.svc" {
		t.Fatalf("expected upstream Host=internal.svc, got %q", gotHost)
	}
	// Origin rewrite replaces the domainURL prefix ("http:") with the header
	// value - see SetHostHeader logic preserved in tunnelDirector. We just
	// assert the header was touched (original was "http://test.localhost").
	if gotOrigin == "http://test.localhost" {
		t.Fatalf("Origin was not rewritten: %q", gotOrigin)
	}
}

func TestHTTPTunnel_PathMode(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", true)

	var (
		mu      sync.Mutex
		gotPath string
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		mu.Unlock()
		w.WriteHeader(204)
	})
	tc := connectAndRegister(t, setup, "id=test,tunnelname=hello,type=http", "127.0.0.1", handler, nil)

	// Path mode: /<tunnelName>/<rest> should route to tunnelName and upstream
	// should see /<rest> after prefix stripping.
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/hello/foo/bar", tc.bindPort), nil)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/foo/bar" {
		t.Fatalf("expected upstream path /foo/bar, got %q", gotPath)
	}
}

func TestHTTPTunnel_HTTPSUpstream(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	cert := generateSelfSignedCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// http.Server sets r.TLS when served over a *tls.Conn.
		fmt.Fprintf(w, "tls=%v path=%s", r.TLS != nil, r.URL.Path)
	})
	wrap := func(c net.Conn) net.Conn { return tls.Server(c, tlsConfig) }
	tc := connectAndRegister(t, setup, "id=test,tunnelname=hello,type=https", "127.0.0.1", handler, wrap)

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/secure", tc.bindPort), nil)
	req.Host = "hello.test.localhost"
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "tls=true") {
		t.Fatalf("upstream did not see TLS: %q", body)
	}
	if !strings.Contains(string(body), "path=/secure") {
		t.Fatalf("path not propagated: %q", body)
	}
}

func TestHTTPTunnel_WebSocket(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	handler := websocket.Handler(func(ws *websocket.Conn) {
		ws.PayloadType = websocket.TextFrame
		var msg string
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			return
		}
		_ = websocket.Message.Send(ws, "echo: "+msg)
	})
	tc := connectAndRegister(t, setup, "id=test,tunnelname=ws,type=http", "127.0.0.1", handler, nil)

	// Dial TCP to the proxy, then upgrade via websocket.NewClient with a Location
	// whose Host routes to our "ws" tunnel.
	tcpConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tc.bindPort), 5*time.Second)
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	defer tcpConn.Close()

	cfg := &websocket.Config{
		Location: mustParseURL(t, "ws://ws.test.localhost/"),
		Origin:   mustParseURL(t, "http://ws.test.localhost/"),
		Version:  websocket.ProtocolVersionHybi13,
	}
	ws, err := websocket.NewClient(cfg, tcpConn)
	if err != nil {
		t.Fatalf("ws upgrade: %v", err)
	}
	defer ws.Close()

	if err := websocket.Message.Send(ws, "hello"); err != nil {
		t.Fatalf("ws send: %v", err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	var reply string
	if err := websocket.Message.Receive(ws, &reply); err != nil {
		t.Fatalf("ws recv: %v", err)
	}
	if reply != "echo: hello" {
		t.Fatalf("expected %q, got %q", "echo: hello", reply)
	}
}

func TestHTTPTunnel_ChannelReuse(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})
	tc := connectAndRegister(t, setup, "id=test,tunnelname=hello,type=http", "127.0.0.1", handler, nil)

	// One http.Client with its default Transport - will pool connections to
	// the proxy's HTTP listener. The proxy's own Transport to the SSH upstream
	// also pools channels (MaxIdleConnsPerHost=32).
	client := &http.Client{Timeout: 5 * time.Second}
	const N = 20
	for i := 0; i < N; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/r%d", tc.bindPort, i), nil)
		req.Host = "hello.test.localhost"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	got := tc.ChannelCount()
	if got >= N {
		t.Fatalf("expected keep-alive reuse (< %d channels for %d requests), got %d", N, N, got)
	}
	t.Logf("%d requests used %d forwarded-tcpip channels", N, got)
}

func TestHTTPTunnel_TunnelNameCollision(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	handlerA := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "A") })
	handlerB := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "B") })

	tcA := connectAndRegister(t, setup, "id=clienta,tunnelname=hello,type=http", "127.0.0.1", handlerA, nil)
	// Same tunnelname, different clientID - server must assign a random name.
	_ = connectAndRegister(t, setup, "id=clientb,tunnelname=hello,type=http", "127.0.0.1", handlerB, nil)

	// Identify client B's randomly assigned tunnel name by clientID.
	var bName string
	sshTunnelListenersLock.RLock()
	for k, v := range sshTunnelListeners {
		if v.clientID == "clientb" {
			bName = strings.TrimPrefix(k, "127.0.0.1:0")
			break
		}
	}
	sshTunnelListenersLock.RUnlock()

	if bName == "" {
		t.Fatal("client B tunnel entry missing")
	}
	if bName == "hello" {
		t.Fatalf("client B should not have claimed %q", bName)
	}

	// "hello" → A
	client := &http.Client{Timeout: 5 * time.Second}
	reqA, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", tcA.bindPort), nil)
	reqA.Host = "hello.test.localhost"
	respA, err := client.Do(reqA)
	if err != nil {
		t.Fatalf("req A: %v", err)
	}
	bodyA, _ := io.ReadAll(respA.Body)
	respA.Body.Close()
	if string(bodyA) != "A" {
		t.Fatalf("hello should route to A, got %q", bodyA)
	}

	// Random name → B
	reqB, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", tcA.bindPort), nil)
	reqB.Host = bName + ".test.localhost"
	respB, err := client.Do(reqB)
	if err != nil {
		t.Fatalf("req B: %v", err)
	}
	bodyB, _ := io.ReadAll(respB.Body)
	respB.Body.Close()
	if string(bodyB) != "B" {
		t.Fatalf("%s should route to B, got %q", bName, bodyB)
	}
}
