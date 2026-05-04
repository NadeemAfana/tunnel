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

	// Pre-allocate a free port and pin httpBindPort to it. This mirrors
	// production where the configured --httpPort differs from what the client
	// sends on -R (the client sends 0, the server pins to httpBindPort), so
	// any cache-key bug that only manifests when those differ is exercised
	// here. Avoids the package default (3000) which may be in use on the host.
	prevHTTPBindPort := httpBindPort
	preLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc http port: %v", err)
	}
	httpBindPort = uint32(preLn.Addr().(*net.TCPAddr).Port)
	preLn.Close()

	// Fresh port registry per test with a generous limit. Tests that exercise
	// the per-user cap construct their own narrower registry inline.
	prevPorts := ports
	ports = newPortRegistry(20000, 65000, 1000)

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
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pub),
						// Stable test owner so per-user counters in the port
						// registry attribute every connection here to the
						// same identity (production sets this from the
						// authorized_keys.json `name` field).
						"key-name": "test-user",
					},
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
		httpBindPort = prevHTTPBindPort
		ports = prevPorts
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
	req.Header.Set("Origin", "http://hello.test.localhost")
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
	if gotOrigin != "http://internal.svc" {
		t.Fatalf("expected upstream Origin=http://internal.svc, got %q", gotOrigin)
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
			bName = strings.TrimPrefix(k, fmt.Sprintf("127.0.0.1:%d", httpBindPort))
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

// HTTP/HTTPS tunnels do not allow a caller-chosen remote bind port; the
// server pins the listener to --httpPort. Anything other than 0 (or the
// matching httpBindPort) must be rejected with a clear error rather than
// silently accepted as a TCP forward.
func TestHTTPTunnel_RejectsCustomRemotePort(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

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
	defer client.Close()

	ch, chReqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go ssh.DiscardRequests(chReqs)
	go io.Copy(io.Discard, ch)

	execPayload := struct{ Command string }{Command: "id=t,tunnelname=hello,type=http"}
	if _, err := ch.SendRequest("exec", false, ssh.Marshal(&execPayload)); err != nil {
		t.Fatalf("send exec: %v", err)
	}

	type fwdReq struct {
		BindAddr string
		BindPort uint32
	}
	// 800 is neither 0 nor httpBindPort; server must reject.
	ok, reply, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(&fwdReq{BindAddr: "127.0.0.1", BindPort: 800}))
	if err != nil {
		t.Fatalf("send tcpip-forward: %v", err)
	}
	if ok {
		t.Fatalf("tcpip-forward with custom HTTP port should have been rejected")
	}
	if !strings.Contains(string(reply), "HTTP/HTTPS tunnels do not accept a custom remote port") {
		t.Fatalf("expected rejection message, got %q", string(reply))
	}
}

// Disconnect cleanup must purge the tunnelName entry so a fresh client
// (different clientID) can reclaim the same name. Reproduces the bug where
// hitting Ctrl+C left "Specified tunnelName 'X' already taken" on the next
// run because the cache key built at disconnect did not match the key under
// which the entry was stored.
func TestHTTPTunnel_NameReclaimableAfterDisconnect(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })

	// Client 1 registers 'hello'.
	tcA := connectAndRegister(t, setup, "id=clienta,tunnelname=hello,type=http", "127.0.0.1", handler, nil)

	sshTunnelListenersLock.RLock()
	preKey := fmt.Sprintf("127.0.0.1:%dhello", httpBindPort)
	if _, ok := sshTunnelListeners[preKey]; !ok {
		sshTunnelListenersLock.RUnlock()
		t.Fatalf("registration missing: expected key %q", preKey)
	}
	sshTunnelListenersLock.RUnlock()

	// Simulate Ctrl+C: close client 1's SSH connection. The server's
	// handleIncomingSSHConn defer should purge sshTunnelListeners[hello].
	tcA.sshClient.Close()

	// Wait briefly for the server's defer to run.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sshTunnelListenersLock.RLock()
		_, stillThere := sshTunnelListeners[preKey]
		sshTunnelListenersLock.RUnlock()
		if !stillThere {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	sshTunnelListenersLock.RLock()
	if _, stillThere := sshTunnelListeners[preKey]; stillThere {
		sshTunnelListenersLock.RUnlock()
		t.Fatalf("tunnelName entry not cleaned up after disconnect (key %q still present)", preKey)
	}
	sshTunnelListenersLock.RUnlock()

	// Client 2 (different clientID) should be able to claim 'hello' again.
	connectAndRegister(t, setup, "id=clientb,tunnelname=hello,type=http", "127.0.0.1", handler, nil)

	sshTunnelListenersLock.RLock()
	defer sshTunnelListenersLock.RUnlock()
	entry, ok := sshTunnelListeners[preKey]
	if !ok {
		t.Fatalf("client B failed to claim 'hello' after client A's disconnect")
	}
	if entry.clientID != "clientb" {
		t.Fatalf("expected entry to belong to clientb, got %q", entry.clientID)
	}
}

// Per-user port quota: with maxPerUser=3, the 4th TCP forward from the same
// authenticated key must be rejected with errUserPortLimit. Exercises the
// portRegistry integration end-to-end through the SSH protocol path.
func TestTCPTunnel_PerUserPortLimit(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	// Replace the registry with one capped at 3 ports for this test.
	ports = newPortRegistry(20000, 65000, 3)

	cfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(setup.clientKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	type fwdReq struct {
		BindAddr string
		BindPort uint32
	}

	// Helper: dial a fresh SSH connection (mirroring tunnel.sh, which opens
	// one connection per invocation), send exec + tcpip-forward, return the
	// forward reply. Keeps the connection alive via the *ssh.Client return so
	// the listener stays bound and counted in the registry until the test
	// ends. tunnel.Close() in t.Cleanup releases everything.
	openTCPForward := func(idSuffix string) (*ssh.Client, bool, []byte) {
		client, err := ssh.Dial("tcp", setup.sshAddr, cfg)
		if err != nil {
			t.Fatalf("ssh dial: %v", err)
		}
		t.Cleanup(func() { client.Close() })

		ch, chReqs, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("open session: %v", err)
		}
		go ssh.DiscardRequests(chReqs)
		go io.Copy(io.Discard, ch)
		execPayload := struct{ Command string }{Command: "id=" + idSuffix + ",type=tcp"}
		if _, err := ch.SendRequest("exec", false, ssh.Marshal(&execPayload)); err != nil {
			t.Fatalf("send exec: %v", err)
		}
		ok, reply, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(&fwdReq{BindAddr: "127.0.0.1", BindPort: 0}))
		if err != nil {
			t.Fatalf("send tcpip-forward: %v", err)
		}
		return client, ok, reply
	}

	for i := 0; i < 3; i++ {
		_, ok, reply := openTCPForward(fmt.Sprintf("c%d", i))
		if !ok {
			t.Fatalf("forward %d should succeed, got reject: %s", i+1, string(reply))
		}
	}
	// 4th must hit the per-user limit.
	_, ok, reply := openTCPForward("c3")
	if ok {
		t.Fatalf("4th forward should have been rejected by per-user limit")
	}
	if !strings.Contains(string(reply), "per-user port limit") {
		t.Fatalf("expected per-user port limit error, got %q", string(reply))
	}
}
