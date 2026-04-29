package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// udpHandlerFunc is invoked once per datagram received on a UDP flow channel.
// The returned bytes, if non-nil, are length-framed and written back over the
// same channel (that becomes the response delivered to the original UDP
// peer). Returning nil sends no reply.
type udpHandlerFunc func(payload []byte) []byte

// connectAndRegisterUDP performs the SSH handshake, sends a tcpip-forward
// with type=udp in the exec command, and wires every incoming
// forwarded-tcpip channel to the supplied per-datagram handler. The returned
// client exposes the kernel-allocated UDP bind port the server is now
// listening on, plus a counter of distinct flow channels.
func connectAndRegisterUDP(t *testing.T, setup *integrationTestSetup, execCmd string, handler udpHandlerFunc) *testTunnelClient {
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
	ok, reply, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(&fwdReq{BindAddr: "127.0.0.1", BindPort: 0}))
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
			go runUDPFlowHandler(c, handler)
		}
	}()

	return tc
}

// runUDPFlowHandler drives one flow channel: read length-prefixed frame, hand
// payload to handler, optionally write framed response. Loops until the
// channel errors or the server closes it. Uses the same writeUDPFrame /
// readUDPFrame primitives the production sender/receiver use, so a wire
// format change only needs to happen in one place.
func runUDPFlowHandler(ch ssh.Channel, handler udpHandlerFunc) {
	defer ch.Close()
	buf := make([]byte, udpMaxDatagramSize)
	for {
		n, err := readUDPFrame(ch, buf)
		if err != nil {
			return
		}
		// Defensive copy — handler may retain the slice past this iteration.
		payload := append([]byte(nil), buf[:n]...)

		resp := handler(payload)
		if resp == nil {
			continue
		}
		if err := writeUDPFrame(ch, resp); err != nil {
			return
		}
	}
}

// dialServerUDP opens a UDP socket connected to the server's bind port. Each
// call gets a fresh ephemeral local port — that's the test's handle on a
// single UDP "flow" as far as the server is concerned.
func dialServerUDP(t *testing.T, bindPort uint32) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(bindPort)})
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// waitForCount polls fn() until it returns >= want or the deadline fires.
// Returns the last observed value either way.
func waitForCount(deadline time.Time, want int64, fn func() int64) int64 {
	for time.Now().Before(deadline) {
		if v := fn(); v >= want {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fn()
}

// --- tests ---

func TestUDPTunnel_BasicRoundTrip(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	handler := func(payload []byte) []byte {
		return append([]byte("echo: "), payload...)
	}
	tc := connectAndRegisterUDP(t, setup, "id=test,type=udp", handler)

	c := dialServerUDP(t, tc.bindPort)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "echo: hello" {
		t.Fatalf("got %q, want %q", got, "echo: hello")
	}
	if got := tc.ChannelCount(); got != 1 {
		t.Fatalf("expected 1 flow channel, got %d", got)
	}
}

func TestUDPTunnel_ChannelPerFlow(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	var datagramCount atomic.Int64
	handler := func(payload []byte) []byte {
		datagramCount.Add(1)
		return nil
	}
	tc := connectAndRegisterUDP(t, setup, "id=test,type=udp", handler)

	const flows = 4
	// Hold each socket open so the kernel can't recycle its ephemeral port —
	// each one is a distinct flow as far as the server's listener is concerned.
	conns := make([]*net.UDPConn, 0, flows)
	for i := 0; i < flows; i++ {
		c := dialServerUDP(t, tc.bindPort)
		conns = append(conns, c)
		if _, err := c.Write([]byte(fmt.Sprintf("flow-%d", i))); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	if got := waitForCount(deadline, flows, datagramCount.Load); got != flows {
		t.Fatalf("expected %d datagrams handled, got %d", flows, got)
	}
	if got := tc.ChannelCount(); got != flows {
		t.Fatalf("expected %d flow channels (one per source port), got %d", flows, got)
	}
}

func TestUDPTunnel_SameFlowSingleChannel(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	var datagramCount atomic.Int64
	handler := func(payload []byte) []byte {
		datagramCount.Add(1)
		return nil
	}
	tc := connectAndRegisterUDP(t, setup, "id=test,type=udp", handler)

	c := dialServerUDP(t, tc.bindPort)

	const N = 6
	for i := 0; i < N; i++ {
		if _, err := c.Write([]byte(fmt.Sprintf("p%d", i))); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	if got := waitForCount(deadline, N, datagramCount.Load); got != N {
		t.Fatalf("expected %d datagrams handled, got %d", N, got)
	}
	if got := tc.ChannelCount(); got != 1 {
		t.Fatalf("expected exactly 1 flow channel for one source port, got %d", got)
	}
}

func TestUDPTunnel_DatagramBoundaries(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	var (
		mu   sync.Mutex
		recv [][]byte
	)
	handler := func(payload []byte) []byte {
		// Make a defensive copy — the caller reuses payload buffers.
		cp := append([]byte(nil), payload...)
		mu.Lock()
		recv = append(recv, cp)
		mu.Unlock()
		return nil
	}
	tc := connectAndRegisterUDP(t, setup, "id=test,type=udp", handler)

	c := dialServerUDP(t, tc.bindPort)

	// Three different-length datagrams sent back-to-back from one source.
	// If framing fails (TCP coalescing within the SSH channel) these would
	// arrive merged or split.
	payloads := [][]byte{
		[]byte("aaa"),
		[]byte("bbbb"),
		[]byte("ccccc"),
	}
	for _, p := range payloads {
		if _, err := c.Write(p); err != nil {
			t.Fatalf("write %q: %v", p, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	waitForCount(deadline, int64(len(payloads)), func() int64 {
		mu.Lock()
		defer mu.Unlock()
		return int64(len(recv))
	})

	mu.Lock()
	defer mu.Unlock()
	if len(recv) != len(payloads) {
		t.Fatalf("expected %d datagrams, got %d: %v", len(payloads), len(recv), recv)
	}
	for i, want := range payloads {
		if string(recv[i]) != string(want) {
			t.Fatalf("datagram %d: expected %q, got %q", i, want, recv[i])
		}
	}
}

func TestUDPTunnel_BidirectionalSameFlow(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	handler := func(payload []byte) []byte {
		return append([]byte("r:"), payload...)
	}
	tc := connectAndRegisterUDP(t, setup, "id=test,type=udp", handler)

	c := dialServerUDP(t, tc.bindPort)

	const N = 5
	for i := 0; i < N; i++ {
		req := []byte(fmt.Sprintf("q%d", i))
		if _, err := c.Write(req); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}

		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		want := "r:q" + fmt.Sprintf("%d", i)
		if got := string(buf[:n]); got != want {
			t.Fatalf("response %d: got %q, want %q", i, got, want)
		}
	}

	if got := tc.ChannelCount(); got != 1 {
		t.Fatalf("expected exactly 1 flow channel for the entire exchange, got %d", got)
	}
}

func TestUDPTunnel_LargeDatagram(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	handler := func(payload []byte) []byte {
		return append([]byte(nil), payload...)
	}
	tc := connectAndRegisterUDP(t, setup, "id=test,type=udp", handler)

	c := dialServerUDP(t, tc.bindPort)

	// Below typical loopback MTU but well above any single-read TCP coalesce
	// window — proves length framing actually delimits the message.
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("expected %d bytes back, got %d", len(payload), n)
	}
	for i := 0; i < n; i++ {
		if buf[i] != payload[i] {
			t.Fatalf("byte %d: got %d, want %d", i, buf[i], payload[i])
		}
	}
}

func TestUDPTunnel_EmptyDatagram(t *testing.T) {
	setup := setupTestServer(t, "http://test.localhost", false)

	got := make(chan int, 1)
	handler := func(payload []byte) []byte {
		got <- len(payload)
		return []byte{}
	}
	tc := connectAndRegisterUDP(t, setup, "id=test,type=udp", handler)

	c := dialServerUDP(t, tc.bindPort)

	if _, err := c.Write([]byte{}); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	select {
	case n := <-got:
		if n != 0 {
			t.Fatalf("handler saw %d bytes, expected 0", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never saw the empty datagram")
	}

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected empty response datagram, got %d bytes: %v", n, buf[:n])
	}
}
