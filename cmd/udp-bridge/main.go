// udp-bridge is the client-side helper for `tunnel.sh udp` mode.
//
// It listens on a TCP bridge port (locally) and translates each incoming TCP
// connection into a UDP flow against the configured target. Each TCP
// connection corresponds to one UDP flow on the server side (channel-per-flow
// model), so this process opens a fresh local UDP socket per accepted TCP
// connection - the local UDP service then sees a unique ephemeral source port
// per remote peer, which is what real UDP forwarders look like.
//
// Wire format on each TCP connection (symmetric, both directions):
//
//	+--------+------------------+
//	| len(2) | payload (len B)  |
//	+--------+------------------+
//
// `len` is a big-endian uint16 giving the payload length in bytes (0 is a
// legal empty datagram). >65507 is invalid and aborts the flow.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpMaxDatagramSize = 65507
	udpBufferSize      = 64 << 10
)

// version is overridable at build time:
//
//	go build -ldflags="-X main.version=1.0.1" ./cmd/udp-bridge
//
// The in-source default tracks the latest tagged release.
var version = "1.0"

var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpBufferSize)
		return &b
	},
}

func main() {
	bridge := flag.String("bridge", "127.0.0.1:0", "TCP bridge listen addr (port 0 = kernel-chosen)")
	target := flag.String("target", "", "Local UDP target host:port")
	showVersion := flag.Bool("version", false, "Print version and exit")
	debug := flag.Bool("debug", false, "Verbose logging (per-packet)")
	flag.Parse()

	if *showVersion {
		fmt.Println("udp-bridge", version)
		return
	}

	if *target == "" {
		die("--target is required (e.g. --target=localhost:53)")
	}
	targetAddr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		die("bad --target %q: %s", *target, err)
	}

	ln, err := net.Listen("tcp", *bridge)
	if err != nil {
		die("listen on %s: %s", *bridge, err)
	}

	// stdout: the resolved bridge address - captured by tunnel.sh so it knows
	// where to point `ssh -R`. stderr: human-readable logs.
	fmt.Println(ln.Addr().String())

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	slog.Info("UDP listening", "version", version, "bridge", ln.Addr().String(), "target", targetAddr.String(), "debug", *debug)

	for {
		c, err := ln.Accept()
		if err != nil {
			slog.Error("accept failed", "err", err)
			return
		}
		go handleFlow(c, targetAddr)
	}
}

// handleFlow services one TCP bridge connection (= one UDP flow on the server
// side). It opens a fresh UDP socket toward the target so the local service
// sees this peer with its own ephemeral source port, then runs framed
// TCP<->UDP relays in both directions until either side errors.
func handleFlow(tcp net.Conn, target *net.UDPAddr) {
	flowID := tcp.RemoteAddr().String()
	started := time.Now()
	log := slog.With("flow", flowID)
	log.Info("UDP flow opened", "target", target.String())

	// Enable TCP keepalive so a dead SSH tunnel / remote peer surfaces in
	// ~2 minutes instead of the OS default (~2 hours on Linux).
	if tc, ok := tcp.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}

	udp, err := net.DialUDP("udp", nil, target)
	if err != nil {
		log.Error("dial UDP failed", "target", target.String(), "err", err)
		tcp.Close()
		return
	}

	var (
		bytesIn, bytesOut     int64
		packetsIn, packetsOut int64
	)

	var wg sync.WaitGroup
	wg.Add(2)

	// TCP -> UDP: deframe and send.
	go func() {
		defer wg.Done()
		defer tcp.Close()
		defer udp.Close()

		var hdr [2]byte
		for {
			if _, err := io.ReadFull(tcp, hdr[:]); err != nil {
				log.Debug("TCP read EOF/error", "err", err)
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))
			if n > udpMaxDatagramSize {
				log.Warn("oversized incoming frame; aborting", "bytes", n)
				return
			}

			bufPtr := udpBufPool.Get().(*[]byte)
			payload := (*bufPtr)[:n]
			if n > 0 {
				if _, err := io.ReadFull(tcp, payload); err != nil {
					udpBufPool.Put(bufPtr)
					log.Debug("TCP payload read error", "err", err)
					return
				}
			}
			if _, err := udp.Write(payload); err != nil {
				udpBufPool.Put(bufPtr)
				log.Debug("UDP write error", "err", err)
				return
			}
			udpBufPool.Put(bufPtr)

			atomic.AddInt64(&packetsIn, 1)
			atomic.AddInt64(&bytesIn, int64(n))
			log.Debug("server -> local UDP", "bytes", n)
		}
	}()

	// UDP -> TCP: read datagrams, frame them, send.
	go func() {
		defer wg.Done()
		defer tcp.Close()
		defer udp.Close()

		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		buf := *bufPtr

		var hdr [2]byte
		for {
			n, err := udp.Read(buf)
			if err != nil {
				log.Debug("UDP read EOF/error", "err", err)
				return
			}
			if n > udpMaxDatagramSize {
				// Should be impossible from the kernel, but guard anyway.
				log.Warn("oversized local datagram; dropping", "bytes", n)
				continue
			}
			binary.BigEndian.PutUint16(hdr[:], uint16(n))
			if _, err := tcp.Write(hdr[:]); err != nil {
				log.Debug("TCP write hdr error", "err", err)
				return
			}
			if n > 0 {
				if _, err := tcp.Write(buf[:n]); err != nil {
					log.Debug("TCP write payload error", "err", err)
					return
				}
			}
			atomic.AddInt64(&packetsOut, 1)
			atomic.AddInt64(&bytesOut, int64(n))
			log.Debug("local UDP -> server", "bytes", n)
		}
	}()

	wg.Wait()
	log.Info("UDP flow closed",
		"elapsed", time.Since(started).Round(10*time.Millisecond).String(),
		"in_bytes", atomic.LoadInt64(&bytesIn),
		"in_packets", atomic.LoadInt64(&packetsIn),
		"out_bytes", atomic.LoadInt64(&bytesOut),
		"out_packets", atomic.LoadInt64(&packetsOut),
	)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR udp-bridge: "+format+"\n", args...)
	os.Exit(1)
}
