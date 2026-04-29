package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
)

// UDP-specific constants. UDP datagrams can be up to 65507 bytes, so the
// TCP-sized bufPool in remoteForward.go is too small for UDP.
const (
	udpBufferSize         = 64 << 10 // 64 kB — fits any UDP datagram (max 65507).
	udpMaxDatagramSize    = 65507
	udpFlowIdleTimeout    = 60 * time.Second
	udpFlowReapInterval   = 15 * time.Second
	udpMaxFlowsPerSession = 200
	udpInboxCapacity      = 64 // per-flow datagram queue depth before drops kick in
)

var udpBufPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, udpBufferSize)
		return &buffer
	},
}

// udpFlow is the per-(srcIP:srcPort) state for the channel-per-flow model.
// Each flow owns one SSH channel, an inbox of pending datagrams to send to
// the client, and a quit signal that lets the sender goroutine exit when the
// flow is being torn down (idle reap, channel error, session close).
type udpFlow struct {
	ch         ssh.Channel
	srcAddr    net.Addr
	inbox      chan udpDatagram
	quit       chan struct{}
	closeOnce  sync.Once
	lastActive int64 // unix nano (atomic)
}

func (f *udpFlow) close() {
	f.closeOnce.Do(func() {
		close(f.quit)
		f.ch.Close()
	})
}

// udpDatagram carries a pooled buffer through the per-flow inbox. The buffer
// is a full-sized udpBufPool slice; n is the meaningful prefix. Callers MUST
// return the buffer with putUDPDatagram exactly once on every code path
// (success, error, drop, drain) — otherwise the pool slowly drains.
type udpDatagram struct {
	bufPtr *[]byte
	n      int
}

func putUDPDatagram(d udpDatagram) {
	if d.bufPtr != nil {
		udpBufPool.Put(d.bufPtr)
	}
}

// errOversizedFrame is returned by readUDPFrame when the length prefix
// exceeds udpMaxDatagramSize. The flow is not recoverable after this — the
// caller is expected to abort the channel.
var errOversizedFrame = errors.New("oversized UDP frame")

// writeUDPFrame encodes one length-prefixed UDP datagram onto w. Wire format:
//
//	+--------+------------------+
//	| len(2) | payload (len B)  |
//	+--------+------------------+
//
// `len` is big-endian uint16. Empty payloads (len=0) are legal.
func writeUDPFrame(w io.Writer, payload []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readUDPFrame decodes one length-prefixed UDP datagram from r into buf and
// returns the payload length. buf must be at least udpMaxDatagramSize bytes.
// Returns errOversizedFrame if the framed length exceeds udpMaxDatagramSize.
func readUDPFrame(r io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > udpMaxDatagramSize {
		return 0, fmt.Errorf("%w (%d bytes)", errOversizedFrame, n)
	}
	if n > 0 {
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// runUDPListener owns the UDP socket bound for one tcpip-forward request and
// implements the channel-per-flow model: for each unique (srcIP:srcPort)
// observed at the listener, a fresh SSH channel is opened and used to carry
// length-prefixed datagrams (`len(2) | payload`) in both directions until the
// flow goes idle, the channel errors, or the session ends.
func runUDPListener(conn *sshConnection, udpConn net.PacketConn, reqPayload *remoteForwardRequest, addr string, ctx context.Context) {
	var flowsMu sync.Mutex
	flows := make(map[string]*udpFlow)
	sessionID := hex.EncodeToString(conn.SessionID())

	closeAllFlows := func() {
		flowsMu.Lock()
		for k, f := range flows {
			f.close()
			delete(flows, k)
		}
		flowsMu.Unlock()
	}

	reaperDone := make(chan struct{})
	defer close(reaperDone)
	go func() {
		ticker := time.NewTicker(udpFlowReapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-reaperDone:
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-udpFlowIdleTimeout).UnixNano()
				flowsMu.Lock()
				for k, f := range flows {
					if atomic.LoadInt64(&f.lastActive) < cutoff {
						f.close()
						delete(flows, k)
						log.Debugf("session %s: reaped idle UDP flow %s", sessionID, k)
					}
				}
				flowsMu.Unlock()
			}
		}
	}()

	readBufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(readBufPtr)
	readBuf := *readBufPtr

	for {
		n, srcAddr, err := udpConn.ReadFrom(readBuf)
		if err != nil {
			select {
			case <-ctx.Done():
				log.Debugf("UDP listener cancelled for session %s @ %s", sessionID, addr)
			default:
				log.Debugf("UDP listener error for session %s @ %s: %s", sessionID, addr, err)
			}
			closeAllFlows()
			forwardsLock.Lock()
			o, ok := forwards[addr]
			if ok && o.sessionID == sessionID {
				delete(forwards, addr)
			}
			forwardsLock.Unlock()
			return
		}

		if n > udpMaxDatagramSize {
			log.Warnf("session %s: oversized UDP datagram (%d bytes) from %s; dropping", sessionID, n, srcAddr)
			continue
		}

		// Acquire a pooled buffer for the datagram so the next ReadFrom can
		// reuse readBuf without clobbering queued data.
		dgBufPtr := udpBufPool.Get().(*[]byte)
		copy(*dgBufPtr, readBuf[:n])
		d := udpDatagram{bufPtr: dgBufPtr, n: n}

		key := srcAddr.String()
		flowsMu.Lock()
		flow, ok := flows[key]
		if !ok {
			if len(flows) >= udpMaxFlowsPerSession {
				flowsMu.Unlock()
				putUDPDatagram(d)
				log.Debugf("session %s: max UDP flows (%d) reached, dropping datagram from %s", sessionID, udpMaxFlowsPerSession, key)
				continue
			}

			ch, openErr := openUDPFlowChannel(conn, reqPayload, srcAddr)
			if openErr != nil {
				flowsMu.Unlock()
				putUDPDatagram(d)
				log.Warnf("session %s: failed to open UDP flow channel for %s: %s", sessionID, key, openErr)
				continue
			}

			flow = &udpFlow{
				ch:      ch,
				srcAddr: srcAddr,
				inbox:   make(chan udpDatagram, udpInboxCapacity),
				quit:    make(chan struct{}),
			}
			atomic.StoreInt64(&flow.lastActive, time.Now().UnixNano())
			flows[key] = flow

			log.Debugf("session %s: opened UDP flow %s", sessionID, key)

			go udpFlowSender(flow, sessionID, key)
			go func(f *udpFlow, k string) {
				udpFlowReceiver(f, udpConn)
				flowsMu.Lock()
				if cur, ok := flows[k]; ok && cur == f {
					delete(flows, k)
				}
				flowsMu.Unlock()
				f.close()
				log.Debugf("session %s: closed UDP flow %s", sessionID, k)
			}(flow, key)
		}
		flowsMu.Unlock()

		select {
		case flow.inbox <- d:
			atomic.StoreInt64(&flow.lastActive, time.Now().UnixNano())
		case <-flow.quit:
			putUDPDatagram(d)
		default:
			putUDPDatagram(d)
			log.Debugf("session %s: UDP flow %s inbox full, dropping datagram", sessionID, key)
		}
	}
}

// udpFlowSender drains the per-flow inbox and writes length-prefixed frames
// onto the SSH channel. Runs in its own goroutine so a slow client cannot
// block the listener thread for other flows. The deferred drain returns any
// queued buffers to the pool when the goroutine exits, so the pool stays hot
// even on torn-down flows.
func udpFlowSender(f *udpFlow, sessionID, key string) {
	defer func() {
		for {
			select {
			case d := <-f.inbox:
				putUDPDatagram(d)
			default:
				return
			}
		}
	}()

	for {
		select {
		case <-f.quit:
			return
		case d := <-f.inbox:
			err := writeUDPFrame(f.ch, (*d.bufPtr)[:d.n])
			putUDPDatagram(d)
			if err != nil {
				log.Debugf("session %s: UDP flow %s write error: %v", sessionID, key, err)
				f.close()
				return
			}
		}
	}
}

// udpFlowReceiver reads length-prefixed frames off the SSH channel and
// delivers each datagram back to the original UDP source.
func udpFlowReceiver(f *udpFlow, udpConn net.PacketConn) {
	bufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, err := readUDPFrame(f.ch, buf)
		if err != nil {
			if errors.Is(err, errOversizedFrame) {
				log.Warnf("UDP flow %s: %s; aborting flow", f.srcAddr, err)
			}
			return
		}
		if _, err := udpConn.WriteTo(buf[:n], f.srcAddr); err != nil {
			log.Debugf("UDP write back to %s error: %s", f.srcAddr, err)
		}
		atomic.StoreInt64(&f.lastActive, time.Now().UnixNano())
	}
}

// openUDPFlowChannel opens a forwarded-tcpip SSH channel for one UDP flow,
// reusing the same channel type as TCP forwarding. The SSH client side does
// not need to distinguish UDP from TCP at the SSH layer — `ssh -R` simply
// dials the configured local bridge port for each new channel; the
// udp-bridge helper deframes the payload there.
func openUDPFlowChannel(conn *sshConnection, reqPayload *remoteForwardRequest, srcAddr net.Addr) (ssh.Channel, error) {
	var originAddr string
	var originPort uint32
	if udpAddr, ok := srcAddr.(*net.UDPAddr); ok {
		originAddr = udpAddr.IP.String()
		originPort = uint32(udpAddr.Port)
	}
	payload := ssh.Marshal(&remoteForwardChannelData{
		DestAddr:   reqPayload.BindAddr,
		DestPort:   reqPayload.BindPort,
		OriginAddr: originAddr,
		OriginPort: originPort,
	})
	ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	return ch, nil
}
