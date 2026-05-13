package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// UDP-specific constants. UDP datagrams can be up to 65507 bytes. Two pool
// sizes split the cost. Most real UDP traffic fits in udpSmallBufSize (MTU
// plus headroom), and only jumbo or max-size datagrams pay for the 64 kB
// buffer.
const (
	udpSmallBufSize       = 2048
	udpLargeBufSize       = 64 << 10 // fits any UDP datagram (max 65507).
	udpMaxDatagramSize    = 65507
	udpFlowIdleTimeout    = 60 * time.Second
	udpFlowReapInterval   = 15 * time.Second
	udpMaxFlowsPerSession = 200
	udpInboxCapacity      = 64 // per-flow datagram queue depth before drops kick in
)

// Two pools, one per buffer size. Pool elements are pointers to fixed-size
// arrays, NOT *[]byte. This makes returning a buffer to the wrong pool a
// compile error: udpSmallPool.Put takes *[udpSmallBufSize]byte, and you
// cannot pass a *[udpLargeBufSize]byte to it (and vice versa).
var (
	udpSmallPool = sync.Pool{New: func() any { return new([udpSmallBufSize]byte) }}
	udpLargePool = sync.Pool{New: func() any { return new([udpLargeBufSize]byte) }}
)

// udpFlow is the per-(srcIP:srcPort) state for the channel-per-flow model.
// Each flow owns one SSH channel, an inbox of pending datagrams to send to
// the client, and a quit signal that lets the sender goroutine exit when the
// flow is being torn down (idle reap, channel error, session close).
type udpFlow struct {
	ch         ssh.Channel
	srcAddr    net.Addr
	inbox      chan pooledDatagram
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

// pooledDatagram is the sum type carried on per-flow inboxes. Concrete
// types (smallDatagram and largeDatagram) wrap buffers from distinct pools
// whose array-pointer element types are not assignable to each other.
// Consumers see only .bytes() and .release(); dispatch to the correct pool
// happens inside the concrete method. Mixing pools is structurally
// impossible. See the udpSmallPool/udpLargePool comment above.
type pooledDatagram interface {
	bytes() []byte
	release()
}

type smallDatagram struct {
	buf *[udpSmallBufSize]byte
	n   int
}

func (d smallDatagram) bytes() []byte { return d.buf[:d.n] }
func (d smallDatagram) release()      { udpSmallPool.Put(d.buf) }

type largeDatagram struct {
	buf *[udpLargeBufSize]byte
	n   int
}

func (d largeDatagram) bytes() []byte { return d.buf[:d.n] }
func (d largeDatagram) release()      { udpLargePool.Put(d.buf) }

// acquireDatagram copies payload into a pool buffer sized for it. This is
// the only constructor for pooledDatagram; any new code path that needs a
// buffer for the inbox MUST go through here. The dispatch line below is
// the one place a size/pool mismatch could be introduced. Keep it short.
func acquireDatagram(payload []byte) pooledDatagram {
	n := len(payload)
	if n <= udpSmallBufSize {
		buf := udpSmallPool.Get().(*[udpSmallBufSize]byte)
		copy(buf[:], payload)
		return smallDatagram{buf: buf, n: n}
	}
	buf := udpLargePool.Get().(*[udpLargeBufSize]byte)
	copy(buf[:], payload)
	return largeDatagram{buf: buf, n: n}
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

// readPooledDatagram reads one length-prefixed UDP frame from r and returns
// it in a pool buffer sized for the payload. The caller MUST call .release()
// on the returned datagram exactly once. On error the function returns nil
// and the underlying pool buffer (if any was acquired) is already returned.
func readPooledDatagram(r io.Reader) (pooledDatagram, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > udpMaxDatagramSize {
		return nil, fmt.Errorf("%w (%d bytes)", errOversizedFrame, n)
	}
	if n <= udpSmallBufSize {
		buf := udpSmallPool.Get().(*[udpSmallBufSize]byte)
		if n > 0 {
			if _, err := io.ReadFull(r, buf[:n]); err != nil {
				udpSmallPool.Put(buf)
				return nil, err
			}
		}
		return smallDatagram{buf: buf, n: n}, nil
	}
	buf := udpLargePool.Get().(*[udpLargeBufSize]byte)
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		udpLargePool.Put(buf)
		return nil, err
	}
	return largeDatagram{buf: buf, n: n}, nil
}

// setupUDPForward binds a UDP packet listener for one tcpip-forward request.
// Mirrors setupTCPForward: the registry validates a caller-specified port or
// allocates a free one with retries on rare kernel-level collisions. The
// per-flow channel model lives in runUDPListener.
func setupUDPForward(sc *forwardSetupContext) (bool, []byte) {
	conn := sc.conn
	session := sc.session
	reqPayload := sc.reqPayload
	addr := sc.addr
	clientID := sc.clientID
	owner := sc.owner
	cancellationCtx := sc.cancellationCtx

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
		if ok, payload := acquireExplicitPort(sc, protoUDP); !ok {
			return false, payload
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

	io.WriteString(session.channel, formatTunnelLine(fmt.Sprintf("UDP %s:%d", domainURI.Hostname(), requestBindPort), sc.localTarget))

	go runUDPListener(conn, udpConn, reqPayload, addr, cancellationCtx)

	return true, ssh.Marshal(&remoteForwardSuccess{uint32(requestBindPort)})
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

	readBufArr := udpLargePool.Get().(*[udpLargeBufSize]byte)
	defer udpLargePool.Put(readBufArr)
	readBuf := readBufArr[:]

	for {
		n, srcAddr, err := udpConn.ReadFrom(readBuf)
		if err != nil {
			select {
			case <-ctx.Done():
				log.Debugf("UDP listener cancelled for session %s @ %s", sessionID, addr)
			default:
				if !errors.Is(err, net.ErrClosed) {
					log.Debugf("UDP listener error for session %s @ %s: %s", sessionID, addr, err)
				}
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
		d := acquireDatagram(readBuf[:n])

		key := srcAddr.String()
		flowsMu.Lock()
		flow, ok := flows[key]
		if !ok {
			if len(flows) >= udpMaxFlowsPerSession {
				flowsMu.Unlock()
				d.release()
				log.Debugf("session %s: max UDP flows (%d) reached, dropping datagram from %s", sessionID, udpMaxFlowsPerSession, key)
				continue
			}

			ch, openErr := openUDPFlowChannel(conn, reqPayload, srcAddr)
			if openErr != nil {
				flowsMu.Unlock()
				d.release()
				log.Warnf("session %s: failed to open UDP flow channel for %s: %s", sessionID, key, openErr)
				continue
			}

			flow = &udpFlow{
				ch:      ch,
				srcAddr: srcAddr,
				inbox:   make(chan pooledDatagram, udpInboxCapacity),
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
			d.release()
		default:
			d.release()
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
				d.release()
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
			err := writeUDPFrame(f.ch, d.bytes())
			d.release()
			if err != nil {
				log.Debugf("session %s: UDP flow %s write error: %v", sessionID, key, err)
				f.close()
				return
			}
		}
	}
}

// udpFlowReceiver reads length-prefixed frames off the SSH channel and
// delivers each datagram back to the original UDP source. Each frame is
// read into a pool buffer sized to its payload, so the steady-state cost
// for typical (sub-MTU) traffic is a 2 kB buffer per in-flight frame
// rather than a persistent 64 kB buffer per flow.
func udpFlowReceiver(f *udpFlow, udpConn net.PacketConn) {
	for {
		d, err := readPooledDatagram(f.ch)
		if err != nil {
			if errors.Is(err, errOversizedFrame) {
				log.Warnf("UDP flow %s: %s; aborting flow", f.srcAddr, err)
			}
			return
		}
		if _, err := udpConn.WriteTo(d.bytes(), f.srcAddr); err != nil {
			log.Debugf("UDP write back to %s error: %s", f.srcAddr, err)
		}
		d.release()
		atomic.StoreInt64(&f.lastActive, time.Now().UnixNano())
	}
}

// openUDPFlowChannel opens a forwarded-tcpip SSH channel for one UDP flow,
// reusing the same channel type as TCP forwarding. The SSH client side does
// not need to distinguish UDP from TCP at the SSH layer, `ssh -R` simply
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
