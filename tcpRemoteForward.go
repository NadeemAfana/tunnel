package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

const tcpBufferSize = 32 << 10 // 32 kB buffer.
var bufPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, tcpBufferSize)
		return &buffer
	},
}

// setupTCPForward binds a TCP listener for one tcpip-forward request. For a
// caller-specified port, the port registry validates the request (range,
// per-user quota, already-in-use). For port 0, a free port is allocated from
// the registry with retries on rare kernel-level collisions. Each accepted
// TCP connection opens a fresh forwarded-tcpip SSH channel.
func setupTCPForward(sc *forwardSetupContext) (bool, []byte) {
	conn := sc.conn
	session := sc.session
	reqPayload := sc.reqPayload
	addr := sc.addr
	clientID := sc.clientID
	owner := sc.owner
	cancellationCtx := sc.cancellationCtx

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

	io.WriteString(session.channel, formatTunnelLine(fmt.Sprintf("TCP %s:%d", domainURI.Hostname(), requestBindPort), sc.localTarget))

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
