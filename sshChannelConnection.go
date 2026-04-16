package main

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Wraps ssh.Channel with net.Conn. SetReadDeadline/SetWriteDeadline are
// implemented via a timer that closes the underlying SSH channel on expiry,
// which unblocks any pending Read/Write. A pending Read/Write that hits a
// deadline returns os.ErrDeadlineExceeded and leaves the channel closed —
// callers (notably net/http's Transport) are expected to discard the conn
// on deadline exceeded, so reuse-after-deadline is not supported.
type sshChannelConnection struct {
	net.Conn
	sshChannel      *ssh.Channel
	cancellationCtx context.Context

	readDeadline  pipeDeadline
	writeDeadline pipeDeadline
}

func (c *sshChannelConnection) Read(b []byte) (n int, err error) {
	if isClosedChan(c.readDeadline.wait()) {
		return 0, os.ErrDeadlineExceeded
	}

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := (*c.sshChannel).Read(b)
		done <- result{n, err}
	}()

	select {
	case r := <-done:
		return r.n, r.err
	case <-c.readDeadline.wait():
		(*c.sshChannel).Close()
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *sshChannelConnection) Write(b []byte) (n int, err error) {
	if isClosedChan(c.writeDeadline.wait()) {
		return 0, os.ErrDeadlineExceeded
	}

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := (*c.sshChannel).Write(b)
		done <- result{n, err}
	}()

	select {
	case r := <-done:
		return r.n, r.err
	case <-c.writeDeadline.wait():
		(*c.sshChannel).Close()
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *sshChannelConnection) Close() error {
	// Clear any armed timers so the runtime doesn't hold references past Close.
	c.readDeadline.set(time.Time{})
	c.writeDeadline.set(time.Time{})
	return (*c.sshChannel).Close()
}

func (c *sshChannelConnection) LocalAddr() net.Addr {
	return sshChannelAddr{}
}

func (c *sshChannelConnection) RemoteAddr() net.Addr {
	return sshChannelAddr{}
}

func (c *sshChannelConnection) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *sshChannelConnection) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

func (c *sshChannelConnection) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.set(t)
	return nil
}

func newSSHChannelConnection(sshChannel *ssh.Channel, cancellationCtx context.Context) *sshChannelConnection {
	return &sshChannelConnection{
		sshChannel:      sshChannel,
		cancellationCtx: cancellationCtx,
		readDeadline:    makePipeDeadline(),
		writeDeadline:   makePipeDeadline(),
	}
}

// sshChannelAddr is a non-nil placeholder so callers that invoke LocalAddr /
// RemoteAddr (e.g. net/http for logging) don't get a nil interface.
type sshChannelAddr struct{}

func (sshChannelAddr) Network() string { return "ssh" }
func (sshChannelAddr) String() string  { return "ssh-channel" }

// pipeDeadline is the same deadline primitive used by Go's net.Pipe: calling
// set(t) arms a timer that closes the channel returned by wait() when t
// elapses. Setting a zero time clears the deadline.
type pipeDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func makePipeDeadline() pipeDeadline {
	return pipeDeadline{cancel: make(chan struct{})}
}

func (d *pipeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // wait for timer callback to finish closing cancel
	}
	d.timer = nil

	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}

	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		d.timer = time.AfterFunc(dur, func() {
			close(d.cancel)
		})
		return
	}

	if !closed {
		close(d.cancel)
	}
}

func (d *pipeDeadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
