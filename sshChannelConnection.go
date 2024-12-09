package main

import (
	"context"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Wraps ssh.Channel with net.Conn
type sshChannelConnection struct {
	net.Conn
	sshChannel      *ssh.Channel
	cancellationCtx context.Context
}

func (c *sshChannelConnection) Read(b []byte) (n int, err error) {
	return (*c.sshChannel).Read(b)
}

func (c *sshChannelConnection) Write(b []byte) (n int, err error) {
	return (*c.sshChannel).Write(b)
}

func (c *sshChannelConnection) Close() error {
	return (*c.sshChannel).Close()
}

func (c *sshChannelConnection) LocalAddr() net.Addr {
	// Not used
	return nil
}

func (c *sshChannelConnection) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail instead of blocking. The deadline applies to all future
// and pending I/O, not just the immediately following call to
// Read or Write. After a deadline has been exceeded, the
// connection can be refreshed by setting a deadline in the future.
//
// If the deadline is exceeded a call to Read or Write or to other
// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
// The error's Timeout method will return true, but note that there
// are other possible errors for which the Timeout method will
// return true even if the deadline has not been exceeded.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *sshChannelConnection) SetDeadline(t time.Time) error {

	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *sshChannelConnection) SetReadDeadline(t time.Time) error {
	// TODO: Implement using a channel
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *sshChannelConnection) SetWriteDeadline(t time.Time) error {
	// TODO: Implement using a channel
	return nil
}

func newSSHChannelConnection(sshChannel *ssh.Channel, cancellationCtx context.Context) *sshChannelConnection {
	return &sshChannelConnection{sshChannel: sshChannel, cancellationCtx: cancellationCtx}
}
