package main

import (
	"context"
	"sync"

	"golang.org/x/crypto/ssh"
)

type sshConnection struct {
	*ssh.ServerConn
	*sync.Mutex
	tunnelName      *string
	reqPayload      *remoteForwardRequest
	sshChannel      *ssh.Channel
	cancellationCtx context.Context
}

func (c *sshConnection) SetRequestForwardPayload(r *remoteForwardRequest) {
	c.Lock()
	defer c.Unlock()
	c.reqPayload = r
}

func (c *sshConnection) GetRequestForwardPayload() *remoteForwardRequest {
	c.Lock()
	defer c.Unlock()
	return c.reqPayload
}

func (c *sshConnection) SetTunnelName(s string) {
	c.Lock()
	defer c.Unlock()
	c.tunnelName = &s
}

func (c *sshConnection) GetTunnelName() *string {
	c.Lock()
	defer c.Unlock()
	return c.tunnelName
}

func (c *sshConnection) GetSessionChannel() *ssh.Channel {
	c.Lock()
	defer c.Unlock()
	return c.sshChannel
}

func (c *sshConnection) SetSessionChannel(s *ssh.Channel) {
	c.Lock()
	defer c.Unlock()
	c.sshChannel = s
}

func newSSHConnection(conn *ssh.ServerConn, cancellationCtx context.Context) *sshConnection {
	return &sshConnection{conn, &sync.Mutex{}, nil, nil, nil, cancellationCtx}
}
