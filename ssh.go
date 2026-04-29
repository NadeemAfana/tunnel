package main

import (
	"context"
	"sync"

	"golang.org/x/crypto/ssh"
)

type sshConnection struct {
	*ssh.ServerConn
	mu              sync.RWMutex
	tunnelName      *string
	reqPayload      *remoteForwardRequest
	sshChannel      *ssh.Channel
	cancellationCtx context.Context
	// All bind addresses this connection has registered in the global `forwards`
	// map. Used by session-end cleanup to purge every TCP/UDP listener bound by
	// this session, since a single session may register multiple forwards.
	forwardAddrs []string
}

func (c *sshConnection) SetRequestForwardPayload(r *remoteForwardRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqPayload = r
}

func (c *sshConnection) GetRequestForwardPayload() *remoteForwardRequest {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.reqPayload
}

func (c *sshConnection) SetTunnelName(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tunnelName = &s
}

func (c *sshConnection) GetTunnelName() *string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tunnelName
}

func (c *sshConnection) GetSessionChannel() *ssh.Channel {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sshChannel
}

func (c *sshConnection) SetSessionChannel(s *ssh.Channel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sshChannel = s
}

func (c *sshConnection) AddForwardAddr(addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forwardAddrs = append(c.forwardAddrs, addr)
}

func (c *sshConnection) GetForwardAddrs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, len(c.forwardAddrs))
	copy(out, c.forwardAddrs)
	return out
}

func (c *sshConnection) RemoveForwardAddr(addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, a := range c.forwardAddrs {
		if a == addr {
			c.forwardAddrs = append(c.forwardAddrs[:i], c.forwardAddrs[i+1:]...)
			return
		}
	}
}

func newSSHConnection(conn *ssh.ServerConn, cancellationCtx context.Context) *sshConnection {
	return &sshConnection{
		ServerConn:      conn,
		cancellationCtx: cancellationCtx,
	}
}
