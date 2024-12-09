package main

import (
	"net"

	"golang.org/x/crypto/ssh"
)

type sshTunnelsListenerData struct {
	conn       *sshConnection
	reqPayload *remoteForwardRequest
	sessionID  string
	clientID   string // For reconnecting: allow client to re-use same subdomain
	hostHeader *string
	// Is the client TCP or http?
	connectionType string
}

type forwardsListenerData struct {
	listener  net.Listener
	clientID  string // TCP only: For reconnecting: allow client to re-use same subdomain
	sessionID string // TCP only: ditto
	conType   connectionType
}

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type execRequestCompletedData struct {
	channel ssh.Channel
	request string
}

type connectionType string

var TCPConnectionType connectionType = "tcp"
var HTTPConnectionType connectionType = "http"
