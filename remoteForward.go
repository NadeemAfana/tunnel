package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// httpBindPort is the remote bind port that distinguishes HTTP/HTTPS forwards
// from raw TCP/UDP forwards. It is mutable so main.go can override the default
// at startup via the --httpPort flag. The client-side wrapper (tunnel.sh) and
// any raw `ssh -R` invocations must request the same port for HTTP traffic to
// be recognized.
var httpBindPort uint32 = 3000

// httpEnabled / tcpEnabled / udpEnabled gate which tunnel protocols are
// accepted. Set from --http / --tcp / --udp at startup. Defaults are true so
// tests that bypass main() see historical behavior unchanged.
var httpEnabled = true
var tcpEnabled = true
var udpEnabled = true

const forwardedTCPChannelType = "forwarded-tcpip"

func formatTunnelLine(from, localTarget string) string {
	return fmt.Sprintf("Tunneling %s -> %s\n", from, localTarget)
}

// forwardSetupContext carries the parsed and validated state from
// forwardHandler down to the per-protocol setup helpers
// (setupHTTPForward / setupTCPForward / setupUDPForward).
type forwardSetupContext struct {
	conn            *sshConnection
	session         execRequestCompletedData
	reqPayload      *remoteForwardRequest
	cancellationCtx context.Context
	clientID        string
	tunnelName      string
	header          string
	headerSpecified bool
	localTarget     string
	owner           string
	addr            string
	connectionType  string // "http" or "https" for HTTP setup; unused otherwise
}

func forwardHandler(conn *sshConnection, req *ssh.Request, execRequestCompleted chan execRequestCompletedData, cancellationCtx context.Context) (bool, []byte) {
	var reqPayload remoteForwardRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		log.Printf("error in tcpip-forward: %s", err)
		return false, []byte{}
	}

	log.Printf("Session %s started", hex.EncodeToString(conn.SessionID()))

	// Wait for SSH session handler to finish or connection close
	session := <-execRequestCompleted
	if session.channel == nil {
		log.Printf("Session %s channel is nil", hex.EncodeToString(conn.SessionID()))
		return false, []byte{}
	}

	// Cache channel for communication with client upon receiving HTTP requests
	conn.SetSessionChannel(&session.channel)

	// For retaining the same tunnelName name in case of an SHH client interruption,
	// Firstly, the tunnelName must not be taken.
	// The client must send its tunnelName name via a channel along with an id (id=dhskjdshf24343,tunnelName=tunnel)
	cmdParts := strings.Split(session.request, ",")
	clientID := ""
	tunnelName := ""
	header := ""
	connectionType := ""
	localTarget := ""
	headerSpecified := false

	for _, p := range cmdParts {
		p = strings.ToLower(strings.TrimSpace(p))
		idIndex := strings.Index(p, "id=")
		tunnelNameIndex := strings.Index(p, "tunnelname=")
		connTypeIndex := strings.Index(p, "type=")
		headerIndex := strings.Index(p, "header=")
		localTargetIndex := strings.Index(p, "localtarget=")

		if idIndex == 0 {
			clientID = p[idIndex+len("id="):]
		} else if tunnelNameIndex == 0 {
			tunnelName = p[tunnelNameIndex+len("tunnelname="):]
		} else if connTypeIndex == 0 {
			connectionType = p[connTypeIndex+len("type="):]

			if connectionType != "https" && connectionType != "http" && connectionType != "tcp" && connectionType != "udp" {
				log.Printf("invalid connectionType %s", connectionType)
				return false, []byte(fmt.Sprintf("invalid connectionType %s", connectionType))
			}
		} else if headerIndex == 0 {
			header = p[headerIndex+len("header="):]
			headerSpecified = true
		} else if localTargetIndex == 0 {
			localTarget = p[localTargetIndex+len("localtarget="):]
		}
	}

	// Default to HTTP when the client did not specify a type. Earlier behavior
	// fell through to TCP, but HTTP is the most common case and matches what
	// tunnel.sh sends.
	if connectionType == "" {
		connectionType = "http"
	}

	// Reject the request early if the operator has disabled this protocol via
	// --http / --tcp / --udp. Surface a human-readable message on the SSH
	// session so the client sees why their tunnel was rejected.
	switch connectionType {
	case "http", "https":
		if !httpEnabled {
			msg := "HTTP tunneling is not enabled\n"
			io.WriteString(session.channel, msg)
			return false, []byte(msg)
		}
	case "tcp":
		if !tcpEnabled {
			msg := "TCP tunneling is not enabled\n"
			io.WriteString(session.channel, msg)
			return false, []byte(msg)
		}
	case "udp":
		if !udpEnabled {
			msg := "UDP tunneling is not enabled\n"
			io.WriteString(session.channel, msg)
			return false, []byte(msg)
		}
	}

	if clientID == "" {
		log.Printf("id empty setting equal to session id %s", hex.EncodeToString(conn.SessionID()))
		clientID = hex.EncodeToString(conn.SessionID())
	}

	// Authenticated identity from PublicKeyCallback. Used as the per-user
	// quota key in the port registry and for audit logging. Falls back to
	// sessionID if the auth layer somehow did not set it (defense-in-depth;
	// this should not happen in practice).
	owner := ""
	if conn.Permissions != nil {
		owner = conn.Permissions.Extensions["key-name"]
	}
	if owner == "" {
		owner = "session-" + hex.EncodeToString(conn.SessionID())
	}

	// For HTTP/HTTPS, the public port is server-controlled (httpBindPort) and
	// not a per-client choice. Reject explicit non-matching ports rather than
	// silently ignoring them, so a user passing `-p 800 --http` gets a clear
	// error instead of wondering why their port was discarded. Clients should
	// send 0 (or omit `-p`); httpBindPort is also accepted as a no-op.
	if connectionType == "http" || connectionType == "https" {
		if reqPayload.BindPort != 0 && reqPayload.BindPort != httpBindPort {
			msg := fmt.Sprintf("HTTP/HTTPS tunnels do not accept a custom remote port; "+
				"the server binds to --httpPort=%d. Send 0 (or omit -p) instead of %d.\n",
				httpBindPort, reqPayload.BindPort)
			io.WriteString(session.channel, msg)
			return false, []byte(msg)
		}
	}

	// Server localhost:port to listen for http requests at.
	// For HTTP/HTTPS, pin the shared listener to httpBindPort regardless of
	// what the client requested. HTTP discrimination is driven entirely by
	// `type=http|https` in the exec command. Rewrite reqPayload.BindPort to
	// the effective port so disconnect cleanup at main.go and the cancel
	// handler below build matching cache keys (mirrors the TCP/UDP pattern
	// where the server-allocated port is written back to reqPayload).
	var addr string
	if connectionType == "http" || connectionType == "https" {
		reqPayload.BindPort = httpBindPort
		addr = net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(httpBindPort)))
	} else {
		addr = net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	}

	conn.SetRequestForwardPayload(&reqPayload)

	sc := &forwardSetupContext{
		conn:            conn,
		session:         session,
		reqPayload:      &reqPayload,
		cancellationCtx: cancellationCtx,
		clientID:        clientID,
		tunnelName:      tunnelName,
		header:          header,
		headerSpecified: headerSpecified,
		localTarget:     localTarget,
		owner:           owner,
		addr:            addr,
		connectionType:  connectionType,
	}

	// Dispatch by protocol. For TCP, the connection is one-to-one meaning the
	// local listener is exclusively for this SSH client. For HTTP, the
	// connection is shared (many-to-one) — one listener on httpBindPort fans
	// out to many clients keyed by tunnelName.
	switch connectionType {
	case "http", "https":
		return setupHTTPForward(sc)
	case "udp":
		return setupUDPForward(sc)
	default:
		return setupTCPForward(sc)
	}
}

func cancelForwardHandler(conn *sshConnection, req *ssh.Request, ctx context.Context) (bool, []byte) {
	var reqPayload remoteForwardCancelRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		log.Printf("error in cancel-tcpip-forward: %s", err)
		return false, []byte{}
	}
	if reqPayload.BindPort == httpBindPort {
		tunnelName := conn.GetTunnelName()
		if tunnelName != nil {
			cacheKey := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort))) + *conn.GetTunnelName()

			sshTunnelListenersLock.Lock()
			s, ok := sshTunnelListeners[cacheKey]
			if ok && s.sessionID == hex.EncodeToString(conn.SessionID()) {
				delete(sshTunnelListeners, cacheKey)
				log.Printf("Purged cache for session %s", s.sessionID)
			}
			sshTunnelListenersLock.Unlock()
		}
		return true, nil
	}
	// TCP/UDP: closing the listener (or PacketConn) makes the per-forward
	// goroutine exit. Also release the registry slot so the user's quota and
	// the port itself are immediately reusable.
	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	forwardsLock.Lock()
	lnO, ok := forwards[addr]
	if ok {
		delete(forwards, addr)
	}
	forwardsLock.Unlock()
	if ok {
		lnO.listener.Close()
		releasePortFromRegistry(addr, lnO.conType)
	}
	return true, nil
}
