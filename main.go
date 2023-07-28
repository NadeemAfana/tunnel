package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var domain string

const sshPort = 5223
const clientKeepaliveInterval = 5 * time.Second
const clientKeepaliveMaxCount = 2

const forwardTCPRequestType = "tcpip-forward"
const cancelForwardTCPRequestType = "cancel-tcpip-forward"

// Represents tunnels: SSH connections filtered by localhost binding port+subdomain (:80+subdomain)
var sshTunnelListeners map[string]sshTunnelsListenerData
var sshTunnelListenersLock sync.Mutex
var forwards map[string]forwardsListenerData
var forwardsLock sync.Mutex

func init() {
	forwards = make(map[string]forwardsListenerData)
	sshTunnelListeners = make(map[string]sshTunnelsListenerData)
}

func main() {

	// --domain="domain.io"
	domainPtr := flag.String("domain", "", "DNS domain (eg domain.io) that points to this server.")

	// --log=info
	logPtr := flag.String("log", "info", "Log level: debug, info, warn, or error.")

	// --pprof=6060
	// Spin up pprof endpoints at port 6060
	pprofPtr := flag.Int("pprof", 0, "poprt number to spin up pprof endpoints for. Useful for debugging and troubleshooting.")

	flag.Parse()

	if domainPtr == nil || *domainPtr == "" {
		log.Fatalln("DNS domain is empty.")
	}
	domain = *domainPtr

	err := godotenv.Load("secrets.env")
	if err != nil {
		log.Fatalf("An error occured reading secrtets.env: %s", err)
	}

	log.SetOutput(os.Stdout)

	logLevel, err := log.ParseLevel(*logPtr)
	if err != nil {
		log.Fatalf("An error occured parsing log level: %s", err)
	}
	log.SetLevel(logLevel)

	var authorizedKeysBytes []byte
	if os.Getenv("authorized_keys.enc") != "" {
		authorizedKeysBytes, err = base64.StdEncoding.DecodeString(os.Getenv("authorized_keys.enc"))
	} else {
		authorizedKeysBytes, err = ioutil.ReadFile("authorized_keys")
	}
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
	}

	cancellationCtx, cancelBackground := context.WithCancel(context.Background())
	defer cancelBackground()

	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for session %q", c.SessionID())
		},
	}
	var privateBytes []byte
	if os.Getenv("ssh_host_key.enc") != "" {
		privateBytes, err = base64.StdEncoding.DecodeString(os.Getenv("ssh_host_key.enc"))
	} else {
		privateBytes, err = ioutil.ReadFile("ssh_host_key")
	}
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	sshLocalListener, err := net.Listen("tcp", ":"+strconv.Itoa(sshPort))
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	log.Println("Listening for SSH connections at", ":"+strconv.Itoa(sshPort))
	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Accept incoming SSH connections
	var tempDelay time.Duration
	go func() {
		for {
			conn, err := sshLocalListener.Accept()
			if err != nil {
				select {
				case <-cancellationCtx.Done():
					return
				default:
					if ne, ok := err.(net.Error); ok && ne.Temporary() {
						log.Println("temporary error accepting incoming connection: ", err)
						if tempDelay == 0 {
							tempDelay = 5 * time.Millisecond
						} else {
							tempDelay *= 2
						}
						if max := 1 * time.Second; tempDelay > max {
							tempDelay = max
						}
						time.Sleep(tempDelay)
						continue
					} else {
						log.Println("failed to accept incoming connection: ", err)
						break
					}
				}
			}

			// Handle incoming requests concurrently.
			go handleIncomingSSHConn(conn, config, cancellationCtx)
		}
	}()

	// Did we specify pprof port?
	var srv *http.Server
	if pprofPtr != nil && *pprofPtr > 0 {
		srv = &http.Server{
			Addr: "localhost:" + strconv.Itoa(*pprofPtr),
		}
		go func() {
			log.Infof("Listening for HTTP pprof requests at %s...", srv.Addr)
			err := srv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				log.Infof("Shutting down HTTP server at %s...", srv.Addr)
			}
		}()
	}
	<-quit
	cancelBackground()
	if srv != nil {
		srv.Close()
	}
	sshLocalListener.Close()
	log.Println("Shutting down server...")

	// Close all forward/bound listeners (ie http)
	forwardsLock.Lock()
	for _, l := range forwards {
		l.listener.Close()
	}
	forwardsLock.Unlock()

	sshTunnelListenersLock.Lock()
	for _, tunnel := range sshTunnelListeners {
		tunnel.conn.Close()
	}
	sshTunnelListenersLock.Unlock()

	log.Infoln("Server exiting")
}

func handleIncomingSSHConn(nConn net.Conn, config *ssh.ServerConfig, cancellationCtx context.Context) {
	nConn.(*net.TCPConn).SetKeepAlive(true)
	nConn.(*net.TCPConn).SetKeepAlivePeriod(time.Second * 10)

	// Before use, a handshake must be performed on the incoming net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		// Logging would be too noisy on the server
		return
	}
	log.Printf("logged in with key %s and session %s", conn.Permissions.Extensions["pubkey-fp"], hex.EncodeToString(conn.SessionID()))

	serverConnection := newSSHConnection(conn, cancellationCtx)

	// Signaled when the "exec" request is handled
	// Because "session" channel can come in async along with port forward global request, we need a sync mechanism.
	execRequestCompleted := make(chan execRequestCompletedData)
	defer close(execRequestCompleted)
	defer func() {
		// Clean up subdomain cache
		subdomain := serverConnection.GetSubDomain()
		if subdomain != nil {
			forwardRequest := serverConnection.GetRequestForwardPayload()
			if forwardRequest != nil {
				cacheKey := net.JoinHostPort(forwardRequest.BindAddr, strconv.Itoa(int(forwardRequest.BindPort))) + *subdomain

				sshTunnelListenersLock.Lock()
				s, ok := sshTunnelListeners[cacheKey]
				if ok && s.sessionID == hex.EncodeToString(conn.SessionID()) {
					delete(sshTunnelListeners, cacheKey)
					log.Printf("Purged cache for HTTP session %s\n", s.sessionID)
				}
				sshTunnelListenersLock.Unlock()
			}
		}

		// Clean up TCP listener as well since it's one-to-one.
		forwardsLock.Lock()
		forwardRequest := serverConnection.GetRequestForwardPayload()
		if forwardRequest != nil {
			cacheKey := net.JoinHostPort(forwardRequest.BindAddr, strconv.Itoa(int(forwardRequest.BindPort)))
			o, ok := forwards[cacheKey]
			if ok && o.conType == TCPConnectionType && o.sessionID == hex.EncodeToString(conn.SessionID()) {
				delete(forwards, cacheKey)
				o.listener.Close()
				log.Printf("Purged cache for TCP session %s\n", o.sessionID)
			}
		}
		forwardsLock.Unlock()
	}()

	// The incoming Request channel must be serviced.
	// Global SSH requests come here (eg tcpip-forward,  cancel-tcpip-forward)
	// See 4.9.2.  Connection Protocol Global Request Names  https://www.ietf.org/rfc/rfc4250.txt
	go handleGlobalRequests(reqs, serverConnection, execRequestCompleted, cancellationCtx)

	go func() {
		// Keepalive
		// Send to client keepalive SSH requests
		missingReplies := 0
		ticker := time.NewTicker(clientKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if missingReplies >= clientKeepaliveMaxCount {
					log.Printf("Did not receive keepalive replies, closing session %s", hex.EncodeToString(conn.SessionID()))
					err := conn.Close()
					if err != nil {
						log.Debugf("error closing session %s: %s\n", hex.EncodeToString(conn.SessionID()), err)
					}
					return
				}
				missingReplies = missingReplies + 1
				go func() {
					// SendRequest is synchronous we don't wait on it since it can take a long time.
					_, _, err := conn.SendRequest("keepalive@domain.io", true, nil)
					if err == nil {
						// Reset count
						missingReplies = 0
					}
				}()

			}
		}
	}()

	channelAlreadyHandled := false
	// Service the incoming Channel channels (eg session, x11, etc). See 4.9.1.  Connection Protocol Channel Types https://www.ietf.org/rfc/rfc4250.txt
	for newChannel := range chans {

		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		} else if channelAlreadyHandled {
			newChannel.Reject(ssh.UnknownChannelType, "another session channel type already exists")
			continue
		} else {
			channelAlreadyHandled = true
			// We accept a single "Session" channel because otherwise there is no easy way to link a channel to the portforward global request.
			go sessionChannelHandler(newChannel, conn, execRequestCompleted, cancellationCtx)
		}
	}

}

func handleGlobalRequests(reqs <-chan *ssh.Request, conn *sshConnection, execRequestCompleted chan execRequestCompletedData, cancellationCtx context.Context) {
	// eg tcpip-forward request
	for req := range reqs {
		if req.Type == forwardTCPRequestType {
			ret, payload := forwardHandler(conn, req, execRequestCompleted, cancellationCtx)
			req.Reply(ret, payload)
		} else if req.Type == cancelForwardTCPRequestType {
			ret, payload := cancelForwardHandler(conn, req, cancellationCtx)
			req.Reply(ret, payload)
		} else {
			// Keepalive requests et al
			req.Reply(false, nil)
			continue
		}
	}
}

func sessionChannelHandler(sshChannel ssh.NewChannel, conn *ssh.ServerConn, execRequestCompleted chan<- execRequestCompletedData, cancellationCtx context.Context) {
	// "session" channel handler
	// Each SSH channel has multiple requests (eg exec, env). See 4.9.3.  Connection Protocol Channel Request Names  https://www.ietf.org/rfc/rfc4250.txt
	channel, requests, err := sshChannel.Accept()
	if err != nil {
		select {
		case <-cancellationCtx.Done():
			return
		default:
			log.Printf("Could not accept channel from session %s: %v\n", hex.EncodeToString(conn.SessionID()), err)
			return
		}
	}

	// Close channel when handler finishes processing all requests or cancelled/error
	defer channel.Close()

	//  Here we handle only the "exec" request only and once.
	requestHandled := false
	var execRequest string
	func(in <-chan *ssh.Request) {
		for req := range in {
			if req.Type == "exec" && !requestHandled {
				var payload = struct{ Value string }{}
				err := ssh.Unmarshal(req.Payload, &payload)
				if err != nil {
					log.Printf("error parsing exec payload for session %s: %s", hex.EncodeToString(conn.SessionID()), err)
					req.Reply(false, nil)
				}
				execRequest = payload.Value
				// We only accept one exec request per session
				requestHandled = true

				// Signal SSH handler completion and pass channel for communication with client
				execRequestCompleted <- execRequestCompletedData{channel: channel, request: execRequest}

				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}
		}
	}(requests)

}
