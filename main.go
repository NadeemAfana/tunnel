package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type authorizedKeyEntry struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type authorizedKeysFile struct {
	Keys []authorizedKeyEntry `json:"keys"`
}

// DNS domainURL. This might include a path but only when domainPath is true.
// This will be used for both TCP and HTTP tunnels. For TCP, the host name part is used.
var domainURL string
var domainURI url.URL

// Indicates a url path (ie not subdomain) setup.
var domainPath bool

const sshPort = 5223
const clientKeepaliveInterval = 5 * time.Second
const clientKeepaliveMaxCount = 2

const forwardTCPRequestType = "tcpip-forward"
const cancelForwardTCPRequestType = "cancel-tcpip-forward"

// Represents tunnels: SSH connections filtered by localhost binding port+subdomain (:80+subdomain)
var sshTunnelListeners map[string]sshTunnelsListenerData
var sshTunnelListenersLock sync.RWMutex
var forwards map[string]forwardsListenerData
var forwardsLock sync.Mutex

// Authorized client SSH public keys, in-memory. Key is the marshaled wire-format
// of the public key (pubKey.Marshal()), value is the display name. Mutated at
// runtime by the admin command channel; protected by authorizedKeysLock.
var authorizedKeys map[string]string
var authorizedKeysLock sync.RWMutex

// bcrypt hash of the admin passphrase, loaded from the admin_passphrase_bcrypt
// env var. If empty, admin commands are disabled.
var adminPassphraseHash []byte

// Global TCP/UDP port registry. Initialized from --portMin / --portMax /
// --maxPortsPerUser at startup; nil during very early init and in tests that
// don't go through main(). Tests in this package replace it via
// setupTestServer.
var ports *portRegistry

func init() {
	forwards = make(map[string]forwardsListenerData)
	sshTunnelListeners = make(map[string]sshTunnelsListenerData)
	authorizedKeys = make(map[string]string)
}

func main() {

	// --domainUrl="https://domain.io"
	domainPtr := flag.String("domainUrl", "", "DNS domain URL (eg https://domain.io) that points to this server. Users will use this url to send HTTP requests and will use the host part of this url for TCP communication.")

	// --domainPath=true or --domainPath
	domainPathPtr := flag.Bool("domainPath", false, "Instead of subdomains, use a URL query path for user tunnels.")

	// --authorizedKeysFile=/etc/tunnel/authorized_keys.json
	authorizedKeysFilePtr := flag.String("authorizedKeysFile", "", "Path to a JSON file listing authorized client public keys. Required.")

	// --log=info
	logPtr := flag.String("log", "info", "Log level: debug, info, warn, or error.")

	// --pprof=6060
	// Spin up pprof endpoints at port 6060
	pprofPtr := flag.Int("pprof", 0, "port number to spin up pprof endpoints for. Useful for debugging and troubleshooting.")

	// --httpPort=3000
	// TCP port on which the server listens for incoming HTTP/HTTPS tunnel
	// traffic. Defaults to 3000 so the binary can run as an unprivileged user
	// (ports < 1024 require CAP_NET_BIND_SERVICE on Linux). Front this with a
	// reverse proxy (ALB, Nginx, etc.) on 80/443 if you want clean URLs.
	httpPortPtr := flag.Int("httpPort", 3000, "TCP port to listen on for incoming HTTP/HTTPS tunnel traffic.")

	// --portMin / --portMax: shared TCP+UDP port range for per-tunnel
	// listeners. Above the kernel's privileged range (1024) so the non-root
	// container can bind. The default upper bound overlaps the Linux ephemeral
	// range (32768-60999), which is fine because the server picks ports from
	// its own registry; on rare kernel collisions the bind retries.
	portMinPtr := flag.Int("portMin", 10000, "Minimum TCP/UDP remote port for tunnels (inclusive).")
	portMaxPtr := flag.Int("portMax", 59999, "Maximum TCP/UDP remote port for tunnels (inclusive).")
	maxPortsPerUserPtr := flag.Int("maxPortsPerUser", 30, "Maximum simultaneous TCP/UDP tunnels per authenticated key (combined across protocols).")

	// --genAdminHash: utility mode. Reads a passphrase from stdin, prints the
	// bcrypt hash, and exits. Used to bootstrap the admin_passphrase_bcrypt
	// env var without external tools.
	genAdminHashPtr := flag.Bool("genAdminHash", false, "Read a passphrase from stdin, print its bcrypt hash, and exit. Used once to bootstrap admin_passphrase_bcrypt.")

	flag.Parse()

	if *genAdminHashPtr {
		runGenAdminHash()
		return
	}

	if domainPtr == nil || *domainPtr == "" {
		log.Fatalln("DNS domain is empty.")
	}
	domainURL = *domainPtr

	uriPtr, err := url.Parse(domainURL)
	if err != nil {
		log.Fatalf("An error occured parsing domainURL: %s", err)
	}
	domainURI = *uriPtr

	if domainPathPtr != nil {
		domainPath = *domainPathPtr
	}

	if *httpPortPtr <= 0 || *httpPortPtr >= 1<<16 {
		log.Fatalf("--httpPort=%d is out of range (1-65535)", *httpPortPtr)
	}
	httpBindPort = uint32(*httpPortPtr)

	if *portMinPtr < 1 || *portMaxPtr >= 1<<16 || *portMinPtr > *portMaxPtr {
		log.Fatalf("invalid TCP/UDP port range [%d, %d]", *portMinPtr, *portMaxPtr)
	}
	if *maxPortsPerUserPtr < 1 {
		log.Fatalf("--maxPortsPerUser must be >= 1; got %d", *maxPortsPerUserPtr)
	}
	ports = newPortRegistry(uint32(*portMinPtr), uint32(*portMaxPtr), *maxPortsPerUserPtr)

	log.SetOutput(os.Stdout)

	logLevel, err := log.ParseLevel(*logPtr)
	if err != nil {
		log.Fatalf("An error occured parsing log level: %s", err)
	}
	log.SetLevel(logLevel)

	if authorizedKeysFilePtr == nil || *authorizedKeysFilePtr == "" {
		log.Fatalln("--authorizedKeysFile is required")
	}

	authorizedKeysData, err := os.ReadFile(*authorizedKeysFilePtr)
	if err != nil {
		log.Fatalf("Failed to read authorized keys file %q: %v", *authorizedKeysFilePtr, err)
	}

	var keysFile authorizedKeysFile
	if err := json.Unmarshal(authorizedKeysData, &keysFile); err != nil {
		log.Fatalf("Failed to parse authorized keys file %q: %v", *authorizedKeysFilePtr, err)
	}

	cancellationCtx, cancelBackground := context.WithCancel(context.Background())
	defer cancelBackground()

	// Public key authentication compares the public key of a received
	// connection against the entries loaded from --authorizedKeysFile.
	// Map value is the entry's name, used for logging.
	authorizedKeysLock.Lock()
	for _, entry := range keysFile.Keys {
		if entry.PublicKey == "" {
			log.Fatalf("Authorized keys file entry %q has empty publicKey", entry.Name)
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry.PublicKey))
		if err != nil {
			log.Fatalf("Failed to parse public key for entry %q: %v", entry.Name, err)
		}
		authorizedKeys[string(pubKey.Marshal())] = entry.Name
	}
	authorizedKeysLock.Unlock()

	// Optional bcrypt hash of the admin passphrase. If unset, admin commands
	// are rejected at runtime.
	if hash := os.Getenv("admin_passphrase_bcrypt"); hash != "" {
		adminPassphraseHash = []byte(hash)
		log.Printf("Admin commands enabled (passphrase hash loaded)")
	} else {
		log.Printf("Admin commands disabled (admin_passphrase_bcrypt env var not set)")
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			authorizedKeysLock.RLock()
			name, ok := authorizedKeys[string(pubKey.Marshal())]
			authorizedKeysLock.RUnlock()
			if ok {
				return &ssh.Permissions{
					// Record the public key and entry name used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
						"key-name":  name,
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for session %q", c.SessionID())
		},
	}
	var privateBytes []byte
	if os.Getenv("ssh_host_key_enc") != "" {
		privateBytes, err = base64.StdEncoding.DecodeString(os.Getenv("ssh_host_key_enc"))
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
	quit := make(chan os.Signal, 1)
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

	sshTunnelListenersLock.RLock()
	for _, tunnel := range sshTunnelListeners {
		tunnel.conn.Close()
	}
	sshTunnelListenersLock.RUnlock()

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
	log.Printf("logged in as %q with key %s and session %s", conn.Permissions.Extensions["key-name"], conn.Permissions.Extensions["pubkey-fp"], hex.EncodeToString(conn.SessionID()))

	serverConnection := newSSHConnection(conn, cancellationCtx)

	// Signaled when the "exec" request is handled
	// Because "session" channel can come in async along with port forward global request, we need a sync mechanism.
	execRequestCompleted := make(chan execRequestCompletedData)
	defer close(execRequestCompleted)
	defer func() {
		sessionID := hex.EncodeToString(conn.SessionID())

		// Clean up subdomain cache (HTTP only — one tunnel name per connection).
		subdomain := serverConnection.GetTunnelName()
		if subdomain != nil {
			forwardRequest := serverConnection.GetRequestForwardPayload()
			if forwardRequest != nil {
				cacheKey := net.JoinHostPort(forwardRequest.BindAddr, strconv.Itoa(int(forwardRequest.BindPort))) + *subdomain

				sshTunnelListenersLock.Lock()
				s, ok := sshTunnelListeners[cacheKey]
				if ok && s.sessionID == sessionID {
					delete(sshTunnelListeners, cacheKey)
					log.Printf("Purged cache for HTTP session %s\n", s.sessionID)
				}
				sshTunnelListenersLock.Unlock()
			}
		}

		// Close every TCP/UDP listener bound by this session. A session may
		// register more than one forward, so iterate everything tracked.
		for _, addr := range serverConnection.GetForwardAddrs() {
			forwardsLock.Lock()
			o, ok := forwards[addr]
			if ok && o.sessionID == sessionID {
				delete(forwards, addr)
				o.listener.Close()
				releasePortFromRegistry(addr, o.conType)
				log.Printf("Purged %s forward cache for session %s @ %s", o.conType, o.sessionID, addr)
			}
			forwardsLock.Unlock()
		}
	}()

	// The incoming Request channel must be serviced.
	// Global SSH requests come here (eg tcpip-forward,  cancel-tcpip-forward)
	// See 4.9.2.  Connection Protocol Global Request Names  https://www.ietf.org/rfc/rfc4250.txt
	go handleGlobalRequests(reqs, serverConnection, execRequestCompleted, cancellationCtx)

	go func() {
		// Keepalive: send periodic SSH requests to detect dead connections.
		// All state mutation happens on this single goroutine — no shared
		// counter, no nested goroutines — so there is no data race and the
		// "N consecutive missed replies" semantic is enforced correctly even
		// when a slow reply arrives after several ticks.
		missing := 0
		ticker := time.NewTicker(clientKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-cancellationCtx.Done():
				return
			case <-ticker.C:
				if missing >= clientKeepaliveMaxCount {
					log.Printf("Did not receive keepalive replies, closing session %s", hex.EncodeToString(conn.SessionID()))
					if err := conn.Close(); err != nil {
						log.Debugf("error closing session %s: %s", hex.EncodeToString(conn.SessionID()), err)
					}
					return
				}
				// SendRequest blocks until the client replies (or the
				// connection breaks). That is fine — this goroutine has no
				// other work, and Ticker.C drops extra ticks if SendRequest
				// is slower than the interval.
				if _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); err != nil {
					missing++
				} else {
					missing = 0
				}
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

				// Admin commands are handled inline (not via the tunnel-forward path).
				// They run synchronously, send an exit-status, and return.
				if strings.HasPrefix(execRequest, adminCommandPrefix) {
					req.Reply(true, nil)
					handleAdminExec(channel, conn, execRequest)
					continue
				}

				// Signal SSH handler completion and pass channel for communication with client
				execRequestCompleted <- execRequestCompletedData{channel: channel, request: execRequest}

				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}
		}
	}(requests)

}
