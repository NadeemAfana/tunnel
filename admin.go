package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

const adminCommandPrefix = "tunnel-admin"

// handleAdminExec runs synchronously from sessionChannelHandler. It reads the
// passphrase from the first stdin line, verifies it against adminPassphraseHash,
// dispatches the subcommand, then sends an exit-status request and closes the
// channel. The caller's key name (from the SSH permissions extensions) is used
// purely for audit logging.
func handleAdminExec(channel ssh.Channel, conn *ssh.ServerConn, command string) {
	defer channel.Close()

	callerName := conn.Permissions.Extensions["key-name"]

	if len(adminPassphraseHash) == 0 {
		fmt.Fprintln(channel.Stderr(), "admin commands disabled: server has no admin_passphrase_bcrypt configured")
		sendExitStatus(channel, 1)
		return
	}

	reader := bufio.NewReader(channel)
	passphrase, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(channel.Stderr(), "failed to read passphrase: %v\n", err)
		sendExitStatus(channel, 1)
		return
	}
	passphrase = strings.TrimRight(passphrase, "\r\n")
	if passphrase == "" {
		fmt.Fprintln(channel.Stderr(), "passphrase required on first stdin line")
		sendExitStatus(channel, 1)
		return
	}

	if err := bcrypt.CompareHashAndPassword(adminPassphraseHash, []byte(passphrase)); err != nil {
		log.Warnf("ADMIN AUTH FAIL: caller=%q command=%q", callerName, command)
		fmt.Fprintln(channel.Stderr(), "invalid passphrase")
		sendExitStatus(channel, 1)
		return
	}

	// command form: "tunnel-admin <subcommand> [args...]"
	parts := strings.Fields(strings.TrimPrefix(command, adminCommandPrefix))
	if len(parts) == 0 {
		fmt.Fprintln(channel.Stderr(), "usage: tunnel-admin <list|add NAME|remove NAME>")
		sendExitStatus(channel, 1)
		return
	}

	switch parts[0] {
	case "list":
		adminList(channel)
		sendExitStatus(channel, 0)

	case "add":
		if len(parts) != 2 {
			fmt.Fprintln(channel.Stderr(), "usage: tunnel-admin add NAME (public key on stdin after passphrase line)")
			sendExitStatus(channel, 1)
			return
		}
		// Remaining stdin is the OpenSSH-format public key (one line).
		body, err := io.ReadAll(reader)
		if err != nil {
			fmt.Fprintf(channel.Stderr(), "failed to read public key: %v\n", err)
			sendExitStatus(channel, 1)
			return
		}
		if err := adminAddKey(channel, callerName, parts[1], body); err != nil {
			fmt.Fprintf(channel.Stderr(), "%v\n", err)
			sendExitStatus(channel, 1)
			return
		}
		sendExitStatus(channel, 0)

	case "remove":
		if len(parts) != 2 {
			fmt.Fprintln(channel.Stderr(), "usage: tunnel-admin remove NAME")
			sendExitStatus(channel, 1)
			return
		}
		if err := adminRemoveKey(channel, callerName, parts[1]); err != nil {
			fmt.Fprintf(channel.Stderr(), "%v\n", err)
			sendExitStatus(channel, 1)
			return
		}
		sendExitStatus(channel, 0)

	default:
		fmt.Fprintf(channel.Stderr(), "unknown subcommand %q (expected list, add, remove)\n", parts[0])
		sendExitStatus(channel, 1)
	}
}

func adminList(out io.Writer) {
	authorizedKeysLock.RLock()
	defer authorizedKeysLock.RUnlock()

	for marshaled, name := range authorizedKeys {
		pk, err := ssh.ParsePublicKey([]byte(marshaled))
		if err != nil {
			fmt.Fprintf(out, "%s\t<unparseable: %v>\n", name, err)
			continue
		}
		fmt.Fprintf(out, "%s\t%s\n", name, strings.TrimRight(string(ssh.MarshalAuthorizedKey(pk)), "\n"))
	}
}

func adminAddKey(out io.Writer, callerName, name string, publicKeyBytes []byte) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}
	marshaled := string(pubKey.Marshal())

	authorizedKeysLock.Lock()
	if existingName, dup := authorizedKeys[marshaled]; dup {
		authorizedKeysLock.Unlock()
		return fmt.Errorf("public key already registered under name %q", existingName)
	}
	for _, existing := range authorizedKeys {
		if existing == name {
			authorizedKeysLock.Unlock()
			return fmt.Errorf("name %q is already in use", name)
		}
	}
	authorizedKeys[marshaled] = name
	authorizedKeysLock.Unlock()

	keyLine := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pubKey)), "\n")
	log.Warnf("ADMIN ACTION: %q added key %q (fingerprint %s). Persist to authorized_keys.json:\n  { \"name\": %q, \"publicKey\": %q }",
		callerName, name, ssh.FingerprintSHA256(pubKey), name, keyLine)

	fmt.Fprintf(out, "ok: added key %q\n", name)
	return nil
}

func adminRemoveKey(out io.Writer, callerName, name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if name == callerName {
		return fmt.Errorf("refusing to remove caller's own key %q (would lock you out)", name)
	}

	authorizedKeysLock.Lock()
	var marshaledToRemove string
	for marshaled, existingName := range authorizedKeys {
		if existingName == name {
			marshaledToRemove = marshaled
			break
		}
	}
	if marshaledToRemove == "" {
		authorizedKeysLock.Unlock()
		return fmt.Errorf("no key found with name %q", name)
	}
	delete(authorizedKeys, marshaledToRemove)
	authorizedKeysLock.Unlock()

	pk, err := ssh.ParsePublicKey([]byte(marshaledToRemove))
	fingerprint := "<unknown>"
	if err == nil {
		fingerprint = ssh.FingerprintSHA256(pk)
	}
	log.Warnf("ADMIN ACTION: %q removed key %q (fingerprint %s). Remove this entry from authorized_keys.json.",
		callerName, name, fingerprint)

	fmt.Fprintf(out, "ok: removed key %q\n", name)
	return nil
}

func sendExitStatus(channel ssh.Channel, status uint32) {
	channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}

// runGenAdminHash reads a passphrase from stdin (whole content, then trims
// trailing newline so `echo "pass"` works), prints its bcrypt hash to stdout,
// and exits. Used to bootstrap admin_passphrase_bcrypt without needing
// htpasswd, mkpasswd, openssl, or any other external tool.
func runGenAdminHash() {
	passphraseBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
		os.Exit(1)
	}
	passphrase := strings.TrimRight(string(passphraseBytes), "\r\n")
	if passphrase == "" {
		fmt.Fprintln(os.Stderr, "passphrase is empty (read 0 bytes from stdin)")
		os.Exit(1)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(passphrase), 12)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bcrypt: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}
