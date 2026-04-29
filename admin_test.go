package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

const adminTestPassphrase = "password@123"

// adminTestSetup wires up an SSH server that uses the production auth path
// (reads the package-level authorizedKeys map and sets the key-name extension).
// Tests in this package run serially - setup snapshots and restores the
// shared globals on cleanup so admin tests don't bleed into tunnel tests.
type adminTestSetup struct {
	sshAddr      string
	callerName   string
	callerSigner ssh.Signer
	extraSigner  ssh.Signer // a second valid keypair, NOT initially in authorizedKeys
	extraPubText string     // OpenSSH-format text, ready to feed to "tunnel-admin add"
	ctx          context.Context
	cancel       context.CancelFunc
}

func setupAdminTestServer(t *testing.T) *adminTestSetup {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	_, callerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen caller key: %v", err)
	}
	callerSigner, err := ssh.NewSignerFromKey(callerPriv)
	if err != nil {
		t.Fatalf("caller signer: %v", err)
	}

	_, extraPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen extra key: %v", err)
	}
	extraSigner, err := ssh.NewSignerFromKey(extraPriv)
	if err != nil {
		t.Fatalf("extra signer: %v", err)
	}
	extraPubText := strings.TrimRight(string(ssh.MarshalAuthorizedKey(extraSigner.PublicKey())), "\n")

	authorizedKeysLock.Lock()
	prevKeys := authorizedKeys
	authorizedKeys = map[string]string{
		string(callerSigner.PublicKey().Marshal()): "alice",
	}
	authorizedKeysLock.Unlock()

	prevHash := adminPassphraseHash
	hash, err := bcrypt.GenerateFromPassword([]byte(adminTestPassphrase), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	adminPassphraseHash = hash

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			authorizedKeysLock.RLock()
			name, ok := authorizedKeys[string(pubKey.Marshal())]
			authorizedKeysLock.RUnlock()
			if ok {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
						"key-name":  name,
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for session %q", c.SessionID())
		},
	}
	config.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ssh listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleIncomingSSHConn(nConn, config, ctx)
		}
	}()

	t.Cleanup(func() {
		cancel()
		ln.Close()
		authorizedKeysLock.Lock()
		authorizedKeys = prevKeys
		authorizedKeysLock.Unlock()
		adminPassphraseHash = prevHash
	})

	return &adminTestSetup{
		sshAddr:      ln.Addr().String(),
		callerName:   "alice",
		callerSigner: callerSigner,
		extraSigner:  extraSigner,
		extraPubText: extraPubText,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// runAdminCommand opens a fresh SSH session, sends an exec request, pipes the
// given stdin payload, and returns the captured stdout/stderr plus the exit
// status the server signalled. signer=nil uses the default caller key.
func runAdminCommand(t *testing.T, s *adminTestSetup, command, stdinContent string, signer ssh.Signer) (stdout, stderr string, exitStatus int) {
	t.Helper()
	if signer == nil {
		signer = s.callerSigner
	}

	cfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", s.sshAddr, cfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	sess.Stdout = &stdoutBuf
	sess.Stderr = &stderrBuf
	sess.Stdin = strings.NewReader(stdinContent)

	runErr := sess.Run(command)
	exit := 0
	if runErr != nil {
		if ee, ok := runErr.(*ssh.ExitError); ok {
			exit = ee.ExitStatus()
		} else {
			t.Fatalf("run: %v stderr=%q", runErr, stderrBuf.String())
		}
	}
	return stdoutBuf.String(), stderrBuf.String(), exit
}

// --- tests ---

func TestAdmin_List(t *testing.T) {
	s := setupAdminTestServer(t)

	stdout, stderr, exit := runAdminCommand(t, s, "tunnel-admin list", adminTestPassphrase+"\n", nil)
	if exit != 0 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr)
	}
	if !strings.Contains(stdout, "alice") {
		t.Errorf("expected caller name 'alice' in list, got: %q", stdout)
	}
}

func TestAdmin_AddThenAuthenticate(t *testing.T) {
	s := setupAdminTestServer(t)

	stdin := adminTestPassphrase + "\n" + s.extraPubText + "\n"
	stdout, stderr, exit := runAdminCommand(t, s, "tunnel-admin add bob", stdin, nil)
	if exit != 0 {
		t.Fatalf("add: exit=%d stderr=%q", exit, stderr)
	}
	if !strings.Contains(stdout, "added key") {
		t.Errorf("expected 'added key' in stdout: %q", stdout)
	}

	// Bob should now be able to authenticate using his new key.
	cfg := &ssh.ClientConfig{
		User:            "bob",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.extraSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", s.sshAddr, cfg)
	if err != nil {
		t.Fatalf("bob's new key was not accepted post-add: %v", err)
	}
	client.Close()
}

func TestAdmin_AddDuplicateName(t *testing.T) {
	s := setupAdminTestServer(t)

	stdin := adminTestPassphrase + "\n" + s.extraPubText + "\n"
	_, stderr, exit := runAdminCommand(t, s, "tunnel-admin add alice", stdin, nil)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for duplicate name")
	}
	if !strings.Contains(stderr, "already in use") {
		t.Errorf("expected 'already in use' in stderr, got: %q", stderr)
	}
}

func TestAdmin_AddDuplicateKey(t *testing.T) {
	s := setupAdminTestServer(t)

	stdin := adminTestPassphrase + "\n" + s.extraPubText + "\n"
	_, stderr, exit := runAdminCommand(t, s, "tunnel-admin add bob", stdin, nil)
	if exit != 0 {
		t.Fatalf("first add: exit=%d stderr=%q", exit, stderr)
	}

	_, stderr, exit = runAdminCommand(t, s, "tunnel-admin add carol", stdin, nil)
	if exit == 0 {
		t.Fatalf("expected duplicate-key rejection")
	}
	if !strings.Contains(stderr, "already registered") {
		t.Errorf("expected 'already registered' in stderr, got: %q", stderr)
	}
}

func TestAdmin_RemoveAndDeauthenticate(t *testing.T) {
	s := setupAdminTestServer(t)

	// Pre-populate bob directly so this test focuses on remove, not add.
	authorizedKeysLock.Lock()
	authorizedKeys[string(s.extraSigner.PublicKey().Marshal())] = "bob"
	authorizedKeysLock.Unlock()

	_, stderr, exit := runAdminCommand(t, s, "tunnel-admin remove bob", adminTestPassphrase+"\n", nil)
	if exit != 0 {
		t.Fatalf("remove: exit=%d stderr=%q", exit, stderr)
	}

	// Bob's key should no longer authenticate.
	cfg := &ssh.ClientConfig{
		User:            "bob",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.extraSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	if _, err := ssh.Dial("tcp", s.sshAddr, cfg); err == nil {
		t.Fatalf("bob's key should be rejected after removal")
	}
}

func TestAdmin_RemoveSelfRefused(t *testing.T) {
	s := setupAdminTestServer(t)

	_, stderr, exit := runAdminCommand(t, s, "tunnel-admin remove "+s.callerName, adminTestPassphrase+"\n", nil)
	if exit == 0 {
		t.Fatalf("expected refusal to remove caller's own key")
	}
	if !strings.Contains(stderr, "lock you out") {
		t.Errorf("expected lockout warning in stderr, got: %q", stderr)
	}

	// The caller's key must still authenticate.
	cfg := &ssh.ClientConfig{
		User:            s.callerName,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.callerSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	client, err := ssh.Dial("tcp", s.sshAddr, cfg)
	if err != nil {
		t.Fatalf("caller's key was unexpectedly removed: %v", err)
	}
	client.Close()
}

func TestAdmin_RemoveNonexistent(t *testing.T) {
	s := setupAdminTestServer(t)

	_, stderr, exit := runAdminCommand(t, s, "tunnel-admin remove ghost", adminTestPassphrase+"\n", nil)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for missing name")
	}
	if !strings.Contains(stderr, "no key found") {
		t.Errorf("expected 'no key found' in stderr, got: %q", stderr)
	}
}

func TestAdmin_WrongPassphrase(t *testing.T) {
	s := setupAdminTestServer(t)

	_, stderr, exit := runAdminCommand(t, s, "tunnel-admin list", "wrongpass\n", nil)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for wrong passphrase")
	}
	if !strings.Contains(stderr, "invalid passphrase") {
		t.Errorf("expected 'invalid passphrase' in stderr, got: %q", stderr)
	}
}

func TestAdmin_DisabledWhenNoHash(t *testing.T) {
	s := setupAdminTestServer(t)

	prev := adminPassphraseHash
	adminPassphraseHash = nil
	t.Cleanup(func() { adminPassphraseHash = prev })

	_, stderr, exit := runAdminCommand(t, s, "tunnel-admin list", adminTestPassphrase+"\n", nil)
	if exit == 0 {
		t.Fatalf("expected non-zero exit when admin is disabled")
	}
	if !strings.Contains(stderr, "disabled") {
		t.Errorf("expected 'disabled' in stderr, got: %q", stderr)
	}
}

func TestAdmin_UnknownSubcommand(t *testing.T) {
	s := setupAdminTestServer(t)

	_, stderr, exit := runAdminCommand(t, s, "tunnel-admin frobnicate", adminTestPassphrase+"\n", nil)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for unknown subcommand")
	}
	if !strings.Contains(stderr, "unknown subcommand") {
		t.Errorf("expected 'unknown subcommand' in stderr, got: %q", stderr)
	}
}

func TestRunGenAdminHash(t *testing.T) {
	// Redirect os.Stdin and os.Stdout via pipes, then call runGenAdminHash.
	// This exercises the bootstrap helper end-to-end (read stdin -> bcrypt ->
	// print hash) without spawning a subprocess.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdin: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}

	origStdin, origStdout := os.Stdin, os.Stdout
	os.Stdin = stdinR
	os.Stdout = stdoutW
	t.Cleanup(func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	})

	const passphrase = "test-passphrase-xyz"
	go func() {
		stdinW.Write([]byte(passphrase + "\n"))
		stdinW.Close()
	}()

	runGenAdminHash()
	stdoutW.Close()

	out, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	hash := strings.TrimRight(string(out), "\n")
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Fatalf("expected a bcrypt-format hash, got: %q", hash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(passphrase)); err != nil {
		t.Errorf("generated hash does not validate against original passphrase: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-passphrase")); err == nil {
		t.Errorf("generated hash should NOT validate against a different passphrase")
	}
}