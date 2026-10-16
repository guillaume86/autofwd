package sshconn

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/guillaume86/autofwd/internal/sshtest"
)

func writeFile(t *testing.T, path, data string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func slash(p string) string { return filepath.ToSlash(p) }

func TestResolve(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, filepath.Join(dir, "config"), `
Host dev
  HostName %h.example.com
  User alice
  Port 2222
  IdentityFile ~/.ssh/k1
  IdentityFile %d/k2
  IdentitiesOnly yes
  ProxyJump bastion
  ConnectTimeout 7

Host legacy
  ProxyCommand nc %h %p

Host direct
  ProxyJump none

Host *
  User fallback
  UserKnownHostsFile ~/kh1 ~/kh2
`)
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()

	h, err := r.Resolve("dev")
	if err != nil {
		t.Fatal(err)
	}
	if h.HostName != "dev.example.com" || h.User != "alice" || h.Port != "2222" || h.ProxyJump != "bastion" || !h.IdentitiesOnly {
		t.Errorf("dev resolved to %+v", h)
	}
	if want := []string{filepath.Join(home, ".ssh", "k1"), filepath.Join(home, "k2")}; !slices.Equal(h.IdentityFiles, want) {
		t.Errorf("IdentityFiles = %v, want %v", h.IdentityFiles, want)
	}
	if h.KnownHostsFiles[0] != filepath.Join(home, "kh1") || h.KnownHostsFiles[1] != filepath.Join(home, "kh2") {
		t.Errorf("KnownHostsFiles = %v", h.KnownHostsFiles)
	}
	if h.ConnectTimeout.Seconds() != 7 {
		t.Errorf("ConnectTimeout = %v", h.ConnectTimeout)
	}

	h, _ = r.Resolve("bob@dev")
	if h.User != "bob" || h.Alias != "dev" {
		t.Errorf("user override: %+v", h)
	}

	h, _ = r.Resolve("unknown.host")
	if h.HostName != "unknown.host" || h.Port != "22" || h.User != "fallback" || h.ProxyJump != "" {
		t.Errorf("unknown host: %+v", h)
	}
	if len(h.IdentityFiles) != 3 || filepath.Base(h.IdentityFiles[0]) != "id_ed25519" {
		t.Errorf("default identities: %v", h.IdentityFiles)
	}

	if h, _ := r.Resolve("direct"); h.ProxyJump != "" {
		t.Errorf("ProxyJump none: %q", h.ProxyJump)
	}

	var ce *ConfigError
	if _, err := r.Resolve("legacy"); !errors.As(err, &ce) || !strings.Contains(err.Error(), "ProxyCommand") {
		t.Errorf("ProxyCommand: %v", err)
	}
	for _, bad := range []string{"", "a b", "user@"} {
		if _, err := r.Resolve(bad); err == nil {
			t.Errorf("Resolve(%q) succeeded", bad)
		}
	}
}

func TestResolveRejectsUnparsableConfig(t *testing.T) {
	cfg := writeFile(t, filepath.Join(t.TempDir(), "config"), "Match exec \"true\"\n  User x\n")
	if _, err := NewResolver(cfg); err == nil {
		t.Fatal("expected an error for Match exec")
	}
}

func TestMissingConfigIsFine(t *testing.T) {
	if _, err := NewResolver(filepath.Join(t.TempDir(), "nope")); err != nil {
		t.Fatal(err)
	}
}

func TestParseJump(t *testing.T) {
	tests := []struct{ in, user, host, port string }{
		{"bastion", "", "bastion", ""},
		{"me@bastion", "me", "bastion", ""},
		{"me@bastion:2200", "me", "bastion", "2200"},
		{"10.0.0.1:22", "", "10.0.0.1", "22"},
		{"[2001:db8::1]:2200", "", "2001:db8::1", "2200"},
		{"2001:db8::1", "", "2001:db8::1", ""},
	}
	for _, tt := range tests {
		u, h, p, err := parseJump(tt.in)
		if err != nil || u != tt.user || h != tt.host || p != tt.port {
			t.Errorf("parseJump(%q) = %q %q %q, %v", tt.in, u, h, p, err)
		}
	}
	for _, bad := range []string{"host:abc", "host:0", "[::1", "a@b@host:70000"} {
		if _, _, _, err := parseJump(bad); err == nil {
			t.Errorf("parseJump(%q) accepted", bad)
		}
	}
}

func TestKnownAlgorithms(t *testing.T) {
	dir := t.TempDir()
	rsaLine := "[devbox]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDD0vjJ7Ml4cyk5Tyuwk6xUHRvdZd1E1IiQsYqLxNFl3ZqL9ZBC3xAuFy4wQhVB0jzG34QIBnO1i1EWy0p5r7ZE+GJNi4ITW9bE6Gy1+2kD/XZTWR/7swWjBNmdmn5fWtrsXDsCf8IJ04hxAp/pUX7bq2RjtmPxHVkm9W7+GYG3SQ==\n"
	edKey, _ := sshtest.NewKey(t)
	edLine := fmt.Sprintf("[devbox]:2222 %s", ssh.MarshalAuthorizedKey(edKey.PublicKey()))
	kh := writeFile(t, filepath.Join(dir, "kh"), edLine+rsaLine)
	db, err := knownhosts.New(kh)
	if err != nil {
		t.Fatal(err)
	}
	got := knownAlgorithms(db, "devbox:2222")
	// Known types first, in known_hosts order, then every other supported
	// type so a changed key type is reported as a mismatch, not a kex error.
	want := []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	if len(got) <= len(want) || !slices.Equal(got[:len(want)], want) {
		t.Errorf("got %v, want prefix %v and more", got, want)
	}
	if !slices.Contains(got, ssh.KeyAlgoECDSA256) || slices.Contains(got, ssh.KeyAlgoRSA) {
		t.Errorf("fallback list wrong: %v", got)
	}
	if slices.Index(got, ssh.KeyAlgoECDSA256) < len(want) {
		t.Errorf("fallback types must come after the known ones: %v", got)
	}
	if got := knownAlgorithms(db, "otherhost:22"); got != nil {
		t.Errorf("unknown host: %v", got)
	}
}

func writeKey(t *testing.T, path string, priv ed25519.PrivateKey, passphrase string) {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(pem.EncodeToMemory(block)))
}

type countingPrompt struct {
	mu      sync.Mutex
	answers []string
	calls   int
}

func (c *countingPrompt) prompt(string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if len(c.answers) == 0 {
		return nil, errors.New("unexpected prompt")
	}
	a := c.answers[0]
	c.answers = c.answers[1:]
	return []byte(a), nil
}

func hostBlock(alias string, port int, extra string) string {
	return fmt.Sprintf("Host %s\n  HostName 127.0.0.1\n  Port %d\n  User tester\n%s\n", alias, port, extra)
}

func commonBlock(dir string, keys ...string) string {
	var b strings.Builder
	b.WriteString("Host *\n  IdentityAgent none\n")
	fmt.Fprintf(&b, "  UserKnownHostsFile %s\n  GlobalKnownHostsFile %s\n", slash(filepath.Join(dir, "known_hosts")), slash(filepath.Join(dir, "none")))
	for _, k := range keys {
		fmt.Fprintf(&b, "  IdentityFile %s\n", slash(k))
	}
	return b.String()
}

func TestPassphrasePromptedOnceAcrossReconnects(t *testing.T) {
	dir := t.TempDir()
	signer, priv := sshtest.NewKey(t)
	srv := sshtest.Start(t, signer.PublicKey())
	keyPath := filepath.Join(dir, "id_enc")
	writeKey(t, keyPath, priv, "s3cret")
	writeFile(t, filepath.Join(dir, "known_hosts"), srv.KnownHostsLine()+"\n")
	cfg := writeFile(t, filepath.Join(dir, "config"), hostBlock("dev", srv.Port, "")+commonBlock(dir, keyPath))

	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := &countingPrompt{answers: []string{"wrong", "s3cret"}}
	d := NewDialer(r, p.prompt, nil)
	for i := range 3 {
		c, err := d.Dial(context.Background(), "dev")
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		c.Close()
	}
	if p.calls != 2 {
		t.Errorf("prompted %d times, want 2 (one wrong, one right, then cached)", p.calls)
	}
}

func TestNoPromptForKeyTheServerRejects(t *testing.T) {
	dir := t.TempDir()
	good, goodPriv := sshtest.NewKey(t)
	_, otherPriv := sshtest.NewKey(t)
	srv := sshtest.Start(t, good.PublicKey())
	enc, plain := filepath.Join(dir, "id_enc"), filepath.Join(dir, "id_plain")
	writeKey(t, enc, otherPriv, "unused")
	writeKey(t, plain, goodPriv, "")
	writeFile(t, filepath.Join(dir, "known_hosts"), srv.KnownHostsLine()+"\n")
	cfg := writeFile(t, filepath.Join(dir, "config"), hostBlock("dev", srv.Port, "")+commonBlock(dir, enc, plain))

	r, _ := NewResolver(cfg)
	p := &countingPrompt{}
	c, err := NewDialer(r, p.prompt, nil).Dial(context.Background(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if p.calls != 0 {
		t.Errorf("prompted %d times for a key the server would not accept", p.calls)
	}
}

func TestProxyJump(t *testing.T) {
	signer, priv := sshtest.NewKey(t)
	jump := sshtest.Start(t, signer.PublicKey())
	jump.AllowRealDial()
	target := sshtest.Start(t, signer.PublicKey())
	target.SetProc("hello from target\n")

	for _, form := range []string{"alias", "inline", "chain"} {
		t.Run(form, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "id")
			writeKey(t, keyPath, priv, "")
			writeFile(t, filepath.Join(dir, "known_hosts"), jump.KnownHostsLine()+"\n"+target.KnownHostsLine()+"\n")
			var pj string
			switch form {
			case "alias":
				pj = "jump"
			case "inline":
				pj = fmt.Sprintf("tester@127.0.0.1:%d", jump.Port)
			case "chain": // jump -> jump -> target
				pj = fmt.Sprintf("jump,tester@127.0.0.1:%d", jump.Port)
			}
			cfg := writeFile(t, filepath.Join(dir, "config"),
				hostBlock("target", target.Port, "  ProxyJump "+pj)+
					hostBlock("jump", jump.Port, "")+
					commonBlock(dir, keyPath))
			r, _ := NewResolver(cfg)
			c, err := NewDialer(r, nil, nil).Dial(context.Background(), "target")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			sess, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			out, err := sess.Output(sshtest.ProcCommand)
			if err != nil || string(out) != "hello from target\n" {
				t.Fatalf("output %q, %v", out, err)
			}
			if !slices.Contains(jump.Dialed(), target.Addr) {
				t.Errorf("jump host never dialed %s: %v", target.Addr, jump.Dialed())
			}
		})
	}
}

func TestProxyJumpLoopIsRejected(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, filepath.Join(dir, "config"), "Host a\n  ProxyJump b\nHost b\n  ProxyJump a\n"+commonBlock(dir))
	r, _ := NewResolver(cfg)
	_, err := NewDialer(r, nil, nil).Dial(context.Background(), "a")
	var ce *ConfigError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("got %v", err)
	}
}
