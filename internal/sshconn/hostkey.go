package sshconn

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyError means the server's key could not be verified. It is always
// fatal: autofwd never accepts an unknown or changed key.
type HostKeyError struct {
	Alias   string // what to tell the user to `ssh` to
	Host    string // name:port as looked up in known_hosts
	Key     ssh.PublicKey
	Changed bool
	Revoked bool
	Known   []knownhosts.KnownKey
}

func (e *HostKeyError) Error() string {
	fp := e.Key.Type() + " " + ssh.FingerprintSHA256(e.Key)
	switch {
	case e.Revoked:
		return fmt.Sprintf("host key for %s (%s) is marked @revoked in known_hosts; refusing to connect", e.Host, fp)
	case e.Changed:
		var where []string
		for _, k := range e.Known {
			where = append(where, fmt.Sprintf("%s:%d", k.Filename, k.Line))
		}
		return fmt.Sprintf("HOST KEY MISMATCH for %s: the server sent %s, which does not match known_hosts (%s). "+
			"This may be a man-in-the-middle attack, or the host was reinstalled. Check the fingerprint, "+
			"then run `ssh-keygen -R %s` and `ssh %s` to record the new key.",
			e.Host, fp, strings.Join(where, ", "), e.Host, e.Alias)
	default:
		return fmt.Sprintf("host %s is not in known_hosts (server key %s). "+
			"Run `ssh %s` once to verify and accept its key, then start autofwd again.", e.Host, fp, e.Alias)
	}
}

// hostKeyChecker builds the verification callback for h, plus the host key
// algorithms to offer: those already recorded for the host, so a server with
// several key types presents the one we can verify.
func hostKeyChecker(h Host, hostport string) (ssh.HostKeyCallback, []string, error) {
	var files []string
	for _, f := range h.KnownHostsFiles {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	var db ssh.HostKeyCallback
	if len(files) > 0 {
		var err error
		if db, err = knownhosts.New(files...); err != nil {
			return nil, nil, &ConfigError{fmt.Errorf("reading known_hosts: %w", err)}
		}
	} else {
		db = func(string, net.Addr, ssh.PublicKey) error { return &knownhosts.KeyError{} }
	}

	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := db(hostname, remote, key)
		if err == nil {
			return nil
		}
		hke := &HostKeyError{Alias: h.Alias, Host: knownhosts.Normalize(hostport), Key: key}
		var ke *knownhosts.KeyError
		var re *knownhosts.RevokedError
		switch {
		case errors.As(err, &ke):
			hke.Changed = len(ke.Want) > 0
			hke.Known = ke.Want
		case errors.As(err, &re):
			hke.Revoked = true
		default:
			return err
		}
		return hke
	}
	return cb, knownAlgorithms(db, hostport), nil
}

var probeKey = sync.OnceValue(func() ssh.PublicKey {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return k
})

// knownAlgorithms asks the known_hosts database which key types it holds for
// hostport by presenting a key it cannot know.
func knownAlgorithms(db ssh.HostKeyCallback, hostport string) []string {
	var ke *knownhosts.KeyError
	if err := db(hostport, &net.TCPAddr{IP: net.IPv4zero}, probeKey()); !errors.As(err, &ke) {
		return nil
	}
	var algos []string
	add := func(a ...string) {
		for _, x := range a {
			if !slices.Contains(algos, x) {
				algos = append(algos, x)
			}
		}
	}
	for _, k := range ke.Want {
		switch t := k.Key.Type(); t {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		default:
			add(t)
		}
	}
	if len(algos) == 0 {
		return nil
	}
	// Known types first, then everything else, as OpenSSH does. Without the
	// rest, a server that no longer has the recorded key type would fail key
	// exchange with an algorithm error instead of a clear host-key mismatch.
	add(ssh.SupportedAlgorithms().HostKeys...)
	return algos
}
