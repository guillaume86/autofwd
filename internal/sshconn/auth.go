package sshconn

import (
	"cmp"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/guillaume86/autofwd/internal/logx"
)

// AuthError means the server rejected every credential we had.
type AuthError struct {
	Host string
	Err  error
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("authentication to %s failed: %v (is your key loaded in ssh-agent or listed as IdentityFile?)", e.Host, e.Err)
}
func (e *AuthError) Unwrap() error { return e.Err }

// PromptFunc asks the user for a secret. TerminalPrompt is the default.
type PromptFunc func(prompt string) ([]byte, error)

var promptMu sync.Mutex

// TerminalPrompt reads a passphrase from the console without echo.
func TerminalPrompt(prompt string) ([]byte, error) {
	promptMu.Lock()
	defer promptMu.Unlock()
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("stdin is not a terminal, cannot ask for a passphrase (load the key into ssh-agent instead)")
	}
	fmt.Fprint(os.Stderr, prompt)
	defer fmt.Fprintln(os.Stderr)
	return term.ReadPassword(fd)
}

// keyFile is a private key whose public half is known up front and whose
// private half is decrypted only when the server has accepted the public
// key. Decrypted keys stay in memory so reconnecting never re-prompts.
type keyFile struct {
	path string
	pub  ssh.PublicKey
	pem  []byte

	mu     sync.Mutex
	signer ssh.Signer
	err    error // sticky failure: wrong passphrase three times, or skipped
}

// keyRing caches key files across connection attempts.
type keyRing struct {
	mu     sync.Mutex
	keys   map[string]*keyFile
	prompt PromptFunc
	log    *logx.Logger
}

// load returns the key at path, or nil when it is absent or unusable.
func (r *keyRing) load(path string) *keyFile {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keys[path]; ok {
		return k
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			r.log.Debugf("  key %s: %v", path, err)
		}
		return nil
	}
	k := &keyFile{path: path, pem: pem}
	signer, err := ssh.ParsePrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		k.signer, k.pub = signer, signer.PublicKey()
	case errors.As(err, &missing):
		k.pub = missing.PublicKey
		if k.pub == nil {
			k.pub = readPublicKey(path + ".pub")
		}
		// Legacy encrypted PEM keys without a .pub file must be decrypted
		// before we even know which key they are.
	default:
		r.log.Debugf("  key %s: %v", path, err)
		return nil
	}
	r.keys[path] = k
	return k
}

func readPublicKey(path string) ssh.PublicKey {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil
	}
	return pub
}

// ready reports whether k can sign without a prompt.
func (k *keyFile) ready() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.signer != nil {
		return 1
	}
	return 0
}

// failed reports whether an earlier prompt for k was skipped or failed.
func (k *keyFile) failed() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.err != nil
}

// unlock decrypts k, prompting up to three times. pause runs around the
// prompts so the caller can suspend its handshake timeout meanwhile.
func (k *keyFile) unlock(prompt PromptFunc, pause func() (resume func())) (ssh.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.signer != nil || k.err != nil {
		return k.signer, k.err
	}
	if pause != nil {
		defer pause()()
	}
	for range 3 {
		pass, err := prompt(fmt.Sprintf("Enter passphrase for %s: ", k.path))
		if err != nil {
			k.err = err
			return nil, err
		}
		if len(pass) == 0 {
			k.err = errors.New("passphrase entry skipped")
			return nil, k.err
		}
		s, err := ssh.ParsePrivateKeyWithPassphrase(k.pem, pass)
		if errors.Is(err, x509.IncorrectPasswordError) {
			continue
		}
		if err != nil {
			k.err = err
			return nil, err
		}
		k.signer, k.pub = s, s.PublicKey()
		k.pem = nil
		return s, nil
	}
	k.err = errors.New("too many incorrect passphrases")
	return nil, k.err
}

// PassphraseError means a key the server accepted could not be decrypted:
// the prompt was skipped, failed three times, or could not be shown. The
// key is not offered again this run.
type PassphraseError struct {
	Path string
	Err  error
}

func (e *PassphraseError) Error() string { return e.Path + ": " + e.Err.Error() }
func (e *PassphraseError) Unwrap() error { return e.Err }

// lazySigner presents a keyFile to x/crypto/ssh, which queries the server
// with the public key before asking for a signature.
type lazySigner struct {
	k      *keyFile
	prompt PromptFunc
	pause  func() (resume func())
}

func (s *lazySigner) PublicKey() ssh.PublicKey { return s.k.pub }

func (s *lazySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	inner, err := s.k.unlock(s.prompt, s.pause)
	if err != nil {
		return nil, &PassphraseError{Path: s.k.path, Err: err}
	}
	return inner.Sign(rand, data)
}

func (s *lazySigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	inner, err := s.k.unlock(s.prompt, s.pause)
	if err != nil {
		return nil, &PassphraseError{Path: s.k.path, Err: err}
	}
	if as, ok := inner.(ssh.AlgorithmSigner); ok {
		return as.SignWithAlgorithm(rand, data, algorithm)
	}
	if algorithm != "" && algorithm != inner.PublicKey().Type() {
		return nil, fmt.Errorf("%s: cannot sign with %s", s.k.path, algorithm)
	}
	return inner.Sign(rand, data)
}

// signers assembles the public keys to offer, agent first, then key files.
// x/crypto/ssh tries only one AuthMethod per method name, so everything must
// go through a single publickey callback. The returned closer releases the
// agent connection once the handshake is over.
func (r *keyRing) signers(h Host, pause func() (resume func())) (func() ([]ssh.Signer, error), io.Closer) {
	var agentConn net.Conn
	closer := closerFunc(func() error {
		if agentConn != nil {
			return agentConn.Close()
		}
		return nil
	})

	cb := func() ([]ssh.Signer, error) {
		var files []*keyFile
		for _, p := range h.IdentityFiles {
			if k := r.load(p); k != nil {
				files = append(files, k)
			}
		}
		wanted := make(map[string]bool) // IdentitiesOnly allowlist
		for _, k := range files {
			if k.pub != nil {
				wanted[string(k.pub.Marshal())] = true
			}
		}

		var out []ssh.Signer
		offered := make(map[string]bool)
		if h.IdentityAgent != "none" {
			conn, err := dialAgent(h.IdentityAgent)
			if err != nil {
				r.log.Debugf("  ssh-agent unavailable: %v", err)
			} else {
				if agentConn != nil {
					agentConn.Close() // the callback ran again (partial success)
				}
				agentConn = conn
				agentSigners, err := agent.NewClient(conn).Signers()
				if err != nil {
					r.log.Debugf("  ssh-agent: %v", err)
				}
				for _, s := range agentSigners {
					key := string(s.PublicKey().Marshal())
					if h.IdentitiesOnly && !wanted[key] {
						continue
					}
					offered[key] = true
					out = append(out, s)
				}
				r.log.Debugf("  ssh-agent offers %d key(s)", len(out))
			}
		}

		// Keys that are already usable go first, so a passphrase prompt
		// that gets skipped cannot shadow a key that would have worked.
		slices.SortStableFunc(files, func(a, b *keyFile) int {
			return cmp.Compare(b.ready(), a.ready())
		})
		for _, k := range files {
			if k.failed() {
				r.log.Debugf("  key %s: not offered again after an earlier passphrase failure", k.path)
				continue
			}
			if k.pub == nil {
				if _, err := k.unlock(r.prompt, pause); err != nil {
					r.log.Debugf("  key %s: %v", k.path, err)
					continue
				}
			}
			key := string(k.pub.Marshal())
			if offered[key] {
				continue
			}
			offered[key] = true
			out = append(out, &lazySigner{k: k, prompt: r.prompt, pause: pause})
		}
		return out, nil
	}
	return cb, closer
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
