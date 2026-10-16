// Package sshtest runs a small in-process SSH server for tests. It accepts
// one public key, answers `cat /proc/net/tcp /proc/net/tcp6` with fake
// contents, replies to keepalives and serves direct-tcpip to registered
// in-memory backends.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// ProcCommand is the command the discovery loop runs.
const ProcCommand = "cat /proc/net/tcp /proc/net/tcp6"

type Server struct {
	Addr    string // 127.0.0.1:port
	Port    int
	HostKey ssh.Signer

	t        testing.TB
	ln       net.Listener
	cfg      *ssh.ServerConfig
	mu       sync.Mutex
	proc     string
	backends map[string]func(net.Conn)
	realDial bool
	mute     bool // ignore keepalives
	conns    map[*ssh.ServerConn]struct{}
	dialed   []string
	logins   int
	wg       sync.WaitGroup
}

// NewKey returns a fresh ed25519 key pair.
func NewKey(t testing.TB) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, priv
}

// Start runs a server that authorizes the given public key for any user.
func Start(t testing.TB, authorized ssh.PublicKey) *Server {
	t.Helper()
	hostKey, _ := NewKey(t)
	s := &Server{
		HostKey:  hostKey,
		t:        t,
		backends: make(map[string]func(net.Conn)),
		conns:    make(map[*ssh.ServerConn]struct{}),
	}
	s.cfg = &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(authorized.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	s.cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	s.Addr = ln.Addr().String()
	s.Port = ln.Addr().(*net.TCPAddr).Port
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// SetProc sets what `cat /proc/net/tcp /proc/net/tcp6` prints.
func (s *Server) SetProc(data string) {
	s.mu.Lock()
	s.proc = data
	s.mu.Unlock()
}

// Handle registers an in-memory service for direct-tcpip to target ("127.0.0.1:3000").
func (s *Server) Handle(target string, h func(net.Conn)) {
	s.mu.Lock()
	s.backends[target] = h
	s.mu.Unlock()
}

// AllowRealDial makes direct-tcpip to unregistered targets dial for real,
// so the server can act as a ProxyJump host.
func (s *Server) AllowRealDial() {
	s.mu.Lock()
	s.realDial = true
	s.mu.Unlock()
}

// MuteKeepalives makes the server swallow global requests without replying,
// like a peer that vanished without closing the TCP connection.
func (s *Server) MuteKeepalives(mute bool) {
	s.mu.Lock()
	s.mute = mute
	s.mu.Unlock()
}

// Dialed returns the direct-tcpip targets requested so far.
func (s *Server) Dialed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.dialed...)
}

// Logins counts successful handshakes.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// KillConnections drops every client connection abruptly.
func (s *Server) KillConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		c.Close()
	}
}

func (s *Server) Close() {
	s.ln.Close()
	s.KillConnections()
	s.wg.Wait()
}

// KnownHostsLine is the known_hosts entry for this server.
func (s *Server) KnownHostsLine() string {
	return fmt.Sprintf("[127.0.0.1]:%d %s", s.Port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey()))))
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(nc)
		}()
	}
}

func (s *Server) handleConn(nc net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, s.cfg)
	if err != nil {
		nc.Close()
		return
	}
	s.mu.Lock()
	s.conns[conn] = struct{}{}
	s.logins++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	go func() {
		for r := range reqs {
			s.mu.Lock()
			mute := s.mute
			s.mu.Unlock()
			if !mute && r.WantReply {
				r.Reply(false, nil) // what OpenSSH answers to keepalive@openssh.com
			}
		}
	}()

	var wg sync.WaitGroup
	defer wg.Wait()
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			ch, chReqs, err := nch.Accept()
			if err != nil {
				continue
			}
			wg.Add(1)
			go func() { defer wg.Done(); s.session(ch, chReqs) }()
		case "direct-tcpip":
			wg.Add(1)
			go func() { defer wg.Done(); s.directTCPIP(nch) }()
		default:
			nch.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			r.Reply(false, nil)
			continue
		}
		var msg struct{ Command string }
		if err := ssh.Unmarshal(r.Payload, &msg); err != nil {
			r.Reply(false, nil)
			return
		}
		r.Reply(true, nil)
		status := uint32(0)
		if msg.Command == ProcCommand {
			s.mu.Lock()
			io.WriteString(ch, s.proc)
			s.mu.Unlock()
		} else {
			fmt.Fprintf(ch.Stderr(), "sshtest: unknown command %q\n", msg.Command)
			status = 127
		}
		ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
		return
	}
}

func (s *Server) directTCPIP(nch ssh.NewChannel) {
	var req struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nch.ExtraData(), &req); err != nil {
		nch.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}
	target := net.JoinHostPort(req.Host, fmt.Sprint(req.Port))
	s.mu.Lock()
	s.dialed = append(s.dialed, target)
	h := s.backends[target]
	realDial := s.realDial
	s.mu.Unlock()

	var backend net.Conn
	switch {
	case h != nil:
		a, b, err := tcpPair()
		if err != nil {
			nch.Reject(ssh.ConnectionFailed, err.Error())
			return
		}
		go h(b)
		backend = a
	case realDial:
		c, err := net.Dial("tcp", target)
		if err != nil {
			nch.Reject(ssh.ConnectionFailed, err.Error())
			return
		}
		backend = c
	default:
		nch.Reject(ssh.ConnectionFailed, "connect failed (Connection refused)")
		return
	}
	ch, reqs, err := nch.Accept()
	if err != nil {
		backend.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	done := make(chan struct{})
	go func() {
		io.Copy(ch, backend)
		ch.CloseWrite()
		close(done)
	}()
	io.Copy(backend, ch)
	if cw, ok := backend.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		backend.Close()
	}
	<-done
	ch.Close()
	backend.Close()
}

// WriteClientFiles writes a private key, an ssh_config and a known_hosts
// file into dir. hosts maps alias to a config body (indented lines).
func WriteClientFiles(t testing.TB, dir string, key ed25519.PrivateKey, knownHosts []string, hosts map[string]string) (configPath, keyPath string) {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "id_test")
	writeFile(t, keyPath, string(pemEncode(block.Type, block.Bytes)))
	khPath := filepath.Join(dir, "known_hosts")
	writeFile(t, khPath, strings.Join(knownHosts, "\n")+"\n")

	var b strings.Builder
	for alias, body := range hosts {
		fmt.Fprintf(&b, "Host %s\n%s\n", alias, body)
	}
	fmt.Fprintf(&b, "Host *\n  IdentityFile %s\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile %s\n  IdentityAgent none\n",
		filepath.ToSlash(keyPath), filepath.ToSlash(khPath), filepath.ToSlash(filepath.Join(dir, "none")))
	configPath = filepath.Join(dir, "config")
	writeFile(t, configPath, b.String())
	return configPath, keyPath
}

func writeFile(t testing.TB, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
