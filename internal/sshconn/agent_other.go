//go:build !windows

package sshconn

import (
	"errors"
	"net"
	"os"
	"time"
)

// dialAgent connects to ssh-agent at path (from IdentityAgent) or SSH_AUTH_SOCK.
func dialAgent(path string) (net.Conn, error) {
	if path == "" {
		path = os.Getenv("SSH_AUTH_SOCK")
	}
	if path == "" {
		return nil, errors.New("SSH_AUTH_SOCK is not set")
	}
	return net.DialTimeout("unix", path, 2*time.Second)
}
