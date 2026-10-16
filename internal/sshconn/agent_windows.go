package sshconn

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// defaultAgentPipe is where the Windows OpenSSH agent service listens.
const defaultAgentPipe = `\\.\pipe\openssh-ssh-agent`

// dialAgent connects to ssh-agent. An explicit path comes from IdentityAgent.
// Otherwise SSH_AUTH_SOCK is tried (a named pipe or AF_UNIX socket, as some
// third-party agents use) and then the OpenSSH service pipe. The fallback
// matters because Git Bash often exports an MSYS pseudo-socket in
// SSH_AUTH_SOCK that native programs cannot open.
func dialAgent(path string) (net.Conn, error) {
	if path != "" {
		return dialAgentPath(path)
	}
	if env := os.Getenv("SSH_AUTH_SOCK"); env != "" {
		c, err := dialAgentPath(env)
		if err == nil {
			return c, nil
		}
		c, err2 := dialAgentPath(defaultAgentPipe)
		if err2 != nil {
			return nil, fmt.Errorf("SSH_AUTH_SOCK=%s: %v; %s: %v", env, err, defaultAgentPipe, err2)
		}
		return c, nil
	}
	return dialAgentPath(defaultAgentPipe)
}

func dialAgentPath(path string) (net.Conn, error) {
	if strings.HasPrefix(path, `\\.\pipe\`) || strings.HasPrefix(path, `//./pipe/`) {
		timeout := 2 * time.Second
		return winio.DialPipe(path, &timeout)
	}
	return net.DialTimeout("unix", path, 2*time.Second)
}
