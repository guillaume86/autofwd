# autofwd

`autofwd` forwards remote ports automatically over SSH, the way VS Code Remote-SSH's "auto forwarded ports" does, but without VS Code.

When a process on a remote Linux box starts listening on a TCP port, `autofwd` opens the same port on your machine's `localhost`. When the process stops listening, the local port closes again. It uses a single SSH connection, ships as a single static binary, and needs nothing installed on the remote side.

```
> autofwd devbox
12:01:07 connected to devbox
12:01:07 press s for status, ? for keys
12:01:07 + 3000  http://localhost:3000
12:01:07 + 5173  http://localhost:5173  (remote ::1)
12:03:44 + 8080  http://localhost:8080
12:03:51 ! 9229 local port busy: another local process listens on it (retry in 30s)
12:05:10 - 8080
12:20:02 - 3000 5173
12:20:02 disconnected from devbox: no keepalive reply within 15s (reconnect in 1s)
12:20:05 connected to devbox (down 3s)
12:20:05 + 3000  http://localhost:3000
12:20:05 + 5173  http://localhost:5173  (remote ::1)
```

On a terminal, the markers are colored and a few keys work while it runs: `s` toggles a status footer (connection state, every forwarded port with its URL, age and open connections, busy and skipped ports), `o` opens the newest port in your browser, `1`–`9` open a row of the status list, `v` toggles verbose logging, `r` polls right now and retries busy ports, `q` quits. When output is piped, or with `--log`, it is a plain log with no colors or keys.

Services are reached at `http://localhost:<port>`, on the same port number as on the remote host. That matters for two reasons:

- Browsers treat `localhost` as a secure context, which `Secure` and `__Host-` cookies depend on.
- OAuth callback URLs only work when the port numbers match.

### Why not plain `ssh -L`?

- Windows' built-in OpenSSH has no `ControlMaster`, so you can't add forwards to a running `ssh` session from the command line.
- Exposing ports through Tailscale (or similar) puts them on a non-localhost name, which loses the secure-context behavior.

## Install

**Prebuilt binaries:** download the archive for your platform from the [Releases page](https://github.com/guillaume86/autofwd/releases) (Windows x64/arm64, Linux x64/arm64, macOS Intel/Apple Silicon), unpack it and put `autofwd` somewhere on your `PATH`. `checksums.txt` on the same page lists the SHA-256 of each archive.

**With Go** (1.26 or later, which the `golang.org/x` dependencies require):

```sh
go install github.com/guillaume86/autofwd/cmd/autofwd@latest
```

**From a checkout.** The result is a static binary with no cgo:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o autofwd ./cmd/autofwd
```

To cross-compile, set `GOOS`/`GOARCH` (for example `GOOS=windows GOARCH=arm64`), or build every release target at once with [GoReleaser](https://goreleaser.com/install/) (`goreleaser release --snapshot --clean`); the archives land in `dist/`.

### Remote host requirements

- Linux with `/proc` mounted (any distribution; no packages needed, not even `ss` or iproute2).
- A little-endian CPU: x86-64, arm64, riscv64. See [Known limitations](#known-limitations).
- Public-key login. Password and keyboard-interactive authentication aren't supported.
- `sshd` must allow running commands and local forwarding: no `ForceCommand` for your user, and `AllowTcpForwarding` set to `yes` or `local` (the default is `yes`).
- Only the network namespace of your SSH session is visible. Ports inside containers are detected only if they are published to the host.

## Usage

```
autofwd [flags] [user@]<host>
```

`<host>` is looked up in `~/.ssh/config`, just as `ssh <host>` would. Flags can go before or after the host. Both `-flag` and `--flag` work.

| Flag | Default | Meaning |
|---|---|---|
| `--interval` | `2s` | How often to read the remote port table. Seconds (`5`) or a duration (`500ms`). |
| `--min-port` | `1024` | Ignore remote ports below this. |
| `--ignore` | | Ports never to forward, for example `5432,6379,40000-50000`. |
| `--only` | | Allowlist. When set, it replaces `--min-port` and `--ignore`. |
| `-q`, `--quiet` | | Log only warnings (`!` lines) and connection state (`connected`/`disconnected`). |
| `-v`, `--verbose` | | Also log each proxied connection, keepalives and diagnostics. |
| `--log` | | Plain log: no colors, keys or status footer. Automatic when stderr or stdin is not a terminal. |
| `--config` | see below | Path to the config file. |
| `--version` | | Print the version. |

Press Ctrl+C to close every listener and the SSH connection, then exit. A second Ctrl+C kills the process immediately.

### Log lines

| Line | Meaning |
|---|---|
| `+ 3000  http://localhost:3000` | The port is now forwarded; the URL is what to open. `(remote ::1)` or `(remote 10.0.0.5)` is added when the remote side is dialed somewhere other than `127.0.0.1`. |
| `- 3000` | The forward was removed. Connections already open on it finish normally. On a disconnect, one line lists every port: `- 3000 5173`. |
| `~ 3000  remote listener moved to [::1]:3000` | The remote listener changed address; the local listener stays. |
| `! 8080 local port busy: reason (retry in 30s)` | Something on your machine already uses that port, so it is skipped. See [Busy ports](#busy-ports). |
| `! 3000 dial 127.0.0.1:3000: connection refused` | A proxied connection was refused on the remote side. Reported at most every 10s per port. |
| `! connect to … failed: … (retry in 2s)` | Connection attempt failed. Identical repeats are collapsed into `! still cannot connect to …`. |
| `connected to …` / `disconnected from …: reason` | Connection state. A reconnect says how long the connection was down. |

The exit status is 0 after Ctrl+C, 1 on a fatal error (see [Reconnects](#reconnects)) and 2 for a usage error.

## Config file

The config file is optional. It lives at:

- Windows: `%APPDATA%\autofwd\config.toml`
- Elsewhere, macOS included: `$XDG_CONFIG_HOME/autofwd/config.toml`, falling back to `~/.config/autofwd/config.toml`

Values at the top level apply to every host. A `[hosts.<name>]` table overrides them for one host. `<name>` is the host exactly as you type it on the command line, without any `user@`. Flags given on the command line override both.

```toml
interval = "2s"
min_port = 1024
ignore   = "5432,6379"

[hosts.devbox]
ignore = [5432, 6379, "40000-50000"]   # string or array, either works

[hosts."db.example.com"]
only = "5432"
quiet = true
```

The keys are `interval` (a string like `"500ms"`, or a number of seconds), `min_port`, `ignore`, `only`, `quiet` and `verbose`. An unknown key is an error, so typos don't go unnoticed.

## How it works

### Discovery

Every `--interval`, autofwd opens a session on the existing connection and runs `cat /proc/net/tcp /proc/net/tcp6`. This needs neither `ss` nor iproute2 on the remote host. autofwd parses the tables itself:

- Only rows in state `0A` (LISTEN) count.
- Addresses are hex, little-endian within each 32-bit word.
- IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are treated as IPv4.

If IPv6 is disabled on the remote host, `/proc/net/tcp6` is missing and `cat` exits non-zero. autofwd still uses the IPv4 table.

Each listening socket determines the address autofwd dials on the remote side:

| Remote listener | Dialed as |
|---|---|
| `0.0.0.0`, `::`, anything in `127.0.0.0/8` | `127.0.0.1` |
| `::1` | `::1`, but only if no IPv4 socket listens on that port |
| any other specific address | that address |
| link-local `fe80::` | not forwarded: the kernel table doesn't record the interface, so the address can't be dialed |

### Forwarding

Each forwarded port is bound on both `127.0.0.1` and `[::1]`, because Windows browsers may resolve `localhost` to either. If your machine has no IPv6 loopback, autofwd uses IPv4 only. It never binds a non-loopback address.

Each accepted connection becomes a `direct-tcpip` channel on the shared SSH connection, the same mechanism as `ssh -L`. Data is copied in both directions, and a half-close (EOF in one direction) is passed through instead of tearing down the whole connection.

When a remote port disappears, its local listeners close immediately, but connections already open on it continue. When the SSH connection drops, everything is closed.

### Busy ports

If a local port is already taken, autofwd logs it once and skips it. It never remaps to another port, because then the port numbers in URLs would no longer match.

It tries again when the remote port disappears and comes back, or after 30 seconds otherwise.

Before binding, autofwd also connects to the port on loopback to see whether something already answers. Windows, and BSD/macOS with `SO_REUSEADDR`, let a loopback bind succeed even while another process listens on `0.0.0.0` for the same port. Without this check, autofwd would silently take over your local dev server's port.

### Reconnects

autofwd sends a `keepalive@openssh.com` request every 30 seconds. If no reply arrives within 15 seconds, it treats the connection as dead. This catches connections that hang without closing, which is common after a laptop sleeps or changes networks.

On any disconnect, autofwd removes every local forward and reconnects with exponential backoff: 1s, 2s, 4s and so on, capped at 30s. The backoff starts over at 1s once a connection has stayed up for more than 30s. Decrypted keys are kept in memory, so a reconnect never asks for a passphrase again.

Discovery failures count too: if reading the port table fails three polls in a row (for example, the remote isn't Linux and has no `/proc/net/tcp`), the connection is dropped and re-established. Network errors never stop autofwd. A mistyped host name, a host that is down, or a VPN that isn't up yet all show as `! connect to … failed … (retry in Ns)` lines until the host becomes reachable or you press Ctrl+C.

Timeouts, for reference: TCP connect plus SSH handshake 30s per hop (`ConnectTimeout` in `ssh_config` overrides it; time spent typing a passphrase doesn't count), reading the remote port table 15s, dialing a remote port for a proxied connection 15s, reaching the agent 2s.

Some errors are fatal, because retrying can't fix them:

- An unknown, changed or revoked host key.
- An invalid `ssh_config`.
- An authentication failure on the very first attempt. After a successful connection, authentication failures are retried, in case the agent is briefly unavailable.

## SSH configuration

### `~/.ssh/config`

autofwd reads `~/.ssh/config` and the system-wide file (`/etc/ssh/ssh_config`, or `%ProgramData%\ssh\ssh_config` on Windows). As in ssh, the first value found wins.

It honors these options:

- `HostName`, `User`, `Port`
- `IdentityFile` (several allowed), `IdentitiesOnly`, `IdentityAgent`
- `UserKnownHostsFile`, `GlobalKnownHostsFile`, `HostKeyAlias`
- `ProxyJump`, `ConnectTimeout`
- `Include`, `Host` patterns, and `Match host` / `Match all`

The tokens `~`, `%d`, `%h`, `%n`, `%p`, `%r`, `%u` and `%%` are expanded. When no `IdentityFile` is configured, autofwd tries `~/.ssh/id_ed25519`, `id_ecdsa` and `id_rsa`.

**ProxyJump is supported.** That includes a single hop (`ProxyJump bastion`), inline hops (`user@host:port`) and chains (`a,b`). The first hop follows its own config, including its own `ProxyJump`. All hops run inside autofwd, with no `ssh` subprocess. Each hop's host key is checked against known_hosts.

### Authentication

autofwd offers credentials in the same order as ssh:

1. **ssh-agent.**
   - Windows: autofwd uses the OpenSSH agent service's named pipe, `\\.\pipe\openssh-ssh-agent`. The service is disabled by default. Enable it once from an elevated PowerShell, then add your key:

     ```powershell
     Get-Service ssh-agent | Set-Service -StartupType Automatic
     Start-Service ssh-agent
     ssh-add $env:USERPROFILE\.ssh\id_ed25519
     ```

     If `SSH_AUTH_SOCK` is set, autofwd tries it first. It can be a named pipe such as `\\.\pipe\...` (used by 1Password or KeePassXC) or a real AF_UNIX socket. If that fails, autofwd falls back to the OpenSSH pipe. This matters in Git Bash, which often exports an MSYS `ssh-agent` socket that native programs can't open; the fallback makes the OpenSSH agent work there anyway.
   - Linux and macOS: `SSH_AUTH_SOCK`.
   - On every platform, `IdentityAgent` overrides this, and `IdentityAgent none` disables the agent.
2. **Key files.**
   - A key with a passphrase is decrypted only after the server has accepted its public key, so you are never asked for a passphrase for a key the server would reject. The one exception is a legacy PEM-encrypted key with no `.pub` file next to it: its public half isn't known until it is decrypted, so it is prompted for up front.
   - The prompt appears on the terminal. An empty answer skips the key; three wrong passphrases drop it. Either way the key is not offered again for the rest of the run.
   - Each key is decrypted at most once per run.
   - If stdin isn't a terminal, encrypted keys are skipped. Use the agent in that case.

### Host keys

Host keys are checked against `~/.ssh/known_hosts` (plus `known_hosts2` and the global file). Hashed entries and non-standard ports (`[host]:2222`) work.

autofwd asks the server for the key types already recorded for that host. That way, a server with several host keys presents one that autofwd can verify.

autofwd never accepts an unknown or changed key:

- **Unknown key:** autofwd stops with an error telling you to run `ssh <host>` once, check the fingerprint and accept it.
- **Changed key:** autofwd stops with a mismatch error that names the known_hosts line. Check the new fingerprint, then remove the old entry with `ssh-keygen -R`.

`StrictHostKeyChecking` is ignored; checking is always strict.

## Known limitations

- **ProxyCommand** isn't supported. A host that uses it fails with a clear error. Use `ProxyJump` where you can.
- **`Match exec` and other `Match` criteria** (`user`, `localuser`, `canonical`, …) make `ssh_config` parsing fail. autofwd reports the error instead of silently ignoring a config it can't read.
- **Remote host must be Linux** (it needs `/proc/net/tcp`). The remote CPU must be little-endian, which covers x86-64, arm64 and riscv64. On big-endian hosts such as s390x, addresses would be decoded byte-swapped.
- **Each poll runs `cat` through your login shell.** Startup files such as `.bashrc` therefore run every couple of seconds. Output they print is tolerated (rows that don't parse are skipped), but slow startup files slow down discovery.
- **Detection latency** is up to one `--interval`. Only TCP is forwarded.
- **A link-local IPv6 listener** (`fe80::…`) is never forwarded, because the kernel table doesn't record its interface. **A listener bound only to `::` with `IPV6_V6ONLY`** is dialed as `127.0.0.1` and refuses the connection. Bind such a service to `::1` explicitly.
- **Ports below 1024** aren't forwarded by default. If you allow them with `--only`, Linux and macOS need privileges to bind them locally.
- **On Windows, ports inside an excluded range** reserved by Hyper-V, WSL or Docker (`netsh int ipv4 show excludedportrange protocol=tcp`) are reported as busy.
- **Only public-key authentication.** Password and keyboard-interactive logins aren't supported.
- **Host certificates (`@cert-authority`), user certificates on disk (`CertificateFile`, `id_*-cert.pub`), FIDO/`-sk` key files and PKCS#11** aren't supported directly. Certificates and `-sk` keys work if they are loaded in the agent.
- **A relative `Include` in the system-wide `ssh_config`** is resolved against `~/.ssh/` rather than `/etc/ssh/`. Absolute paths, which is what distributions ship, are fine.
- **No GUI, tray icon, Windows service, UDP, reverse forwards or port remapping.** These are deliberate non-goals.

## Development

```sh
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go test ./...
CGO_ENABLED=1 go test -race ./...    # the race detector needs a C toolchain
```

| Package | Role |
|---|---|
| `cmd/autofwd` | Flags, config-file merging, signal handling. |
| `internal/procnet` | `/proc/net/tcp{,6}` parser. Fixtures are in `testdata/`. |
| `internal/ports` | Port lists, filtering, choosing the remote dial address. |
| `internal/forward` | Local listeners, the busy-port policy, the two-way copy with half-close. |
| `internal/sshconn` | `ssh_config`, agent and key-file auth, known_hosts, ProxyJump. |
| `internal/supervisor` | Connection lifecycle: discovery loop, keepalive, reconnect with backoff. |
| `internal/sshtest` | In-process SSH server for tests: fake `/proc`, `direct-tcpip`, keepalive control. |
| `internal/config` | The optional TOML config file and its per-host precedence. |
| `internal/ui` | Terminal layer: colored log sink with the status footer, raw-mode keys, passphrase prompt, open-in-browser. |
| `internal/logx` | One-line-per-event leveled logger. |

The integration tests in `internal/supervisor` and `internal/sshconn` start a real SSH server in the test process. They exercise the actual client code end to end: config resolution, host-key verification, auth, discovery, forwarding, half-close, busy ports, keepalive timeout, reconnect and ProxyJump chains.

### Dependencies

| Module | Why |
|---|---|
| `golang.org/x/crypto` | SSH client, agent protocol, known_hosts. |
| `golang.org/x/term` | Passphrase prompt without echo, on the Windows console and POSIX terminals. |
| `golang.org/x/sys` | The Windows `WSAEADDRINUSE`/`WSAEACCES` constants and console mode calls. Already pulled in by `x/term` and go-winio. |
| `github.com/kevinburke/ssh_config` | `ssh_config` parsing with ssh's matching rules, including `Include`. |
| `github.com/Microsoft/go-winio` | Named-pipe client for the Windows OpenSSH agent. The standard library can't dial named pipes. |
| `github.com/BurntSushi/toml` | Config file parsing. It has no dependencies of its own. |

There are no test-only dependencies. The test SSH server is a few hundred lines on top of `x/crypto/ssh`, rather than pulling in `gliderlabs/ssh`, and it can do things that library makes awkward, such as ignoring keepalives or dropping connections on demand.
