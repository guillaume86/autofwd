# TODO

Deferred items, mostly from the pre-release reviews (October 2026). Nothing here blocks a release; fixed findings are not listed.

## Robustness

- **One unparsable `known_hosts` line is fatal for every host.** `knownhosts.New` rejects the whole file on the first bad line (unknown key type, malformed blob), which autofwd reports as a config error and stops. OpenSSH skips such lines with a warning. Fix idea: on the `knownhosts: file:line: …` error, drop that line from an in-memory copy, write it to a temp file and retry; log each dropped line at debug level.
- **`UserKnownHostsFile` / `GlobalKnownHostsFile` with quoted paths containing spaces** are split on whitespace. `~` covers the common case.
- **ProxyJump gaps vs OpenSSH:** no `%h`/`%n`/`%p`/`%r` token expansion inside `ProxyJump`; the `ssh://user@host:port` URI form is misparsed.
- **Hung ProxyJump link:** `Conn.Close` closes the outermost hop first, which unblocks the rest. Not covered by a test.
- **Big-endian remotes:** addresses would decode byte-swapped. Detect via `uname -m` once per connection, or keep it documented only (current state).

## UX

- **ssh muscle memory:** `-p`, `-l`, `-i`, `-J` are rejected as unknown flags. They map cleanly onto `Host` fields and are cheap to accept as sugar.
- **Agent-not-running on Windows is only visible with `-v`.** When the OpenSSH agent pipe fails and the first authentication attempt fails, print a platform-specific hint (`Start-Service ssh-agent`) at warning level.
- **Config file discoverability:** nothing says at startup whether a config file was found. A `-v` line `config: <path> (not found)` would do.
- **`--interval` too small via the config file** reports as `--interval must be at least 100ms` without naming the file.
- **Unknown-host-key error with ProxyJump** should say which hop.
- **Password and keyboard-interactive login.** Only public-key auth is supported.
- **Filter by owner.** The `uid` column of `/proc/net/tcp` is parsed out but unused. An option such as `--mine` would forward only ports owned by the SSH user, so system services are skipped.
- **Interactive mode:** pin/mute a port and per-port connection history are deferred to the daemon/TUI idea below. The status footer caps at nine rows.

## Tests

- `TestKeepaliveDetectsDeadPeer` searches the whole log for the timeout message; a spurious timeout before `MuteKeepalives(true)` on a slow CI box would satisfy it. Search only the suffix written after muting.
- Half-close is only tested local→remote. Add the remote→local direction: remote `CloseWrite`s, the client reads EOF, then still writes and the remote still receives.
- No in-repo test for the frozen-transport teardown path (a TCP proxy that stops delivering bytes without closing). The fix in `supervisor.serve`/`poll` was verified by a reviewer with such a test.
- `sshtest` writes the fake `/proc` output to the channel while holding its mutex; a stalled client would deadlock `KillConnections`/`Close` and hang a failing test instead of failing it.

## Daemon + TUI

Split autofwd into a long-running daemon and a TUI client that attaches to it:

- **Daemon:** keeps one supervisor per host running in the background and survives the terminal closing.
  - Exposes state and control over a local socket: a named pipe on Windows, a Unix socket elsewhere.
  - It could start at login. A Windows service is still a non-goal; a per-user startup entry is enough.
- **TUI:** connects to the daemon, in the style of k9s or the sshfwd TUI.
  - Shows each host's connection state.
  - Lists every forwarded port, with its remote target, the owning process and user if known, and live connection counts.
  - Lists ports skipped as busy or filtered, with the reason.
  - Toggles: pin a port so it stays forwarded, mute a port, add or remove hosts.
  - Opens a port in the browser (`http://localhost:<port>`).
  - Follows the event log (`+` / `-` / `!` lines).
- **No TUI attached:** the daemon behaves exactly like today's CLI (auto-forward everything the filters allow). The current `autofwd <host>` foreground mode stays.
- **Open questions:**
  - How the passphrase prompt works with no terminal: agent only, or ask through the attached TUI.
  - Whether the config file becomes the daemon's host list.

## Optional ideas

- Support `@cert-authority` host certificates and `CertificateFile` user certificates on disk.
- A relative `Include` in the system-wide `ssh_config` resolves against `~/.ssh/`; the parsing library has no public "system" mode.
