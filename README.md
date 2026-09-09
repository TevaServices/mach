# mach

One binary, any OS, zero inbound ports. `mach` gives you remote CLI access
to registered machines — quick interactive troubleshooting plus long-running
named access — where **every target only ever makes outbound connections**;
the control plane is the only publicly reachable component.

```
┌──────────┐  outbound   ┌───────────────┐  outbound   ┌──────────┐
│   mach   │◄──WebSocket──│ control plane │◄──WebSocket──│   mach   │   targets (no open ports)
│ (target) │              │    (Docker)   │              │ (target) │
└──────────┘              └───────▲───────┘              └──────────┘
                                  │ HTTPS (REST + pair pages)
                          ┌───────┴───────┐
                          │  mach CLI     │   you / the LLM troubleshooter
                          └───────────────┘
```

## One command, that's it

**On a machine you want wired in** (Linux, macOS, or Windows): run

```
mach
```

with no arguments. If it isn't enrolled yet, it prints the QR → you scan,
compare the challenge code, approve, name it — and then holds the live
connection right there in that console (Ctrl-C to stop). To make it
permanent (auto-start at boot, reconnect after network loss), run once:

```
mach install
```

That registers the OS service: systemd (linux), launchd (macOS), or Task
Scheduler (Windows).

**On your admin machine** (or the LLM troubleshooter's box): run

```
mach
```

with no arguments. First run asks for the control plane URL + API key (once);
after that it shows the live fleet status. Explicit subcommands:

| Command | Purpose |
|---|---|
| `mach list` | enrolled machines + online state |
| `mach exec <m> <cmd...>` | run remotely; local exit code = remote exit code |
| `mach exec <m> -- <argv>` | **no-shell mode**: args pass through byte-exact (no quoting issues) |
| `mach console <m>` | interactive line-based remote shell (`:!` runs locally) |
| `mach audit [m] [n]` | recent command audit log |

Advanced/server flags still exist for automation (`mach register --api-key K
--name N`, `mach serve`, `mach add-api-key`), but nothing *requires* them.

## Cross-platform behavior

- **Shells (per-OS default with fallbacks):** linux `bash → sh`; macOS
  `bash → zsh → sh`; Windows `PowerShell → pwsh → cmd`. Shell-mode commands
  get exactly one parse by the chosen shell; argv (`--`) mode parses zero.
- **Service install:** systemd (linux), launchd (macOS, KeepAlive + RunAtLoad),
  Task Scheduler (Windows, ONLOGON + restart).
- **State dir:** `$MACH_STATE_DIR`, else `/var/lib/mach` (root on linux),
  `~/.mach` (user), `%APPDATA%\mach`-equivalent user dir on Windows.
- **Binaries:** static, CGO-free; linux/macOS/Windows × amd64/arm64.

## Enrollment

**QR (interactive):** `mach` on the new machine prints a QR whose URL points
at the **control plane** (the phone never needs to reach the agent), plus a
challenge code *not* embedded in the QR. Scan, compare codes, approve, name
the machine — the agent finishes enrollment over its own outbound connection.

**API key (headless):** `mach register --server https://… --api-key KEY --name web-01`.
Create keys with `mach add-api-key <name> <key>` (runs where the DB is).

## Running the control plane (Docker)

```bash
MACH_PUBLIC_URL=https://mach.example.com docker compose up -d --build
# create a console/agent API key
MACH_PUBLIC_URL=... docker compose run --rm mach add-api-key hermes-console "$KEY"
```

The image also ships prebuilt agent binaries for all six OS/arch targets
(`/opt/mach-agents/`) — copy one to a target machine; it never needs Go.
State lives in `./data/mach.db` (SQLite: machines, keys, pairings, full
command audit log). Put Caddy/nginx in front for TLS (agents speak wss://).

## Security posture (v1)

- Agents hold only their own Ed25519 identity (no shared master secret);
  hellos are signed with a ±5-minute replay window.
- Pairing tokens are single-use, ~10-minute TTL; pair-start is rate-limited
  and grants nothing until phone approval + challenge-code match.
- Every command is audit-logged (machine, timestamp, command/argv, source
  key, exit code, output snippets) in the control plane's SQLite.
- Control plane binds to loopback by default; expose only via your TLS proxy.

### Known limitations (pre-1.0, honest list)

- No application-layer E2E encryption yet: the control plane can read
  command content (TLS protects the wire). Obvious v1.1 item.
- No per-machine command allow/deny policies yet.
- `mach console` is line-based, not a PTY (no TUI apps / streaming).
- SQLite = single-writer; fine for a household fleet, not a datacenter.

## Build

Any host with Docker (no Go needed): `docker compose build` builds the
control plane plus all cross-targets. Local dev with a Go toolchain:
`go build ./cmd/mach`.