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
after that bare `mach` prints the fleet status table — same as `mach list`.
Explicit subcommands:

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

### Features (post-limitations, v0.3)

- **E2E encryption**: exec commands and results are sealed with X25519 +
  ChaCha20-Poly1305 between console and agent; the control plane relays
  ciphertext and audits a `[E2E sealed command]` placeholder (metadata
  only: machine, timestamp, source key, exit code). Agents register an
  X25519 public key at enrollment; consoles fetch it per target. Machines
  enrolled before this feature re-enroll (or re-register) to get a key —
  plaintext exec is the automatic fallback for keyless machines.
- **Confinement**: every remote command runs in its own process group
  (unix) and is SIGKILL-killed as a tree on timeout — detached
  grandchildren no longer outlive commands. (Windows: timeout + output
  caps only.)
- **Streaming console**: `mach console` runs each command over the
  streaming endpoint — output arrives live (32 KiB chunks) instead of
  buffered-at-end; Ctrl-C kills the remote session. Falls back to
  buffered exec automatically.
- **Postgres backing (optional)**: `MACH_DB=postgres://…` swaps SQLite
  for Postgres (same schema), removing the single-writer constraint for
  larger fleets. SQLite stays the default (WAL + capped connections).

### Known limitations (pre-1.0, honest list)

- The policy layer (`deny:`/`allowonly`) is a foot-guard, not a sandbox —
  OS confinement (pgroup/rlimit) bounds damage but no seccomp/Seatbelt
  profile exists yet.
- `mach console` streams output but is not a kernel PTY: no echo/line
  discipline; full-screen TUI apps (vim, htop) still need a real PTY.
- No signed release manifests for the agent binaries shipped in the
  container image (updates pushed at runtime ARE signature-verified).

## Build

Any host with Docker (no Go needed): `docker compose build` builds the
control plane plus all cross-targets. Local dev with a Go toolchain:
`go build ./cmd/mach`.