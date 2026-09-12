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
| `mach exec <m> <cmd...>` | run remotely, streaming output as it is produced; local exit code = remote exit code |
| `mach exec <m> -- <argv>` | **no-shell mode**: args pass through byte-exact (no quoting issues) |
| `mach exec --json <m> <cmd...>` | emit the stream as labeled NDJSON frames — for programs (output is data, exit status is a field) |
| `mach console <m>` | interactive line-based remote shell (`:!` runs locally) |
| `mach audit [m] [n]` | recent command audit log |

A machine's output goes to stdout verbatim; mach's own messages go to stderr
with a `mach: ` prefix, so a script never has to guess which is which.

Advanced flags still exist for automation (`mach register --api-key K --name N`,
`mach install`, `mach run`), but nothing *requires* them. Everything on the
control plane — API keys, revocation, update pushes, release attestations —
lives in the separate `mach-server` binary, which is what runs in the container.

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
Keys are created on the control plane (`mach-server add-api-key <name> <scopes>`);
the secret is generated server-side and printed once.

## Running the control plane (Docker)

```bash
MACH_PUBLIC_URL=https://mach.example.com docker compose up -d --build
# create a console/agent API key (scopes: enroll | readonly | exec:* | exec:m1|m2)
docker compose exec mach-server mach-server add-api-key hermes-console 'exec:*'
# optional: a fleet-wide command block list, applied to every key and machine
# (also settable as MACH_EXEC_POLICY_FILE, re-read on change without a restart)
MACH_EXEC_POLICY="deny:rm -rf /
deny:mkfs" docker compose up -d
```

The image also ships prebuilt agent binaries for all six OS/arch targets
(`/opt/mach-agents/`) — copy one to a target machine; it never needs Go.
State lives in `./data/mach.db` (SQLite: machines, keys, pairings, full
command audit log). Put Caddy/nginx in front for TLS (agents speak wss://).

## Security posture (v1)

- Agents hold only their own Ed25519 identity (no shared master secret).
  Every connection carries a fresh server nonce that the agent signs, so a
  captured hello cannot be replayed; the control plane signs the same nonce
  back, which is how the agent verifies it is talking to the pinned server key
  rather than to whatever TLS handed it.
- Pairing tokens are single-use, ~10-minute TTL; pair-start is rate-limited
  and grants nothing until phone approval + challenge-code match.
- **Command policy, in two layers:** each agent can hold its own block list
  (`MACH_POLICY`) that nothing upstream can override, and the control plane
  can hold a fleet-wide one (`MACH_EXEC_POLICY` / `MACH_EXEC_POLICY_FILE`)
  applied to every key, scope and machine before a command is dispatched.
  Both are foot-guards against mistakes, not sandboxes — see
  `SECURITY-NOTES.md` for exactly what they can promise.
- Output streams to the console as it is produced. It is carried as typed,
  base64-framed chunks, so what a command prints can never be mistaken for a
  control fact: a program that prints an exit record gets its text shown, and
  the exit status the caller sees is still the process's real one.
- Every command is audit-logged (machine, timestamp, command/argv, source
  key, exit code, output snippets) in the control plane's SQLite — including
  commands the policy refused.
- Released agent binaries can carry a signed **in-toto attestation** recording
  the toolchain, build flags, module graph and source revision; `push-update
  --attestation` refuses to ship a binary its attestation does not describe.
- Control plane binds to loopback by default; expose only via your TLS proxy.

### Known limitations (pre-1.0, honest list)

- The control plane reads command content — with no application-layer
  encryption, and none planned: it is a broker that has to see what it
  brokers, and an audit log that records nothing would be worse than none.
  Treat the control plane host as trusted and high-value.
- The command policy matches text, so it is a foot-guard, not a sandbox. Use
  OS-level confinement when the threat is a determined attacker.
- `mach exec` streams output but has no stdin channel, so interactive and TUI
  programs do not work; `mach console` is line-based.
- Output is capped at 8 MiB per stream; the tail past the cap is replaced by a
  visible truncation marker.
- SQLite = single-writer; fine for a household fleet, not a datacenter.

## Build

Any host with Docker (no Go needed): `docker compose build` builds the
control plane plus all cross-targets. Local dev with a Go toolchain:
`go build ./cmd/mach`.