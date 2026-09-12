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
| `mach list` | enrolled machines, online state, and per-org E2E state (`e2e=on|off`) |
| `mach exec <m> <cmd...>` | run remotely; output buffered and printed at exit; local exit code = remote exit code |
| `mach exec <m> -- <argv>` | **no-shell mode**: args pass through byte-exact (no quoting issues) |
| `mach exec --json <m> <cmd...>` | print one JSON object instead of raw output — for programs (output and exit status are fields) |
| `mach exec --e2e <m> <cmd...>` | require end-to-end encryption: fail rather than send the command in plaintext |
| `mach exec --no-e2e <m> <cmd...>` | never encrypt: keep the command readable to the fleet-wide block list and the audit log |
| `mach console <m>` | interactive remote shell: output streams live, stdin and Ctrl-C reach the machine (`:!` runs locally) |
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

# optional: turn end-to-end encryption off for one org, so its commands are
# readable by the block list above (no restart; agents are unaffected)
docker compose exec mach-server mach-server e2e off --org acme
```

The image also ships prebuilt agent binaries for all six OS/arch targets
(`/opt/mach-agents/`) — copy one to a target machine; it never needs Go.
State lives in `./data/mach.db` (SQLite: machines, keys, pairings, full
command audit log) — or in Postgres, if `MACH_DB` is a `postgres://` DSN.
Put Caddy/nginx in front for TLS (agents speak wss://).

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
  applied to every key, scope and machine before a command is dispatched —
  on `mach console` as well as `mach exec`, so typing a blocked command into
  the console is refused like any other. Both layers match text, so the fleet
  rules are also mirrored onto every machine — pushed at connect and on every
  change — and evaluated there, where a sealed (E2E) command is readable. A
  sealed command the block list refuses is refused, with the rule named, and the
  control plane still never sees it. Both layers are foot-guards against
  mistakes, not sandboxes — see `SECURITY-NOTES.md` for exactly what they can
  promise.
- Output streams to the console as it is produced. It is carried as typed,
  base64-framed chunks, so what a command prints can never be mistaken for a
  control fact: a program that prints an exit record gets its text shown, and
  the exit status the caller sees is still the process's real one.
- Every dispatched command is audit-logged (machine, timestamp, command/argv,
  source key, exit code, output snippets) in the control plane's database —
  including streamed commands, and including the ones the policy refused.
- Released agent binaries can carry a signed **in-toto attestation** recording
  the toolchain, build flags, module graph and source revision; `push-update
  --attestation` refuses to ship a binary its attestation does not describe.
- Control plane binds to loopback by default; expose only via your TLS proxy.

### Features (post-limitations, v0.3)

- **E2E encryption, optional and per org**: exec commands and results are
  sealed with X25519 + ChaCha20-Poly1305 between console and agent; the control
  plane relays ciphertext and audits a `[E2E sealed command]` placeholder
  (metadata only: machine, timestamp, source key, exit code). It is a
  server-side setting per org — `mach-server e2e on|off --org X`, default on,
  `MACH_E2E=on|off` pinning every org — and every client is told what the
  server accepts (`mach list` shows it per machine) and obeys it. The fleet-wide
  block list applies either way: on the machine when the command is sealed, on
  the control plane when it is not. Agents
  register an X25519 key at enrollment and keep it whichever way the setting
  is, so flipping it needs no re-enrollment. A machine enrolled before this
  feature has no key, and `mach exec` says so rather than pretending.
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

- **The control plane is a trusted, high-value host.** One-shot `mach exec`
  can be end-to-end sealed (X25519 + ChaCha20-Poly1305) so it learns nothing
  but metadata, but the streaming console cannot be: it is a long-lived relay
  of many small frames, and the relay has to read the command to enforce the
  fleet-wide policy at all. If your threat model says the control plane host
  must never see a command, do not use `mach console`, and accept that while a
  fleet-wide policy is configured sealing is off (the server refuses sealed
  commands rather than relaying them unchecked).
- The command policy (`deny:`/`allowonly`) matches text on the command, so it
  is a foot-guard, not a sandbox — and on a streaming session it cannot judge
  what is typed into a running command's stdin. OS confinement (process group,
  rlimit) bounds damage, but no seccomp/Seatbelt profile exists yet.
- `mach console` has stdin and Ctrl-C but is not a kernel PTY: no echo/line
  discipline, so full-screen TUI apps (vim, htop) still need a real PTY.
  `mach exec` remains output-only.
- Output caps are per path: the buffered path truncates at 8 MiB with a
  visible marker; a streamed session is uncapped, and a console that stops
  reading loses frames rather than stalling the agent. Neither is recoverable.
- SQLite is the default and is single-writer; fine for a household fleet, not
  a datacenter. `MACH_DB=postgres://…` swaps in Postgres (same schema,
  translated at the driver layer) when you outgrow it.
- Release attestations cover binaries pushed at runtime through
  `push-update --attestation`; the copies baked into the container image are
  not attested by that path yet.

Follow-up work tracks in GitHub issues (#2 sandboxing, #3 PTY, #4 signed
manifests, #5 multi-server) — not in this file.

## Build

Any host with Docker (no Go needed): `docker compose build` builds the
control plane plus all cross-targets. Local dev with a Go toolchain:
`go build ./cmd/mach`.