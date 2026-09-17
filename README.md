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
connection right there in that console.

Bare `mach` is a **temporary session**: it keeps the identity key, the E2E key
and the config in memory and writes nothing, so Ctrl-C ends it and running
`mach` again enrolls this host from scratch. Its enrollment is marked temporary
on the control plane and it retires that enrollment when it ends — and because it
is marked temporary, running `mach` again reuses the same name without you having
to revoke or delete anything first (which matters when a session is killed rather
than stopped). It cannot disturb a machine you have already installed — on one of
those it says so and exits rather than starting a second identity. To make a
connection permanent (auto-start at boot, reconnect after network loss), run
once:

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
| `mach trust [m]` | pinned E2E keys per machine; `mach trust <m>` accepts a changed key, `--forget` drops the pin |
| `mach version` | this binary's version and platform (the control plane's own: `mach-server version`) |

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

# optional: the web UI. All three OIDC variables or none — a partial set is a
# startup error naming what is missing, and with none set there is no /ui route
# at all. Also set MACH_OIDC_ALLOWED_DOMAINS unless you mean "anyone this
# issuer verifies may manage the fleet".
MACH_OIDC_ISSUER=https://accounts.example.com \
MACH_OIDC_CLIENT_ID=mach-ui \
MACH_OIDC_CLIENT_SECRET='…' \
MACH_OIDC_ALLOWED_DOMAINS=example.com \
MACH_PUBLIC_URL=https://mach.example.com docker compose up -d
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
  sealed with X25519 + ChaCha20-Poly1305 (AEAD key derived with HKDF) between
  console and agent; the control
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
- **Web UI with OIDC sign-in** (optional, off by default): a browser view of the
  fleet with per-machine **block** (freeze dispatch — the agent stays connected),
  **revoke** (self-retires the agent; the machine can come back by re-enrolling,
  and only a revoked one can — an active machine is never displaced) and
  **delete** (remove the machine and its
  key, freeing the name so a re-imaged box can enroll again), plus org
  management: add or remove org prefixes, set sealed-exec per org, and see which
  machines and keys belong to each. Deleting needs the machine name typed.
  The same three actions are on the console API for scripts, gated on an
  `exec:*` key exactly like `revoke` — `POST /v1/admin/block`
  (`{"machine":"…","blocked":true|false}`) and `POST /v1/admin/delete`
  (`{"machine":"…"}`) — so a fleet is operable without a browser.
  Set `MACH_OIDC_ISSUER`, `MACH_OIDC_CLIENT_ID` and `MACH_OIDC_CLIENT_SECRET` to
  turn it on — all three or none; with none, `/ui` does not exist. The pages are
  server-rendered with a vendored htmx (no CDN, no build step), so state stays
  live without a JavaScript toolchain, and every action works as a plain form
  post too.

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
- **The web UI's only gate is your identity provider.** Block is fleet-wide and
  delete is irreversible, so any identity the issuer verifies can do both —
  and with an issuer that permits self-registration, that is the internet. Set
  `MACH_OIDC_ALLOWED_DOMAINS` unless you mean that; with it unset the control
  plane says so at startup. (For calibration: `mach-server delete-machine` from
  a shell on the control-plane host already grants the same power with no
  authentication at all.)
- **Block is a freeze on dispatch, not containment.** A blocked machine is still
  connected and still running whatever already runs on that host; it is sent no
  new commands. A command already running is not cancelled.
- **A deleted machine that is offline is not told.** The control plane answers
  its reconnect exactly as it answers a name that never existed — deliberately,
  so the unauthenticated endpoint cannot be used to enumerate machines — so it
  retries on backoff until it is stopped on the host.
- **UI sessions are in memory**, so restarting the control plane signs operators
  out. Nothing about UI authorization is on disk, which is the point.
- **Revocation is recoverable, not a permanent ban.** A revoked machine comes
  back by enrolling again — operator-gated (an enroll key, or phone approval),
  but it does mean whoever can enroll can also un-revoke. What revocation still
  guarantees is that an *active* machine cannot be taken over. A true ban means
  removing the enrollment paths themselves.
- **A temporary session leaves its enrollment on the control plane.** Plain
  `mach` keeps nothing on disk, so Ctrl-C ends it — but the machine row is the
  record a connection needs, so it stays, marked *temporary* and revoked. Next
  time you run `mach` there it takes that name straight back over; the row is
  visible in the fleet (and badged "temporary") until you delete it.

Follow-up work tracks in GitHub issues (#2 sandboxing, #3 PTY, #4 signed
manifests, #5 multi-server) — not in this file.

## Build

Any host with Docker (no Go needed): `docker compose build` builds the
control plane plus all cross-targets. Local dev with a Go toolchain:
`go build ./cmd/mach`.

Builds are unstamped by default and report `devel`. Stamp a version with
`MACH_VERSION=0.3.0 mise run build`, or straight through the linker:

```
go build -ldflags "-X github.com/bcross/mach/internal/version.Version=0.3.0" ./cmd/mach
```

One string serves everything: both binaries, and the six agent binaries baked
into the container image. Signed-in operators see the control plane's version in
the web UI nav, and any machine whose agent reports a different version is
marked `differs` in the fleet table.
