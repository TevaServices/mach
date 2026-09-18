# mach

Apache-2.0 licensed — free for personal and commercial use. Contributions
follow the same terms; see [License](#license) and
[CONTRIBUTING.md](CONTRIBUTING.md).

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

## Try it locally

One host, everything: a control plane, and this machine enrolled as an agent of
it, with no Docker and no second box.

```
mise run local:up                    # build, start the control plane, enroll this host
mise run local:mach -- list
mise run local:mach -- exec <machine> 'uname -a'
mise run local:mach -- exec --e2e <machine> 'echo this ran sealed'
mise run local:logs                  # follow the control plane, the agent and the IdP
mise run local:down                   # stop (data is kept; `up` resumes it)
```

Everything lands in `data/local/`, including a state dir for each side, so it
cannot disturb a real deployment or your own `~/.mach`. Nothing is installed:
the agent runs as an ordinary background process rather than a launchd/systemd
service. `mise run local:status` prints the fleet, and `data/local/env.sh` holds
the exports if you would rather drive `bin/mach` by hand. Prefix anything the
control plane takes from its environment — `MACH_EXEC_POLICY='deny:rm -rf /'
mise run local:up` — to exercise it.

**The web UI is on here.** A real control plane needs `MACH_OIDC_*` for that;
the playground supplies them by running `scripts/fakeidp`, the same test-only
identity provider the e2e suite uses. The URL to open is printed at startup — use
that one and not `127.0.0.1`, because the sign-in redirect and the session cookie
are both built from the public URL. The provider is bound to loopback on purpose:
it authenticates nobody, so widening it would let anyone on the network sign in
and manage the fleet. So the UI answers on the LAN, but only a browser on this
machine can complete a sign-in.

### From your phone

The control plane binds all interfaces, and `local:up` prints the URL a phone on
the same network can reach. One variable decides it — `MACH_LOCAL_HOST`, default
`auto`, meaning the IPv4 address of the interface carrying the default route —
and the bind and the public URL are both derived from it, so they cannot
disagree. Set it on the command that starts the server:

```
mise run local:server                     # bound to all interfaces; prints the phone URL
MACH_LOCAL_HOST=127.0.0.1 mise run local:server   # this machine only
```

The reason it is one variable and not two: **the QR's URL is built by the client**
from the server URL the enrolling agent was given, not by the control plane from
its public URL. Whichever invocation runs `mach register` therefore decides what
the phone is told, and `local:server` and `local:enroll` are separate processes —
so the resolved host is recorded in `data/local/host` and reused. `local:enroll`
with no environment at all uses the address the running control plane was started
with; asking for a different one is an error telling you to `local:down` first,
rather than a second bind that disagrees with the QR.

To walk the enrollment yourself rather than have it done for you:

```
mise run local:server    # control plane only — no keys minted, nothing enrolled
mise run local:enroll    # prints the QR and the challenge code, then waits
#   scan it with a phone on the same network
mise run local:up        # once enrolled: starts the agent, configures the console
mise run local:reset     # stop and wipe back to a fresh install
```

The challenge code is printed on the agent's console and typed on the pair page:
the QR alone grants nothing, and the page is reachable from the LAN precisely
because the code is what gates it. On an untrusted network, start with
`MACH_LOCAL_HOST=127.0.0.1` and enroll from a browser on this machine instead.

Builds are unstamped by default and report `devel`. Stamp a version with
`MACH_VERSION=0.3.0 mise run build`, or straight through the linker:

```
go build -ldflags "-X github.com/bcross/mach/internal/version.Version=0.3.0" ./cmd/mach
```

One string serves everything: both binaries, and the six agent binaries baked
into the container image. Signed-in operators see the control plane's version in
the web UI nav, and any machine whose agent reports a different version is
marked `differs` in the fleet table.

## Releasing (GitHub Actions)

Push a tag named `v*` and the `release` workflow publishes, on the GitHub
release for that tag: the `mach` client for linux / darwin / windows on
amd64 + arm64, and one in-toto attestation bundle
(`mach-attestations.intoto.jsonl`, a DSSE envelope per line, one per
binary). Each statement carries its binary's sha256, so the bundle is the
release's signed integrity record; the signing key's public half is in the
release notes. Multi-arch (linux/amd64, linux/arm64) `mach-server` and
`mach-agent` containers go to GHCR.

The agent image is for machines that run as containers: enroll it headlessly
with `MACH_SERVER`, `MACH_API_KEY` (an enroll-scoped key) and `MACH_NAME`
(org-prefixed), mount a volume at `/data` for the identity and config, and
restate the machine's own command policy as `MACH_POLICY`. The key is read
once, at enrollment, and can be revoked afterwards; a container that has
already enrolled just needs the volume to keep its enrollment across
restarts. Pushed updates are refused inside the container (the agent updates
by rewriting its own executable, which the image's permissions do not allow) —
pull the next image instead, and the fleet table's `differs` badge is what
flags any container left behind.

The tag is also the version: `v0.3.0` publishes binaries and an image that
report `0.3.0` (the leading `v` is stripped). So `mach version` inside a
container, `mach-server version` on the host, and the GHCR tag all name the
same release — the binaries previously carried a hardcoded constant that no tag
ever reached.

One-time setup: generate a signing key with `scripts/gen-release-key.sh` and
add it as the `MACH_RELEASE_SIGNING_KEY` repository secret. Without it the
release fails rather than shipping unattested binaries — the same rule the
control plane applies to an unreadable policy file. The key is a
provenance/audit control: agents never see the attestation, and a live
control plane still re-attests with its own identity key per the Dockerfile
footer, so `push-update --attestation` works there as documented.

CI (`.github/workflows/ci.yml`) runs lint, unit tests and e2e on main and on
every PR, using the same `mise` tasks the repo documents.

## License

`SPDX-License-Identifier: Apache-2.0`

mach is licensed under the [Apache License 2.0](LICENSE) — use it,
ship it, build a product on it, including commercially.

Contributions are licensed under the same terms (inbound = outbound)
and every commit needs a `Signed-off-by:` line; CI checks it. See
[CONTRIBUTING.md](CONTRIBUTING.md). Found a vulnerability? Don't open
an issue — see [SECURITY.md](SECURITY.md). Code vendored into the tree
(htmx) is listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).