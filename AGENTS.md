# AGENTS.md — guidance for AI agents (Hermes etc.) working in this repo

This is `mach`: remote CLI access to registered machines, outbound-only
(no inbound firewall holes/port forwards on targets). Two binaries:

- `mach` (cmd/mach) — agent + console. On a fresh target, bare `mach`
  prompts for the control-plane URL, enrolls via QR, then holds the live
  connection. `mach install` registers the OS service (systemd/launchd/
  Task Scheduler). On an admin box, bare `mach` prints the fleet table.
- `mach-server` (cmd/mach-server) — the control plane; the ONLY publicly
  reachable component. Ships as a Docker container. Also serves admin
  commands: `add-api-key`, `revoke-machine`, `push-update`.

## Ground rules

- **Do not modify** `internal/server/*`, `internal/agent/run.go`,
  `internal/store/*`, or `internal/console/*` without running
  `go test ./...` AND `scripts/e2e.sh`. These files implement the security
  properties listed below; a change that breaks a test is a regression.
- **Never weaken a security control to make a test pass.** If a test fails
  because a control rejects something, fix the caller or update the test's
  intent — not the control. The full control list and threat model:
  see `SECURITY-NOTES.md` section below.
- Keep `internal/` packages import-clean: `protocol` must stay dependency
  light (stdlib + gorilla/websocket only); it is the wire contract.
- All commands cross the wire as JSON envelopes (`internal/protocol`).
  Adding a frame type: protocol → server pump → agent loop, plus a unit
  test for the payload struct.

## Security invariants (do not regress)

1. Agents are **outbound-only**: never add an inbound listener to the agent.
2. **Hello is challenge-bound**: the agent signs `name|challenge` where the
   challenge is per-connection (`ReqID` of the server's hello frame).
3. **Server key pinning**: agents store `server_key` at enrollment and
   verify update manifests against it (sig over `version|sha256`).
4. **Challenge codes** are 12 chars (Crockford-ish alphabet, ~60 bits) and
   are printed ONLY on the agent console; the pair page never displays them
   and users type them blind. 5 wrong attempts expire the pairing.
5. **Names are org-prefixed** (`<org>-<machine>`, validated by
   `store.ValidOrgName`); taken names error and require a new name. The
   pair page must never suggest names from agent-reported hostnames.
6. **API keys are server-generated** 192-bit secrets, shown once, stored
   as stretched salted hashes. Scopes: `enroll`, `readonly`, `exec:*`,
   `exec:m1|m2`. Enrollment endpoints require the `enroll` scope; exec
   requires the per-machine allowlist match.
7. **Output caps**: agent-side 8 MiB/stream (`cappedBuffer`); audit
   snippets are redacted (`RedactScrubs`).
8. **Revocation** is sticky: revoked machines self-retire, their keys
   cannot re-enroll, and their names stay reserved.
9. `X-Forwarded-For` is honored ONLY when `MACH_TRUST_PROXY=1`.

## Environment variables (control plane)

| Var | Purpose |
|---|---|
| `MACH_DB` | SQLite path (default `/data/mach.db`) |
| `MACH_LISTEN` | listen addr (default `:8080`; compose binds loopback) |
| `MACH_PUBLIC_URL` | public base URL used in QR links (required to serve) |
| `MACH_ORG` | primary org prefix (default `mach`) |
| `MACH_ORGS` | extra orgs for the pair-page dropdown, comma-separated |
| `MACH_TRUST_PROXY` | `1` = honor X-Forwarded-For (only behind your TLS proxy) |
| `MACH_SERVER_KEY` | control-plane identity key path (default `<MACH_DB>.key`) |

Agent side: `MACH_SERVER`, `MACH_ORG`, `MACH_STATE_DIR`, `MACH_POLICY`,
`MACH_USER`, `MACH_KEEP_PRIVILEGES`.

## Testing

- `mise run test` — unit tests (`-race -cover`). Store, server (scopes,
  orgs, normalizeCode, pair page), agent (policy, shells, capped buffer)
  all have coverage; keep it that way for touched code.
- `mise run e2e` — full end-to-end (builds binaries, spins up the control
  plane on 127.0.0.1:8099, enrolls via API key + QR, exercises exec in
  both modes, policy, lockout, revocation, update push). Green = 25 checks.
- Tests must not require network beyond loopback or root privileges.

## Deployment notes

- Control plane runs in Docker (`docker compose up -d --build`); the image
  also carries prebuilt agent binaries for all six OS/arch targets under
  `/opt/mach-agents/` — copy one to a target machine; it never needs Go.
- Put Caddy/nginx in front for TLS (agents speak wss://) and set
  `MACH_TRUST_PROXY=1` on the server. Nothing else exposes ports; targets
  dial out only.
- The control plane is the single high-value target: it brokers every
  command and holds the audit log (E2E keeps command CONTENT from it,
  but metadata remains). Harden it accordingly; see SECURITY-NOTES.md.

## Known limitations (documented, do not hide)

- **E2E encryption is now implemented** (X25519+ChaCha20-Poly1305,
  control plane sees `[E2E sealed command]` audit placeholders) — but the
  policy layer is still a foot-guard, not a sandbox.
- **Streaming console is implemented** (live output chunks, Ctrl-C kills
  the remote session) — it is still not a kernel PTY: no echo/line
  discipline, full-screen TUIs need a real PTY.
- **Postgres backing is implemented** (`MACH_DB=postgres://…`) alongside
  SQLite (WAL, capped connections) — schema is identical.

## Open work for continuing agents (approaches + acceptance criteria)

Each item below was deliberately deferred. Work them in order; each has
an intended approach and an acceptance test. All require `go test ./...`
AND `scripts/e2e.sh` green before a PR.

### 1. Policy layer is a foot-guard, not a sandbox

`internal/agent/policy.go` does substring deny/allow matching — bypassable
(`rm -rf` → `rm -r -f`, base64 pipes, `$(...)`, etc.). Add real OS
confinement behind it:

- Linux: seccomp allowlist for exec'd children
  (`golang.org/x/sys/unix`, SockFprog) applied via the pre-exec hook in
  `internal/agent/run.go` where `applyConfinement(c)` is already called;
  optionally ship `prlimit`-based caps (CPU, FSIZE, NPROC) when the
  `prlimit(1)` binary exists.
- macOS: `sandbox-exec` profile (deprecated but functional) or document
  non-availability honestly.
- Windows: restricted token / Job Object — os/exec cannot do this; use
  `golang.org/x/sys/windows` with a wrapper, or document non-availability.

**Acceptance test**: a unit test where an allowlist-limited command
cannot escape the allowlist via shell metacharacter tricks
(`echo $(rm -rf /)`, backticks, pipes into sh) — the existing
`TestPolicyAllowlist` extends to cover these.

### 2. Streaming console is not a kernel PTY

`/v1/console/stream` (server/stream.go) + `handleStream`
(agent/streamexec.go) give live 32 KiB chunks and remote Ctrl-C, but no
echo/line discipline — TUI apps (vim, htop) don't work.

Fix: add `pty: true` to `protocol.StreamStart`; on the agent, when set,
run the command under a kernel PTY (`github.com/creack/pty`, pure Go,
already an ecosystem standard) and relay the pty master the same way
stream_out chunks flow today. Teach `mach console` local raw mode via
`golang.org/x/term` (MakeRaw on stdin, restore on exit). Keep the
non-PTY path as fallback (Windows without a pty port).

**Acceptance test**: an e2e check that a PTY-allocated session reports
terminal type and survives resize messages — or minimally, `mach
console` running a full-screen app renders without mangling.

### 3. No signed release manifests for shipped binaries

The Docker image ships prebuilt agents in `/opt/mach-agents/` with no
provenance. (Runtime `push-update` manifests ARE signature-verified —
that part is done.)

Fix: in the Dockerfile build stage, after the cross-compile loop, sha256
each binary and sign the manifest with the control-plane identity key
(the same ed25519 flow as `push-update`), emitting `manifest.signed`
next to the binaries. Add a `mach verify <binary> <manifest>`
subcommand that checks the signature against the pinned `server_key`.
Acceptance: a unit test where a tampered binary fails verification, and
an e2e check that the shipped manifest verifies.

### 4. Single control plane = SPOF

Acceptable for a household fleet; the foundation is already in place
(`MACH_DB=postgres://…`). The blocker is the in-memory broker
(`internal/broker/broker.go` maps machine→conn, pinning sessions to one
server). A multi-server design would route exec/stream frames via a
shared pub/sub (Postgres LISTEN/NOTIFY — already a supported backing —
or Redis) and make the `pending` exec waiters shared. Only take this on
if fleet scale actually demands it.

## Wire-format gotchas (learned implementing the above — don't rediscover)

- **SealedB64 is base64 of the SealedMessage JSON**
  (`{"v":1,"eph":...,"body":...}`), and the console's local `e2eWire`
  copy MUST carry the `v:1` field — a missing `v` fails on the agent
  with "unsupported sealed message version".
- **Nonce size**: chacha20poly1305.NonceSize (12 bytes), NOT
  NonceSizeX — mixing them panics on Open.
- **AAD is the sender's ephemeral pubkey** — both Seal and Open must
  pass it; dropping it breaks tamper detection.
- **`mach exec` E2E mode ignores `command`/`argv`**: when `sealed` is
  set the server requires `e2e_pub` and ignores plaintext fields (and
  vice versa). The console always tries E2E first and falls back to
  plaintext only when the machine has no `pub_e2e` (pre-E2E enrollment)
  — don't "fix" that fallback away.
- **Audit in E2E mode** writes a `[E2E sealed command]` placeholder with
  exit code only. Needing command content in audit is a deliberate
  policy change to propose — not silently implement.
- **Agent update re-exec** runs `self run` detached (Setsid on unix);
  if you touch update logic, verify the new process survives the old
  one exiting (e2e checks "post-update exec works" twice).
- **Rate limiters are per-IP** with port-stripped keys; behind a proxy
  they need `MACH_TRUST_PROXY=1` or every client shares the proxy IP.
- **Time-based tests**: pairing TTL/expiry tests sleep tiny amounts;
  keep tolerances loose or they flake on loaded machines.