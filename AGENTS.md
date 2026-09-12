# AGENTS.md — guidance for AI agents (Hermes etc.) working in this repo

This is `mach`: remote CLI access to registered machines, outbound-only
(no inbound firewall holes/port forwards on targets). Two binaries:

- `mach` (cmd/mach) — agent + console. On a fresh target, bare `mach`
  prompts for the control-plane URL, enrolls via QR, then holds the live
  connection. `mach install` registers the OS service (systemd/launchd/
  Task Scheduler). On an admin box, bare `mach` prints the fleet table.
- `mach-server` (cmd/mach-server) — the control plane; the ONLY publicly
  reachable component. Ships as a Docker container. Also serves admin
  commands: `add-api-key`, `revoke-machine`, `delete-machine`, `attest`,
  `verify-attestation`, `push-update`.

## Ground rules

- **Do not modify** `internal/server/*`, `internal/agent/run.go`,
  `internal/store/*`, `internal/console/*`, `internal/policy/*`, or
  `internal/release/*` without running `go test ./...` AND `scripts/e2e.sh`.
  These files implement the security properties listed below; a change that
  breaks a test is a regression.
- **Never weaken a security control to make a test pass.** If a test fails
  because a control rejects something, fix the caller or update the test's
  intent — not the control. The full control list and threat model:
  see `SECURITY-NOTES.md` section below.
- Keep `internal/` packages import-clean: `protocol` must stay dependency
  light (stdlib + gorilla/websocket only); it is the wire contract.
- All commands cross the wire as JSON envelopes (`internal/protocol`).
  Adding a frame type: protocol → server pump → agent loop, plus a unit
  test for the payload struct.
- `internal/policy` is shared by the agent and the control plane: one grammar,
  two enforcement points. Change it once and both sides change together —
  never fork the matching rules.

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
7. **Output is data, never input.** Nothing in the agent may read a command's
   output back to decide anything, and nothing in the console may parse a
   control fact out of text: control facts live in typed fields (`exit_code`,
   `type`) and output travels base64-framed inside a typed chunk. A command
   that prints a protocol frame, a `mach:` line or a fake prompt must change
   nothing. See `client_test.go TestOutputCannotForgeControlFacts`.
8. **Streaming is one-directional**: output only. There is no stdin channel;
   adding one would create a second path by which input reaches a machine, and
   the model has exactly one (a command the control plane asked for).
9. **Output caps**: agent-side 8 MiB/stream (`internal/agent/stream.go`),
   marked visibly when hit; audit snippets are redacted (`RedactScrubs`).
10. **Revocation** is sticky: revoked machines self-retire, their keys
    cannot re-enroll, and their names stay reserved.
11. `X-Forwarded-For` is honored ONLY when `MACH_TRUST_PROXY=1`.
12. **Two command policies, both enforced**: the agent's own
    (`MACH_POLICY`/`policy.txt`, which no upstream can override) and the
    control plane's fleet-wide one (`MACH_EXEC_POLICY`/`_FILE`, checked after
    authorization and before dispatch). Neither is a sandbox — keep
    `SECURITY-NOTES.md` honest about that rather than overselling it.
13. **Release attestations**: `mach-server attest` signs an in-toto statement
    with the identity key agents pin; `push-update --attestation` verifies the
    subject digest before queueing and refuses a modified-tree build. Signature
    verification always precedes parsing the payload.

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

| `MACH_EXEC_POLICY` | fleet-wide block list, inline (`deny:`/`allowonly`/`allow:`) |
| `MACH_EXEC_POLICY_FILE` | fleet-wide block list from a file, re-read on mtime change every 15s; unreadable at startup is fatal |

Agent side: `MACH_SERVER`, `MACH_ORG`, `MACH_STATE_DIR`, `MACH_POLICY`,
`MACH_USER`, `MACH_KEEP_PRIVILEGES`.

## Testing

- `mise run test` — unit tests (`-race -cover`). Store, server (scopes,
  orgs, normalizeCode, pair page, fleet-wide policy), agent (policy, shells,
  streaming writers), console (output-is-data), policy, protocol, release all
  have coverage; keep it that way for touched code.
- `mise run e2e` — full end-to-end (builds binaries, spins up the control
  plane on 127.0.0.1:8099 with a fleet-wide policy installed, enrolls via API
  key + QR, exercises exec in both modes, streaming, output-is-data, both
  policy layers, key scoping, lockout, revocation, and an attested update
  push). Green = 47 checks.
- Timing-sensitive e2e checks (streaming) use a real sleep and a real
  background process; if one flakes, make the sleep longer rather than
  weakening the assertion.
- Tests must not require network beyond loopback or root privileges.

## Deployment notes

- Control plane runs in Docker (`docker compose up -d --build`); the image
  also carries prebuilt agent binaries for all six OS/arch targets under
  `/opt/mach-agents/` — copy one to a target machine; it never needs Go.
- Put Caddy/nginx in front for TLS (agents speak wss://) and set
  `MACH_TRUST_PROXY=1` on the server. Nothing else exposes ports; targets
  dial out only.
- The control plane is the single high-value target: it reads command
  content by design (there is no application-layer E2E and none is planned —
  it is a broker that must see what it brokers) and holds the audit log.
  Harden it accordingly; see README "Known limitations" for the honest list.

## Known limitations (documented, do not hide)

- The control plane can read command content; no application-layer
  encryption, by design (TLS protects the wire only).
- Both policy layers (`deny:`/`allowonly`) match text: foot-guards, not
  sandboxes. Do not describe them as confinement.
- No stdin and no PTY: `mach exec` streams output one way, `mach console` is
  line-based. Interactive/TUI programs do not work.
- Output is capped at 8 MiB/stream, and a slow console can cause drops; both
  are marked visibly but are not recoverable.
- SQLite = single writer; sized for a household fleet.