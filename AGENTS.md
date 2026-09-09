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
- The control plane is the single high-value target: it reads command
  content (no app-layer E2E yet) and holds the audit log. Harden it
  accordingly; see README "Known limitations" for the honest list.

## Known limitations (documented, do not hide)

- **E2E encryption is now implemented** (X25519+ChaCha20-Poly1305,
  control plane sees `[E2E sealed command]` audit placeholders) — but the
  policy layer is still a foot-guard, not a sandbox.
- **Streaming console is implemented** (live output chunks, Ctrl-C kills
  the remote session) — it is still not a kernel PTY: no echo/line
  discipline, full-screen TUIs need a real PTY.
- **Postgres backing is implemented** (`MACH_DB=postgres://…`) alongside
  SQLite (WAL, capped connections) — schema is identical.