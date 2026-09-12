# AGENTS.md — guidance for AI agents (Hermes etc.) working in this repo

This is `mach`: remote CLI access to registered machines, outbound-only
(no inbound firewall holes/port forwards on targets). Two binaries:

- `mach` (cmd/mach) — agent + console. On a fresh target, bare `mach`
  prompts for the control-plane URL, enrolls via QR, then holds the live
  connection. `mach install` registers the OS service (systemd/launchd/
  Task Scheduler). On an admin box, bare `mach` prints the fleet table.
- `mach-server` (cmd/mach-server) — the control plane; the ONLY publicly
  reachable component. Ships as a Docker container. Also serves admin
  commands: `add-api-key`, `revoke-machine`, `delete-machine`, `e2e`,
  `attest`, `verify-attestation`, `push-update`.

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
8. **Streaming is plaintext, and it is not one-directional.** `mach console`
   relays over a dedicated WebSocket (`/v1/console/stream`) and carries
   `stream_stdin` and `stream_kill` alongside `stream_out`. Two things follow,
   both deliberate: the text-matching policy judges the command the console
   asked for, not the bytes later typed into it (there is no honest way to match
   a stream against a block list), and because the relay *can* read the command
   it is the one path where the fleet-wide policy is enforced server-side.
   Stdin reaches a machine only through a command an operator already started.
9. **Output caps are per path**: the buffered one-shot path truncates at 8 MiB
   (`internal/agent/run.go`), marked visibly when hit; a streamed session is
   uncapped and the relay drops frames rather than stalling an agent whose
   console stopped reading. Audit snippets are redacted (`RedactScrubs`).
10. **Revocation** is sticky: revoked machines self-retire, their keys
    cannot re-enroll, and their names stay reserved.
11. `X-Forwarded-For` is honored ONLY when `MACH_TRUST_PROXY=1`.
12. **Two command policies, both enforced on both paths**: the agent's own
    (`MACH_POLICY`/`policy.txt`, which no upstream can override) and the
    control plane's fleet-wide one (`MACH_EXEC_POLICY`/`_FILE`, checked after
    authorization and before dispatch — including on `exec_stream`, so typing a
    blocked command into the console is refused exactly like passing it to
    `exec`). Both check every *plaintext* command whatever the E2E setting is;
    what they cannot check is a sealed command, which has no text to match —
    turn E2E off if the fleet-wide block list has to bite on the one-shot path.
    Neither is a sandbox — keep `SECURITY-NOTES.md` honest about that rather
    than overselling it.
13. **Release attestations**: `mach-server attest` signs an in-toto statement
    with the identity key agents pin; `push-update --attestation` verifies the
    subject digest before queueing and refuses a modified-tree build. Signature
    verification always precedes parsing the payload.
14. **E2E is a server-side setting, per org, and the client obeys it.** Stored
    in the database (`e2e`, `e2e:<org>`), overridden by `MACH_E2E` for every
    org. With it off, sealed exec is refused before dispatch (403, audited, with
    the reason in the response) and `/e2epub` advertises no key, so an obeying
    console never seals. Consoles read the signal (`/e2epub`, the per-machine
    field in the fleet listing) and either seal, or — when the operator passed
    `--e2e` and sealing is unavailable — exit with a message. Nothing on the
    agent changes either way: it keeps its key, so turning the setting back on
    restores sealing with no re-enrollment. Do not reintroduce a "refuse sealed
    while a policy is configured" rule: the flag is the single decision point,
    and a sealed command is exactly what an operator chose when they left it on.
15. **Every dispatched command is audited, streamed ones included.** The relay
    writes a row when the agent reports the exit status — command, source, exit
    code, head of the output — and a `-1` row if the stream ends without one
    (the command's fate on the machine is unknown, so the row says so). A
    refusal is audited as `126` with the rule that refused it, on both paths.
16. **`readonly` cannot stream.** `/v1/console/stream` is command execution; a
    key that can only watch must not reach it, or the scope is decorative.

## Environment variables (control plane)

| Var | Purpose |
|---|---|
| `MACH_DB` | SQLite path (default `/data/mach.db`) **or** a Postgres DSN (`postgres://…`) |
| `MACH_LISTEN` | listen addr (default `:8080`; compose binds loopback) |
| `MACH_PUBLIC_URL` | public base URL used in QR links (required to serve) |
| `MACH_ORG` | primary org prefix (default `mach`) |
| `MACH_ORGS` | extra org prefixes (comma-separated): the pair-page dropdown, and what resolves a machine's org for per-org settings (E2E) |
| `MACH_TRUST_PROXY` | `1` = honor X-Forwarded-For (only behind your TLS proxy) |
| `MACH_SERVER_KEY` | control-plane identity key path (default `<MACH_DB>.key`) |
| `MACH_E2E` | `on`/`off`: overrides the stored E2E setting for **every** org (validated at startup; an unusable value is fatal) |

| `MACH_EXEC_POLICY` | fleet-wide block list, inline (`deny:`/`allowonly`/`allow:`) |
| `MACH_EXEC_POLICY_FILE` | fleet-wide block list from a file, re-read on mtime change every 15s; unreadable at startup is fatal |

Agent side: `MACH_SERVER`, `MACH_ORG`, `MACH_STATE_DIR`, `MACH_POLICY`,
`MACH_USER`, `MACH_KEEP_PRIVILEGES`.

`MACH_TEST_POSTGRES` (test-only): a Postgres DSN for `internal/store`'s
end-to-end test. Without it that test skips, so the Postgres path is otherwise
only covered at the SQL-translation level.

## Testing

- `mise run test` — unit tests (`-race -cover`). Store (both drivers, SQL
  translation), server (scopes, orgs, normalizeCode, pair page, fleet-wide
  policy, the streaming relay, the per-org E2E flag and its control signal),
  agent (policy, shells, streaming writers, confinement), console
  (output-is-data, lost-stream, obeying/refusing the E2E signal), policy,
  protocol, release and in-toto all have coverage; keep it that way for touched
  code.
- `mise run e2e` — full end-to-end (builds binaries, spins up the control
  plane on 127.0.0.1:8099 with a fleet-wide policy installed, enrolls via API
  key + QR, exercises exec in both modes, the console relay, output-is-data,
  both policy layers on both paths, sealed-exec refusal, key scoping, lockout,
  revocation, and an attested update push). It also flips the E2E setting for
  one org at runtime and checks the sealed path end to end (the audit row
  becomes a placeholder because the control plane cannot read what it relayed),
  which is the live proof of the per-org control signal. Green = 61 checks.
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
- The control plane is the single high-value target: it brokers every command
  and holds the audit log. One-shot `mach exec` can be end-to-end sealed, so on
  that path the command and its output are opaque to it (metadata — machine,
  timing, size, exit status — never is). The streaming relay cannot be sealed
  and is plaintext by design, which is also what lets it enforce the block list
  server-side. Harden it accordingly; see SECURITY-NOTES.md.

## Wire-format gotchas (learned the hard way — don't rediscover)

- **Two transports, one protocol.** `mach exec` is one-shot and buffered — a
  single `ExecResult` object carrying exit code and output, which is the only
  shape that can be end-to-end sealed. `mach console` streams over
  `/v1/console/stream` as many small frames. Don't "unify" them: sealing needs
  the whole result (and the whole command) at once, and streaming needs the
  opposite.
- **Both policy layers (`deny:`/`allowonly`) match text** on the command as
  asked: foot-guards, not sandboxes. Do not describe them as confinement. On
  the streaming path they judge the command, never the bytes later typed into
  its stdin — there is no way to match a stream against a block list, and
  pretending otherwise would be worse than saying so.
- **No PTY**: `mach console` has stdin and Ctrl-C (kill) but no echo/line
  discipline, so interactive and TUI programs still do not work. `mach exec`
  remains output-only. This is tracked as future work, not a design claim.
- **Output caps are per path**: the buffered one-shot path truncates at 8 MiB
  (marked visibly); a streamed session is uncapped, and the relay drops frames
  rather than stalling an agent whose console has stopped reading. Neither
  truncation nor a drop is recoverable.
- **`mach exec --json` prints one JSON object**, not a frame stream — the
  machine's output in a field, the exit status in a field. It is for programs
  that would otherwise have to parse an exit status out of bytes a command
  could print.
- **SQLite = single writer; sized for a household fleet.** Postgres is
  supported (`MACH_DB=postgres://…`): one schema, translated at the driver
  layer, so keep new SQL in the `{{ID}}`/`?` style the store's wrappers expect
  rather than hand-writing a dialect.
- **SealedB64 is base64 of the SealedMessage JSON**
  (`{"v":1,"eph":...,"body":...}`), and the console's local `e2eWire`
  copy MUST carry the `v:1` field — a missing `v` fails on the agent
  with "unsupported sealed message version". The console keeps its own copy of
  the sealed-message code deliberately (the two packages must not share a
  dependency edge); `internal/console/client_test.go`'s sealed cases drive a
  real round trip through `internal/e2e`, so a drift between the copies fails a
  test rather than a machine.
- **Nonce size**: chacha20poly1305.NonceSize (12 bytes), NOT
  NonceSizeX — mixing them panics on Open.
- **AAD is the sender's ephemeral pubkey** — both Seal and Open must
  pass it; dropping it breaks tamper detection.
- **`mach exec` E2E mode ignores `command`/`argv`**: when `sealed` is
  set the server requires `e2e_pub` and ignores plaintext fields (and
  vice versa). What the console does about E2E is *obey the server*: `/e2epub`
  says whether this control plane accepts sealed commands and gives the key,
  and the console seals when both are available. It falls back to plaintext
  only for a machine with no `pub_e2e` (pre-E2E enrollment) or a control plane
  that refuses sealing — and in the first case it says so on stderr. Do not
  make that downgrade silent, and do not "fix" the fallback away: the operator
  is told which it was, which is the point.
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
- **E2E is per org and the server is the authority** (`mach-server e2e
  [on|off|inherit] --org X`; `MACH_E2E` pins every org). A client never decides
  on its own: it reads the signal and either obeys or exits with a message.
  Never make a client silently downgrade from sealed to plaintext — an operator
  who believes a command was encrypted when it was not is the failure mode this
  exists to prevent.
