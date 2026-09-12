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
  `internal/store/*`, `internal/console/*`, `internal/policy/*`,
  `internal/oidcauth/*`, or `internal/release/*` without running
  `go test ./...` AND `scripts/e2e.sh`.
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
12. **Two command policies, both enforced on every path**: the agent's own
    (`MACH_POLICY`/`policy.txt`, which no upstream can override) and the
    control plane's fleet-wide one (`MACH_EXEC_POLICY`/`_FILE`, checked after
    authorization and before dispatch — including on `exec_stream`, so typing a
    blocked command into the console is refused exactly like passing it to
    `exec`).
    **The fleet rules are also mirrored onto every machine** (`protocol.PolicyUpdate`,
    pushed at connect and on every change, acknowledged with the version held)
    and evaluated at the same point as the local guardrail. That is what makes
    the block list apply to a *sealed* command: the control plane cannot read one,
    so the text-matching rule has to run where the plaintext is. Both layers are
    evaluated and a refusal from either stands — the mirror can never loosen the
    machine's own rules, and an empty ruleset is an instruction to stop, not a
    licence. Change the rules in one place (`execPolicy.Replace`,
    `reloadFile`) and the broadcast is what makes them current everywhere;
    neither is a sandbox — keep `SECURITY-NOTES.md` honest about that rather
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
15. **The console pins each machine's E2E key on first use** (`console/pins.go`,
    `<state dir>/e2e_pins.json`, 0600), because the key comes from the control
    plane and the control plane is what the seal defends against. A changed key
    refuses to seal in every mode, naming both fingerprints and `mach trust`;
    `mach trust <machine>` is the only thing that accepts one, and
    `--forget` is the only way to turn the protection off. Do not add a silent
    fallback from a pin mismatch to plaintext, and do not make a corrupt pin file
    read as "no pins" — both turn the control off exactly when it matters.
16. **Every dispatched command is audited, streamed ones included.** The relay
    writes a row when the agent reports the exit status — command, source, exit
    code, head of the output — and a `-1` row if the stream ends without one
    (the command's fate on the machine is unknown, so the row says so). A
    refusal is audited as `126` with the rule that refused it, on both paths.
17. **`readonly` cannot stream.** `/v1/console/stream` is command execution; a
    key that can only watch must not reach it, or the scope is decorative.
18. **The web UI is off unless it is fully configured, and never served without
    OIDC.** With no `MACH_OIDC_*` the `/ui` routes are not registered at all —
    not a UI that refuses, no surface to probe. A *partial* configuration is a
    startup failure naming the missing variable. The UI is not a second
    authorization system: any identity the issuer verifies may act, so **that
    issuer's own registration policy is the entire authorization model** unless
    `MACH_OIDC_ALLOWED_DOMAINS` is set. Do not add a UI route outside that gate.
19. **Block is soft, and it is not containment.** A blocked machine stays
    connected and keeps answering keepalives; the control plane sends it no
    commands. Every server→agent *command* path must go through
    `dispatchRefusal` — exec, and the streaming relay's `exec_stream` **and**
    `stream_stdin`/`stream_kill`, since refusing only the first leaves a session
    that can still feed or kill a running command. The policy mirror is
    deliberately **not** gated: it is configuration, and a blocked machine that
    missed a rule change would enforce stale rules against sealed commands the
    moment it was unblocked. Blocking ends live console sessions; it does not
    cancel the command already running on the machine.
20. **Revoke and delete are different, and delete does not reserve the name.**
    Revoke is the sticky tombstone (#10): the row stays, so the name and key stay
    reserved. Delete removes the row and the key, frees the name, and tells a
    connected agent to retire. Delete is the recovery path for a re-imaged box —
    exactly what revocation cannot express — so it is the sharper tool and needs
    the stronger confirmation. Neither writes the other's field.
21. **Enrollment resolves any configured org, not just the primary one.** Orgs
    live in the database (`orgs` table) as well as the environment; `MACH_ORG`
    and `MACH_ORGS` are a pin the UI cannot remove, and an org with machines
    cannot be removed at all. The naming invariant is unchanged
    (`<org>-<machine>` for a *configured* org), but an `enroll`-scoped key can
    now register under any of them.
22. **The agent exits 0 to mean stop.** The installed service restarts on
    failure (`Restart=on-failure`, launchd `SuccessfulExit=false`), so a clean
    exit is how a retirement — revoked or deleted — actually takes effect. Never
    change those to restart unconditionally: it turns a deliberate retirement into
    a restart loop, and it races the update path, which starts its own detached
    replacement and then exits 0.

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
| `MACH_OIDC_ISSUER`, `MACH_OIDC_CLIENT_ID`, `MACH_OIDC_CLIENT_SECRET` | enable the browser UI; **all three or none** (a partial set is fatal). Issuer must be https unless `MACH_PUBLIC_URL` is http |
| `MACH_OIDC_REDIRECT_URL` | default `MACH_PUBLIC_URL + /ui/callback`; required if the public URL has a path prefix |
| `MACH_OIDC_SCOPES` | default `openid,email,profile` |
| `MACH_OIDC_ALLOWED_DOMAINS` | comma-separated email domains; **empty means any identity the issuer verifies may act**. The UI logs this at startup when it is unset |

| `MACH_EXEC_POLICY` | fleet-wide block list, inline (`deny:`/`allowonly`/`allow:`) |
| `MACH_EXEC_POLICY_FILE` | fleet-wide block list from a file, re-read on mtime change every 15s; unreadable at startup is fatal |

Agent side: `MACH_SERVER`, `MACH_ORG`, `MACH_STATE_DIR`, `MACH_POLICY`,
`MACH_USER`, `MACH_KEEP_PRIVILEGES`.

`MACH_TEST_POSTGRES` (test-only): a Postgres DSN for `internal/store`'s
end-to-end test. Without it that test skips, so the Postgres path is otherwise
only covered at the SQL-translation level.

## Testing

- `mise run test` — unit tests (`-race -cover`). Store (both drivers, SQL
  translation, the soft block, org CRUD, single-delivery update pop), server
  (scopes, orgs, normalizeCode, pair page, fleet-wide policy, the streaming
  relay, the per-org E2E flag and its control signal, the fleet-rules mirror and
  its propagation, the block gates on both dispatch paths, the web UI's
  fail-closed routing and CSRF layers), agent (policy — including fleet rules
  binding a sealed command — shells, streaming writers, confinement, the
  supervisor directives), console
  (the E2E signal, key pinning, trust)
  (output-is-data, lost-stream, obeying/refusing the E2E signal), policy,
  protocol, oidcauth (a fake issuer, one broken check per test), release and
  in-toto all have coverage; keep it that way for touched code.
- `mise run e2e` — full end-to-end (builds binaries, spins up the control
  plane on 127.0.0.1:8099 with a fleet-wide policy installed, enrolls via API
  key + QR, exercises exec in both modes, the console relay, output-is-data,
  both policy layers on both paths, sealed-exec refusal, key scoping, lockout,
  revocation, and an attested update push). It also flips the E2E setting for
  one org at runtime and checks the sealed path end to end (the audit row
  becomes a placeholder because the control plane cannot read what it relayed),
  which is the live proof of the per-org control signal. It also proves the
  fleet block list applies to SEALED commands (the rules reach the machine and
  refuse them there) and that a rule added to the policy file on disk reaches a
  machine that is already connected. Pinning is covered too: the first sealed
  command reports the pin, a pin that no longer matches what the control plane
  advertises refuses to seal, and `mach trust` is the only thing that accepts it.
  It also stands up a **second** control plane with OIDC enabled plus
  `scripts/fakeidp` (a stdlib-only loopback identity provider), signs in through
  the real browser flow with a cookie jar, and drives block / unblock / the
  orgs / the typed-name delete / sign-out from the UI. Green = 116 checks.
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
  (`{"v":2,"eph":...,"body":...}`). There is exactly one implementation of that
  format — `internal/e2e`, used by the agent, the console and the tests. Do not
  reintroduce a copy of it in the console: a second implementation is how a
  field goes missing on one side and sealing fails on a machine that is
  otherwise healthy, and there is no dependency edge to avoid (internal/e2e
  imports only the standard library and x/crypto).
- **The AEAD key is derived, not the raw DH output.** `deriveKey` runs HKDF over
  the X25519 shared secret with the recipient's public key and the version bound
  into the info string, so a ciphertext cannot be re-pointed at another
  recipient. The nonce stays random per message, which is safe because the
  sender's key is fresh per message.
- **The format version is checked on the way in, and only one version is
  accepted.** An upgrade that has reached one end and not the other therefore
  fails with "unsupported sealed message version N (this build speaks 2)" rather
  than an AEAD error that reads like a wrong key. Bumping the derivation means
  bumping `sealedVersion`; the machine's own key is unaffected by that.
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
- **A policy change has to be broadcast, not just applied.** The fleet rules
  are enforced on the machines, so `SetExecPolicy` and a `MACH_EXEC_POLICY_FILE`
  reload both call `broadcastFleetPolicy()`. Forget that and the control plane
  holds the new list while every connected machine keeps enforcing the old one
  until it reconnects — regression-tested by
  `TestPolicyFileReloadReachesConnectedAgents`. A push is sent at every connect
  even when the ruleset is empty: "stop enforcing what you were sent" cannot be
  said by staying silent.
- **E2E is per org and the server is the authority** (`mach-server e2e
  [on|off|inherit] --org X`; `MACH_E2E` pins every org). A client never decides
  on its own: it reads the signal and either obeys or exits with a message.
  Never make a client silently downgrade from sealed to plaintext — an operator
  who believes a command was encrypted when it was not is the failure mode this
  exists to prevent.

## Working notes (traps that cost time here)

Not opinions — each of these is something that went wrong in this repo, with the
rule that would have prevented it.

- **A stale control plane holding a port makes the whole e2e UI section lie.**
  The web-UI checks run a second control plane on `MACH_TEST_UI_PORT` (8098) and
  a fake IdP on `MACH_TEST_IDP_PORT` (8097). A `mach-server` left over from
  manual testing keeps the port, the second one fails to bind with only
  `listen tcp ...: address already in use` in its log, and the *stale* server
  answers every request — with a different database. Sign-in still works, so the
  failures look like 21 unrelated broken assertions rather than one occupied
  port. Check the ports before believing a wholesale UI failure.
- **A scripted edit can silently not apply.** Agents edit by string substitution
  across many files, and a replacement that does not match the file's actual text
  fails without saying so. One did, in this repo: the policy-file
  reload updated the control plane and pushed nothing to the agents, which is a
  hole in a security control, and it looked like success. So: after a scripted
  edit, `grep` for the call or marker you inserted in that file, and for anything
  behavioural, write the test, then **revert the change and watch the test fail**
  before trusting it. (`TestPolicyFileReloadReachesConnectedAgents` is the
  example: with `broadcastFleetPolicy()` removed it fails, which is the only
  reason to believe it is testing anything.)
- **`cmd | grep -q pat` can fail spuriously in `scripts/e2e.sh`.** The script sets
  `set -o pipefail`, so when grep exits at its first match the writer takes
  SIGPIPE and the pipeline status is non-zero — a check reports FAIL while the
  output was correct. Capture and compare instead, the way the rest of the script
  does: `OUT=$(cmd 2>&1); [[ "$OUT" == *pat* ]]; check "..." $?`. Remember `check`
  asserts the status you hand it, so whatever produces that status is the test.
- **Update "Green = N checks" in the Testing section** when you add or remove a
  check. The number is the only thing telling the next agent whether the suite
  they ran is the suite this file describes.
- **`internal/console` tests touch the state dir.** Anything that execs resolves
  `MACH_STATE_DIR`, else `$HOME/.mach`. A client test that seals without
  `t.Setenv("MACH_STATE_DIR", t.TempDir())` writes real pin files into the
  developer's home directory — which is how that was noticed. Use `pinState(t)`
  or an equivalent temp state dir.
- **Server goroutines outlive tests.** `server.New` starts a cleanup ticker, and
  nothing ever closes `cleanupStop` (there is no `Close()`), so it keeps running
  for the life of the process — including in every test that builds a server. It
  will therefore read anything you make mutable. A
  package-level `var` for the policy poll interval was a data race between one
  test's cleanup and another test's running server. Hence: keep such knobs
  `const` and expose the tick's body as a function (`pollPolicyOnce`) that a test
  can call directly. That is also faster and less flaky than shrinking a timer.
- **What the server writes into an agent's log becomes greppable test data.** The
  fleet rules are mirrored onto agents and logged there, so the e2e check "the
  blocked marker never appears in the agent's log" started matching the *rule*
  text rather than a dispatched command. Assert on the dispatch path, not on a
  string appearing anywhere in a file.
- **`json.Unmarshal` into a reused struct keeps fields the new JSON omits.** With
  `omitempty` fields (most protocol structs), decoding a second frame into the
  same variable can leave the previous frame's `error` in place. Decode into a
  fresh value.
- **The e2e flips the E2E setting per org mid-run**, so a new step has to know
  which mode is in force — and only a *sealed* command proves anything about what
  reached the machine, because a plaintext one is judged by the control plane.
  That distinction is the whole reason the mirroring tests look the way they do.
- **`gofmt -l .` should be empty before you commit** (there is no mise task for
  it). Files merged in from another branch arrived without trailing newlines, and
  the diff noise from fixing that later is avoidable.
- **Read the merge commit's message before "fixing" something that looks
  redundant.** Two independent implementations of the same four limitations were
  reconciled in `c620a16`; the decisions that look odd in isolation (one-shot exec
  buffered while the console streams, E2E per org and refusable, the block list
  running on the machine) are recorded there with their reasoning.
- **The Postgres path is not exercised by default.** There is neither a Postgres
  server nor a Docker daemon in this environment, so `TestPostgresStoreEndToEnd`
  skips unless you set `MACH_TEST_POSTGRES`. Do not describe that path as verified
  end to end when it has only been checked at the SQL-translation level.
