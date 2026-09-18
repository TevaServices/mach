# AGENTS.md — guidance for AI agents (Hermes etc.) working in this repo

This is `mach`: remote CLI access to registered machines, outbound-only
(no inbound firewall holes/port forwards on targets). Two binaries:

- `mach` (cmd/mach) — agent + console. On a fresh target, bare `mach`
  prompts for the control-plane URL, enrolls via QR, then holds the live
  connection — as a **temporary session**, keeping every secret in memory, so
  Ctrl-C ends it and running it again enrolls from scratch (#23).
  `mach install` registers the OS service (systemd/launchd/Task Scheduler) and
  is what makes a connection survive reboots. On an admin box, bare `mach`
  prints the fleet table. On a target that is already installed, bare `mach`
  refuses rather than starting a second identity.
- `mach-server` (cmd/mach-server) — the control plane; the ONLY publicly
  reachable component. Ships as a Docker container. Also serves admin
  commands: `add-api-key`, `revoke-machine`, `delete-machine`, `e2e`,
  `attest`, `verify-attestation`, `push-update`, `version`.

## Ground rules

- **Do not modify** `internal/server/*`, `internal/agent/run.go`,
  `internal/agent/ephemeral.go`, `internal/store/*`, `internal/console/*`,
  `internal/policy/*`, `internal/oidcauth/*`, or `internal/release/*` without running
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
- **One version string.** `internal/version.Version` is the only software
  version in the tree. Builds stamp it with
  `-ldflags "-X github.com/bcross/mach/internal/version.Version=…"`, and an
  unset version means **no** `-X` rather than an empty one — an empty stamp
  makes every binary report nothing and every agent look skewed. Do not add a
  per-package version constant, and do not conflate it with
  `agent.fleetPolicy.Version` / `server.execPolicy.Version` (ruleset
  fingerprints) or `e2e.sealedVersion` (a message-format version): those answer
  "do these two agree on the wire", never "what was this built as". It must stay
  genuinely **read** by all four binaries — `-X` silently does nothing to an
  unreachable symbol, and silently nothing if the symbol path is misspelled, so
  `scripts/e2e.sh` asserts a stamp actually took.

## Security invariants (do not regress)

1. Agents are **outbound-only**: never add an inbound listener to the agent.
2. **Hello is challenge-bound**: the agent signs `name|challenge` where the
   challenge is per-connection (`ReqID` of the server's hello frame).
3. **Server key pinning**: agents store `server_key` at enrollment and
   verify update manifests against it (sig over `version|sha256`).
4. **Challenge codes** are 12 chars (Crockford-ish alphabet, ~60 bits) and
   are printed ONLY on the agent console; the pair page never displays them
   and users type them blind. 5 wrong attempts expire the pairing.
   **They are also never in the QR or in the pair URL.** The QR now carries the
   org and a suggested machine name (invariant 5), and adding the code to that
   list would be the end of the property the code exists for: a photograph of
   the QR would grant any name in any org for the life of the pairing. The code
   stays on the machine's own screen, read by a person standing at it.
5. **Names are org-prefixed** (`<org>-<machine>`, validated by
   `store.ValidOrgName`); taken names error and require a new name. The pair
   page may **pre-fill** the org and a machine name from the QR — a
   `/pair/<token>` link carrying `org` and `name` parameters — but those are
   only defaults in editable fields.
   The name is agent-reported (the hostname), so it is shown under a line saying
   so, and whatever is submitted is validated by `store.ValidOrgName` and the
   enrollment policy exactly as before. What must never happen is a name being
   *used* because the agent suggested it: no pre-selected, non-editable or
   auto-submitted value, and nothing server-side may treat a suggestion as
   anything but untrusted input. The page asks `store.ValidMachinePart` — the
   store's own rule — whether to show one, rather than growing a second rule
   that could disagree with the one that decides.
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

   **`stream_kill` stops the command, and it is what Ctrl-C sends.** Closing the
   command's stdin was the whole of it, which does nothing to a program that is
   not reading it — `sleep`, a wedged build, a hung client — while the console
   says "Ctrl-C kills the remote session". It closes stdin *and* signals the
   process group, reports "killed" with exit 130 (not "timed out": the two share
   a cancelled context and the operator should not be told the machine decided),
   and is idempotent — a second frame for one session used to panic the agent,
   which nothing recovers. Stdin is written by the session's own goroutine, never
   on the frame loop, because a write to a full pipe blocks and that loop
   dispatches every other frame too. One session carries one command: the agent
   tags output and the terminal record with the session id, so a second
   `exec_stream` before the first ends is refused rather than allowed to
   overwrite the audit row's identity. And on the console side, SIGINT is the
   operator asking to kill the remote command while SIGTERM is somebody stopping
   *this process* — the interrupt guard stands down only for the first.
9. **Output caps are per path, and there are TWO of them on the one-shot path**
   — different numbers, on purpose. `protocol.MaxOutputBytes` (8 MiB) bounds what
   the *agent* carries back per stream, truncated with a visible marker;
   `protocol.MaxExecReplyBytes` (16 × that) bounds the *encoded reply* a client
   reads. They must not be equal: a reply is bigger than the result it carries
   (JSON escaping, the exact-bytes form at 4/3×, two streams, and the sealed
   envelope's base64 twice more at 16/9×), so an equal cap makes the agent's
   truncation marker unreachable — the result arrives as an error instead. A
   streamed session is uncapped and the relay drops frames rather than stalling
   an agent whose console has stopped reading. Audit snippets are redacted
   (`RedactScrubs`).

   Related, and the reason the bytes have to be carried exactly:
   `protocol.ExecResult.Stdout/Stderr` are JSON strings, and a JSON string must
   be valid UTF-8, so Go's encoder replaces every invalid byte with U+FFFD. The
   exact bytes travel in `StdoutB64`/`StderrB64` whenever the text form would be
   lossy, and only then. Use `SetOutput`/`Output`; do not read the text fields on
   a path that is meant to be byte-exact.
10. **Revocation is a forced re-enrollment, and its door is narrow.** A revoked
    machine self-retires, its name and key stay reserved, and it comes back only
    by enrolling again — which needs an enroll key or a phone approval, so it is
    still operator-gated. A **TEMPORARY** enrollment may also be taken over (see
    #23), and nothing else may: the guard is the WHERE clause in `store.reenroll`
    (`revoked=1 OR temporary=1`) rather than a caller's check, because the
    counterweight is what matters most here — an ACTIVELY enrolled, PERMANENT
    machine is never displaced, not its name and not its key. That is what stops
    a typo, or a hostile enrollee, taking over a working agent. A takeover clears
    `revoked`, sets `temporary` from the *new* enrollment (so a permanent
    enrollment makes the record permanent), and leaves `blocked` alone (#19).
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

    **The control plane's own check is skipped for a sealed request, and that is
    the same rule rather than an exception to it.** There is no text to match, and
    running the grammar against the empty command left behind is not a stricter
    check but a wrong one: under `allowonly` an empty command fails closed, so
    every sealed command was refused and a console obeying the 403 fell back to
    plaintext with a command it had been told to keep sealed. The rules reach the
    machine through the mirror, which is the only place the plaintext exists.
    Related, in `internal/policy`: an allow rule matches a prefix, and a prefix
    stops describing what will run once the shell can start a second command
    inside it — so `allowonly` refuses command substitution (`$(...)`, backticks,
    process substitution) instead of authorizing it by accident. argv mode is
    unaffected: nothing re-parses an argument vector, so a literal `$(date)` is
    its own text. And a machine name in an exec allowlist is matched *exactly*:
    the store, the lookups and the dispatch path are all case-sensitive, so
    folding case here would let a key scoped to `web` reach `Web`.
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
23. **Plain `mach` on a target is a TEMPORARY session** (`agent/ephemeral.go`).
    It enrolls and holds the live connection with every secret in memory — no
    identity key, no E2E key, no config on disk — so Ctrl-C is a real shutdown
    and running it again enrolls from scratch. It must never read, write or
    delete the persistent state: an installed host's enrollment is what its
    service runs on, so bare `mach` there refuses rather than starting a second
    identity that would compete for the same console. `registerQRCore` and
    `registerAPIKeyCore` stay free of persistence — that split (load identity
    and keys → core → save) is the only thing keeping the temporary path
    incapable of writing, so do not "simplify" it back.

    Two halves, and both are needed. The enrollment is **recorded as temporary**
    on the control plane (a field on the claim/register request), and the session
    **retires itself on exit** (a `retire` frame on its authenticated
    connection). The retirement is the tidy path; the marking is the one that
    always works — a session killed outright, or cut off before it can say
    anything, leaves a temporary record whose name the next run takes over with
    no operator action. A permanent enrollment clears the marking.

    `retire` is accepted from a temporary machine **only**: a permanent agent
    must not be able to retire a machine the operator expects to stay. The frame
    carries no name — the handler uses the connection's own — so an agent can
    retire itself and nothing else. Say what happened on the way out from the
    goroutine that returns from `RunEphemeral`, never from the signal handler:
    the handler's print raced the exit, and lost.

    A temporary session also **traces every command it is asked to run**
    (`(*sessionCtl).announce`, called from `handleExec`/`handleSealedExec`/
    `handleStream`). It is the gate *and* the reason: this mode is watched at a
    terminal, so "what is being done to this box" belongs on that terminal, while
    an installed agent's journal is not the place for a line per command — so
    `ctl` is nil there and the trace is silent. The text is `%q`-quoted because it
    arrives from the control plane and must not be able to forge a console line;
    it is a trace, and nothing reads it back (invariant 7).

## Environment variables (control plane)

| Var | Purpose |
|---|---|
| `MACH_DB` | SQLite path (default `/data/mach.db`) **or** a Postgres DSN (`postgres://…`) |
| `MACH_LISTEN` | listen addr (default `:8080`; compose binds loopback) |
| `MACH_PUBLIC_URL` | public base URL (required to serve): the OIDC redirect it defaults from, the `Secure` cookie decision, and the http-issuer carve-out. **Not** the QR's host — that is built client-side from the server URL the enrolling agent was handed (`internal/agent/register.go`) |
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

`MACH_VERSION` is **not** a runtime variable and is deliberately absent from the
table above: no process reads a version from the environment, because a version
an env var could change is one no bug report and no attestation can pin. It is a
**build-time** knob only — `MACH_VERSION=0.3.0 mise run build|build-all|attest`,
the Dockerfile's `MACH_VERSION` build arg (which the compose file and the release
workflow both pass), and the tag the release workflow derives. A plain build
reports `devel`.

`MACH_TEST_POSTGRES` (test-only): a Postgres DSN. It switches `internal/store`'s
Postgres tests on (the end-to-end one and the concurrency set) and switches
`scripts/e2e.sh` to run its whole suite against Postgres instead of SQLite.
Without it everything Postgres skips, so that path is otherwise only covered at
the SQL-translation level — see the working note at the end of this file for how
to run it, and for why the driver difference matters.

## Testing

- `mise run test` — unit tests (`-race -cover`). Store (both drivers, SQL
  translation, the soft block, org CRUD, single-delivery update pop), server
  (scopes, orgs, normalizeCode, pair page, fleet-wide policy, the streaming
  relay, the per-org E2E flag and its control signal, the fleet-rules mirror and
  its propagation, the block gates on both dispatch paths, the web UI's
  fail-closed routing and CSRF layers), agent (policy — including fleet rules
  binding a sealed command — shells, streaming writers, confinement, the
  supervisor directives), console (output-is-data, lost-stream, obeying the E2E
  signal, key pinning and trust), policy, protocol, oidcauth (a fake issuer, one
  broken check per test), release and in-toto all have coverage; keep it that
  way for touched code.
- `mise run lint` — the gofmt check plus `go vet`. Read-only; `mise run fmt`
  writes the formatting.
- `mise run local:up` / `local:down` / `local:status` / `local:logs` — a real
  control plane and this host enrolled as its agent, both under `data/local/`
  (`scripts/localdev.sh`; `mise run dev` is the same server in the foreground).
  Use it when the thing you are changing is easiest to judge by driving it:
  `mise run local:mach -- exec <machine> 'uname -a'`, or source
  `data/local/env.sh` and use `bin/mach` directly. It is isolated on purpose —
  its own state dirs on both sides, so it never touches `~/.mach`, and it
  registers no OS service. Anything the server reads from the environment
  (`MACH_EXEC_POLICY`, `MACH_E2E`) can be prefixed onto `local:up` to exercise
  it; the playground pins none of those. It does pin one set of variables, the
  `MACH_OIDC_*` block, so the UI is on — see the bullet below.
- `mise run local:server` / `local:enroll` / `local:temp` / `local:reset` — the
  same playground
  split into pieces, for testing enrollment itself. `local:server` starts the
  control plane and stops there: no keys minted, nothing enrolled, so the pair
  page is the only way in. `local:enroll` runs the QR and challenge-code flow in
  the foreground. `local:temp` runs a **temporary** session the same way — bare
  `mach` against the playground, identity in memory, pairing over the same QR +
  challenge-code page, retiring the enrollment on exit — into its own state dir
  (`data/local/temp-agent`), so it never collides with an enrollment from
  `local:up`. **One variable decides the host — `MACH_LOCAL_HOST`** (default
  `auto`: the IPv4 of the default-route interface), and `LISTEN` and
  `MACH_PUBLIC_URL` are derived from it in one place so they cannot disagree.
  This is one knob rather than two because the QR's URL is built by the
  **client** from the server URL it was given, not by the control plane from
  `MACH_PUBLIC_URL` — so whichever invocation runs `mach register` decides what
  the phone is told. `local:server` and `local:enroll` are separate processes,
  so the resolved host is recorded in `data/local/host` and reused: `local:enroll`
  with no environment at all uses the address the running control plane was
  started with, and asking for a different one is an error naming `local:down`
  rather than a second, disagreeing bind. Set it on the command that *starts*
  the server; `MACH_LOCAL_HOST=127.0.0.1` is the lock-down. `local:reset` stops
  everything and deletes `data/local/` for a fresh install — it refuses any path
  that is not the playground, both by canonical containment and by a
  `.playground` marker, because `MACH_LOCAL_DIR` is caller-controlled and the
  next step is `rm -rf`.

  The playground binds **all interfaces by default**, and that is worth stating
  as a security fact rather than an ergonomic one: the pair page is reachable
  from the LAN, gated on the challenge code (the QR token alone grants nothing),
  and `local:enroll` is a foreground flow a person watches. Use
  `MACH_LOCAL_HOST=127.0.0.1` on an untrusted network, or when the point of the
  run is not the phone.

- **The playground's web UI is enabled by real OIDC configuration, not a bypassed
  gate.** `scripts/localdev.sh` starts `scripts/fakeidp` on loopback and sets all
  three `MACH_OIDC_*` variables, so `loadUIConfig` is *fully* configured and
  invariant 18's partial-config error does not apply — a production control plane
  with none of them still serves no `/ui` route. The provider is bound to loopback
  deliberately: it authenticates nobody, so widening it to the network would let
  anyone who can reach the port sign in and manage the fleet. That loopback bind
  is also what makes the LAN-reachable UI safe, and the reason is worth keeping
  rather than re-deriving: a remote browser's `/ui/login` redirect goes to
  `http://127.0.0.1:8190`, which for that browser is *its own* machine, and
  `/ui/callback` exchanges against **this** control plane's configured issuer,
  which only mints for a code its own `/authorize` issued. A code obtained from
  some other machine's provider is `invalid_grant`. So the UI answers on the LAN,
  but only a browser on this host can complete a sign-in.
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
  orgs / the typed-name delete / sign-out from the UI. It also revives a revoked
  machine by re-enrolling it and checks that an active one cannot be taken over,
  and drives the temporary session's whole lifecycle: bare `mach` enrolling over
  the real pair page, being recorded temporary, retiring itself on SIGTERM, and
  the next run taking that name back over with no operator action.
  It also kills a streamed command with Ctrl-C and checks the machine stopped it
  (exit 130 in the audit row, not "fate unknown"), runs the fleet block list in
  `allowonly` mode against sealed commands (the rules judge a sealed command on
  the machine, so an allow-list must not refuse every one of them for having no
  text at the control plane), and checks that a quoted secret in a command is
  redacted out of the audit row.
  Green = 189 checks.
- Timing-sensitive e2e checks (streaming) use a real sleep and a real
  background process; if one flakes, make the sleep longer rather than
  weakening the assertion.
- Tests must not require network beyond loopback or root privileges.

## Deployment notes

- Control plane runs in Docker (`docker compose up -d --build`); the image
  also carries prebuilt agent binaries for all six OS/arch targets under
  `/opt/mach-agents/` — copy one to a target machine; it never needs Go.
  A machine that *itself* runs as a container can run `Dockerfile.agent`
  instead (`ghcr.io/<owner>/mach-agent` on releases): headless enrollment
  from `MACH_SERVER`/`MACH_API_KEY`/`MACH_NAME`, state in a `/data` volume,
  and pushed updates refused by design — update it by pulling a new image,
  not by the control plane's push path.
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
- **Output caps are per path, and the one-shot path has two of them.** See
  invariant 9: `protocol.MaxOutputBytes` bounds the agent's output per stream and
  `protocol.MaxExecReplyBytes` bounds the reply a client will read, and they must
  stay different numbers — equal caps are what made the truncation marker
  unreachable. Neither truncation nor a dropped frame is recoverable.
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
  only for a machine with no `pub_e2e` (pre-E2E enrollment) or a **403** from
  the control plane — the status that means the request was refused *before
  anything was dispatched* (E2E off for the org, the fleet policy, the key's
  scope, a blocked machine). Nothing else qualifies, and that is load bearing: a
  504 means the command was dispatched and the agent did not answer in time, and
  a reply too large to read means it ran and answered. Both used to be read as
  refusals, and the plaintext retry that followed ran the command a *second*
  time — unsealed — under output that looked correct. **One command is one
  execution**: a lost reply is reported, never resent. Do not make a downgrade
  silent, and do not widen this to "retry on error".
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

- **Schema changes are migrations, not edits.** The store's DDL lives in
  `internal/store/migrations/*.sql` (embedded, applied by `migrate()` at
  every open). Adding a column or table = write ONE new numbered migration
  file (`NNNN_name.sql`, 4-digit sequence + lowercase name, `{{ID}}`-style
  but parameter-free DDL — it must contain no `?` at all, so it rebind-safes
  for both drivers by construction) and extend `verifySchema` + its tests.
  Never edit an applied migration: its sha256 is stamped into
  `schema_migrations` and re-verified on every open, so an edit refuses
  startup by design. There are no down-migrations; startup auto-applies
  pending ones. A pre-migration database is adopted at the baseline when
  `verifySchema` accepts it and refused with verifySchema's own message
  otherwise — so a stale-schema refusal keeps its exact wording.

- **A rule written in two places drifts, and the tests can each be happy.** Two
  real bugs here were the same shape, and both survived a green suite:
  (1) the challenge code was hashed in its dashed display form but compared in
  its normalized form, so **no correct code could ever be approved** — the store
  tests approved with the raw code and the server tests exercised `normalizeCode`
  alone, so nothing covered the join; and (2) the pair page had its own copy of
  the "name is taken" rule with a simpler condition, which disagreed with the
  store about revoked and temporary rows. Both are fixed by giving the rule one
  home (`store.NormalizeCode`, `Server.enrollmentRefusal`) and testing the SEAM —
  drive the whole HTTP flow, not each half. When you add a condition to an
  enrollment or pairing rule, grep for a second copy of it.
- **A stale control plane holding a port makes the whole e2e UI section lie.**
  The web-UI checks run a second control plane on `MACH_TEST_UI_PORT` (8098) and
  a fake IdP on `MACH_TEST_IDP_PORT` (8097). A `mach-server` left over from
  manual testing keeps the port, the second one fails to bind with only
  `listen tcp ...: address already in use` in its log, and the *stale* server
  answers every request — with a different database. Sign-in still works, so the
  failures look like 21 unrelated broken assertions rather than one occupied
  port. Check the ports before believing a wholesale UI failure.

  The suite no longer leaves this to the reader: both servers are checked after
  startup, and a run whose own control plane did not bind stops with a FATAL
  naming the port instead of reporting failures about somebody else's database.
  Reproduced deliberately to be sure of the diagnosis — with a stale server on
  8099 the suite reported 77 failures, every one of them about the other database.
  The check is two conditions because either alone is fooled: the process must
  still be alive (a failed bind is a `log.Fatal`) *and* its own log must say it is
  listening. The log line alone proves nothing, because it is written before
  `ListenAndServe` returns — it is present even in the bind-failure log.
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
- **`Server` owns background work, so a test that builds one must close it.**
  `New` starts the housekeeping goroutine (pairing cleanup, the exec-policy file
  poll). `(*Server).Close()` stops it and *waits* for it, so "Close returned"
  means nothing of the server's is still running; without that call the goroutine
  outlives the test and reads whatever the next one mutates. Test helpers do
  `t.Cleanup(s.Close)` (`newTestServer`, `newAuthTestServer`); a new one should
  too. Anything you add to the background work goes in the WaitGroup and is
  stopped by `Close`, or the leak comes back in a form nobody is looking for.
  Two related habits from before `Close` existed and still worth keeping: a
  package-level `var` read by a live goroutine is a data race (a policy poll
  interval used to be one), and a tick's body is better as a function a test can
  call (`pollPolicyOnce`) than as a timer a test has to wait out.
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
- **Formatting is a task, not a habit.** `mise run lint` runs the gofmt check
  (`mise run fmt-check`, read-only) before `go vet`, so a commit that skips it
  fails there; `mise run fmt` writes the fixes. `mise run all` includes it. Files
  merged in from another branch have arrived unformatted before now, and the diff
  noise from cleaning that up later is avoidable.
- **Read the merge commit's message before "fixing" something that looks
  redundant.** Two independent implementations of the same four limitations were
  reconciled in `c620a16`; the decisions that look odd in isolation (one-shot exec
  buffered while the console streams, E2E per org and refusable, the block list
  running on the machine) are recorded there with their reasoning.
- **The Postgres path is not exercised by default — and saying so is the point.**
  With no `MACH_TEST_POSTGRES`, `TestPostgresStoreEndToEnd` and the
  `postgres_concurrency_test.go` set skip, and the Postgres path is covered only
  at the SQL-translation level. Do not describe it as verified when that is what
  ran.

  It CAN be run, and should be when you touch the store: the two drivers are not
  the same concurrency model (SQLite opens with `MaxOpenConns(1)`, Postgres with
  25), so a statement that is correct only because nothing interleaves is correct
  on one driver and not the other. One variable runs everything:

  ```
  docker run -d --name mach-pg -e POSTGRES_PASSWORD=… -e POSTGRES_USER=mach \
      -e POSTGRES_DB=mach -p 55432:5432 postgres:17-alpine
  export MACH_TEST_POSTGRES='postgres://mach:…@127.0.0.1:55432/mach?sslmode=disable'
  mise run test          # includes the Postgres-only store tests
  mise run e2e           # the WHOLE suite, against Postgres
  ```

  `scripts/e2e.sh` switches drivers on that variable: `scripts/pgsetup` clears the
  schema and creates a second database for the web-UI control plane (two control
  planes must not share tables), and `MACH_SERVER_KEY` is set for it because a DSN
  has no path to derive an identity key from. Both are destructive — point them at
  a throwaway server.
