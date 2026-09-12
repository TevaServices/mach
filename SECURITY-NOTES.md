# SECURITY-NOTES.md — mach security model and threat notes

Audience: operators and security reviewers. Read before exposing the
control plane beyond a household.

## Trust model

```
phone ──TLS──▶ control plane ◀──TLS(wss)── agents (outbound only)
                 ▲
console (mach) ──┤ (TLS, bearer key)
operator browser ┘ (TLS, OIDC — the web UI, optional)
```

- The control plane is the **only public component** and the **single
  point of command authority**: it brokers exec, holds the audit log, and
  can read command content on the streaming path (sealed one-shot execs are
  opaque to it — see below). Treat its host as high-value; access to its
  DB = control of every machine, and the ability to push a signed update.
- The **operator browser** is a fourth client, and it is the least constrained
  one: OIDC establishes *who* someone is, not *whether they should be here*, and
  any identity the issuer verifies may block, revoke, delete and add orgs. It is
  therefore the issuer's registration policy that gates access unless
  `MACH_OIDC_ALLOWED_DOMAINS` is set. The UI is off unless it is fully
  configured, so a deployment that does not want it has no such surface.
- Agents trust exactly: (a) their pinned control-plane identity key
  (`server_key` in config.json), (b) TLS to the enrolled URL.
- The phone/admin is trusted only after presenting the challenge code
  that was printed on the agent's console (12 chars, ~60 bits) — the QR
  token alone grants nothing.

**End-to-end encryption exists, on one of the two command paths, and it is
optional per org.** A one-shot `mach exec` can be sealed with X25519 +
ChaCha20-Poly1305 between the console and the agent: the control plane relays a
ciphertext blob in each direction and learns only metadata (machine, timing,
size, source key, exit status) — command and output content stay opaque to it,
and the audit row records `[E2E sealed command]`. Machines advertise an X25519
key (`pub_e2e`) at enrollment.

It is a server-side setting, per org — `mach-server e2e on|off|inherit --org X`,
with a default for orgs that have no setting of their own, and `MACH_E2E` as a
deployment-wide pin that overrides every org. The control plane is the authority
because it is the party that cannot read ciphertext, and clients never decide on
their own: they read the signal (`GET /v1/machines/{name}/e2epub`, and a
per-machine field in the fleet listing) and either obey it or exit with a
message saying they cannot do what they were asked to.

**What the setting means, in both directions:**

- **On** (the default): the control plane relays sealed commands and hands out
  the machine's key. It cannot read them, so the fleet-wide block list is
  enforced by the machine instead — the rules are mirrored to every agent and
  evaluated where the command is decrypted (see "Command policy" below).
- **Off**: sealed exec is refused before dispatch (`403`, audited, with the
  reason in the response) and no key is advertised, so an obeying console never
  tries. Every command for that org runs in plaintext, where the control plane
  itself can read and refuse it before dispatching anything.

What the seal is worth, stated plainly: it keeps the command and its output from
the control plane and it is authenticated (a tampered envelope fails to open) —
but the key it seals to is handed out by the control plane itself, so a control
plane that wanted to read the command could advertise its own key and open what
it received. The console closes that as far as it can with **trust on first use**:
it remembers the first key it is given for each machine and refuses to seal to any
other, which turns a silent permanent capability into a one-shot, visible one.

Precisely what that does and does not buy:

- **Detected**: a key substituted after this console has sealed to that machine.
  Sealing stops with an error naming both fingerprints, and stays stopped until a
  human runs `mach trust <machine>`. Nothing downgrades to plaintext on the way.
- **Not detected**: a key substituted *before* the first sealed command, which
  silently pins whatever it was given. There is no way around that without an
  out-of-band fingerprint or a key-transparency log, and this does not have one.
- **Also caught, and indistinguishable**: a machine that legitimately re-enrolled
  with a fresh key (wiped state dir, rebuilt host). The remedy is the same
  explicit command, which is the point: a key change is a decision, not something
  a client resolves on its own.
- **The pin file is a control in its own right** (`<state dir>/e2e_pins.json`,
  0600): whoever can rewrite it chooses which key this console seals to. A file
  that cannot be parsed is an error rather than an empty pin set, because
  "unreadable" silently re-pinning would disable the protection exactly when
  something is wrong. `mach trust --forget <machine>` is the deliberate way to
  turn it off for one machine.
- It is not protection from the machine's own operator, and it says nothing about
  whether the machine is the one you think it is — only that it is the same one
  you spoke to last time.

**Nothing on any agent changes in either direction.** An agent keeps its
`e2e.key`, keeps registering the public half at enrollment, and keeps opening
whatever sealed frame reaches it. With the setting off no sealed frame ever
does, because the refusal happens at the control plane, before dispatch — the
agent is never told which way the setting is set and has no reason to care. So
turning it back on restores sealing immediately: no re-enrollment, no agent
restart, no key rotation. An agent enrolled while the setting was off still has
a key registered, and one enrolled before the feature existed simply has none —
`mach exec` says so on stderr rather than letting you believe a command was
sealed, and re-enrolling that machine is what fixes it.

The **streaming console cannot be sealed**, and this is a design limit rather
than an unfinished feature: a live session is a long-lived relay of many small
frames, and a per-frame seal would still let the control plane see frame
boundaries and timing while costing a key exchange per chunk. That same relay
is why the fleet-wide policy can be enforced on the server side at all — it can
read the command. So the two paths trade off honestly: on `mach exec` the
server can protect content but cannot inspect it, and on `mach console` it can
inspect the command but not protect it.

Absent a seal, the control plane is a broker that must see what it brokers, and
it is trusted accordingly. TLS protects the wire; the seal protects content
from the broker; nothing protects content from the machine's own operator.

## Controls implemented

| Control | Where |
|---|---|
| Per-connection challenge-bound agent hello (replay-proof) | server/agent.go, agent/run.go |
| Control-plane identity key persisted & pinned by agents; signed update manifests (sig over version\|sha256) | server/serverkey.go, agent/run.go handleUpdate |
| Pairing tokens: 256-bit, single-use, ~10 min TTL | store.CreatePairing |
| Challenge codes: 12 chars, agent-console-only, typed blind on phone; 5 wrong attempts expire the pairing | store.NewChallengeCode, server/pairpages.go |
| Pair-start rate limit (5 per IP / 10 min) and auth-failure rate limit (20 / 10 min) | server.go, consoleapi.go |
| Org-prefixed machine names, no hostname-derived suggestions, conflicts error | store.ValidOrgName, server/orgs.go, pairpages.go |
| Scoped API keys (enroll / readonly / exec:* / exec:m1\|m2), server-generated 192-bit secrets, stretched salted hashes | controlplane.AddAPIKey, store |
| Read-only keys see the whole fleet and the whole audit trail, and nothing else | server/consoleapi.go canRead/readScope |
| **Fleet-wide command block list** (`MACH_EXEC_POLICY` / `MACH_EXEC_POLICY_FILE`), enforced for every key, scope and machine before dispatch — on `mach exec` **and** on the streaming console | server/policy.go, consoleapi.go handleExec, stream.go handleConsoleStreamWS |
| **The same rules mirrored onto every machine** (pushed at connect, and on every change) and evaluated where a sealed command is decrypted, so the block list applies to E2E commands too; the agent acknowledges the ruleset version it holds | server/policy.go pushFleetPolicy, agent/policy.go fleetPolicy |
| **E2E as a per-org server setting** (`mach-server e2e on\|off\|inherit --org X`, stored in `settings`; `MACH_E2E` pins every org), with the control signal clients obey or refuse on | server/e2eflag.go, consoleapi.go handleExec/handleE2EPub |
| Sealed exec refused while the setting is off, before dispatch, and no key advertised — so a client cannot believe it sealed | consoleapi.go handleExec, handleE2EPub |
| Per-machine command policy on the agent itself (`MACH_POLICY` / `policy.txt`), evaluated where no upstream can override it, on both paths | agent/policy.go, internal/policy |
| E2E sealing of one-shot exec: X25519 + ChaCha20-Poly1305, ephemeral sender key per command, AEAD key derived with HKDF (recipient and format version bound into the info string), AAD = the sender's ephemeral pubkey, format version checked on the way in | internal/e2e, agent/e2eexec.go |
| **Trust-on-first-use pinning of each machine's E2E key** on the console: a changed key refuses to seal (naming both fingerprints and the remedy) instead of sealing to whatever the control plane now advertises | console/pins.go, client.go runExec |
| `readonly` keys refused on the streaming endpoint (it is command execution, not observation) | stream.go handleConsoleStreamWS |
| Confinement of remote commands: own process group (unix), SIGKILL as a tree on timeout (Windows: timeout + caps only) | agent/confine*.go |
| Output caps per path, with visible truncation markers; streamed frames dropped rather than stalling an agent whose console stopped reading | agent/run.go, agent/streamexec.go |
| Machine output is data, never input: nothing in the agent reads it back, and the console labels it rather than parsing a control fact out of text | agent/run.go, console/client.go, console/stream.go |
| Audit log with secret-value redaction; every dispatched command recorded on both paths; refusals audited too; a stream that dies without an exit status recorded as `-1`; optional purge on revoke | store.RedactScrubs/AuditInsert/RemoveMachineAudit, server/stream.go |
| Signed in-toto attestations for released agent binaries, verified before an update can be queued | internal/release, controlplane/attest.go |
| Revocation: self-retiring agents, names and keys stay reserved. **A revoked OR temporary machine can be taken over by re-enrolling it — and only one of those two**: the guard is the `WHERE revoked=1 OR temporary=1` in `store.reenroll`, so an actively enrolled **permanent** machine's name and key can never be taken by an enrollment | store.RevokeMachine/reenroll, server enrollmentRefusal, agent errRevoked |
| **Temporary session** (plain `mach` on a target): enrolls and serves with the identity key, E2E key and config held **in memory only**, so Ctrl-C is a real shutdown and running it again re-enrolls. It cannot read, write or delete the persistent state, so an installed host's enrollment is untouchable from it — and bare `mach` there refuses rather than starting a second identity | agent/ephemeral.go, registerQRCore/registerAPIKeyCore, cmd/mach bootStrap |
| **The temporary enrollment is recorded as such**, and the session **retires it on exit** via a `retire` frame on its own authenticated connection. Accepted **only** from a temporary machine, so a permanent agent cannot retire a machine the operator expects to stay; the frame carries no name, so an agent can retire itself and nothing else | protocol retire, server handleSelfRetire, store.machines.temporary |
| Challenge codes are compared in **one canonical form** (`store.NormalizeCode`), used by both the hashing and the page. It used to be hashed dashed and compared undashed, which meant no correct code could ever be approved — see the working note in AGENTS.md | store.NormalizeCode, server/pairpages.go, paircode_test.go, pairhttp_test.go |
| Agent privilege drop on linux root (MACH_USER, default nobody) | agent/droppriv_linux.go |
| X-Forwarded-For honored only with MACH_TRUST_PROXY=1 | server.New + SetTrustProxy |
| Pair-page security headers (CSP default-src 'none', XFO DENY, nosniff, no-referrer); cross-site POST refused | pairpages.go |
| **Web UI is off unless fully configured**: no `MACH_OIDC_*` means the `/ui` routes are not registered (404, nothing to probe); a partial set is a fatal startup error naming the variable | server/uiconfig.go, server.go Routes |
| **OIDC sign-in**: discovery-backed ID token verification by `coreos/go-oidc` (signature, issuer, audience, expiry), signing algorithms pinned to RS256/ES256/PS256, nonce compared by us because the library does not, empty subject refused. Discovery is lazy and a failure is not cached | server/uicallback, internal/oidcauth |
| **Login CSRF**: the callback must carry the same browser's state cookie, and the state is consumed only after that check — so a captured code cannot be replayed and a stray callback cannot burn the operator's state | server/uihandlers handleUICallback |
| **UI session and CSRF**: in-memory bounded session store (token stored as a digest, 12h TTL, nothing on disk); `HttpOnly`/`SameSite=Lax`/`Secure`-when-https cookies scoped to `/ui`; per-session synchronizer token compared in constant time; `Sec-Fetch-Site` check; no `next` parameter and no reflected text (open redirect / injection) | server/uisession.go, uihandlers.go uiPost |
| **Soft block** (`blocked` on the machine, stored in the database so it survives a restart): every server→agent command path refuses — one-shot exec and the streaming relay's `exec_stream`, `stream_stdin` **and** `stream_kill` — with the refusal audited; live console sessions for the machine are torn down | server/machineadmin.go dispatchRefusal, stream.go |
| **Non-reserving delete**: removes the machine row and its key, tells a connected agent to retire (so it exits rather than reconnecting), and keeps the audit trail; ordering is delete-then-notify so a failed notice cannot leave a live authenticated socket for a row that is gone | server/machineadmin.go deleteMachine, store.DeleteMachine |
| **Org management**: orgs stored in the database with `MACH_ORG`/`MACH_ORGS` as a non-removable pin; an org with machines cannot be removed; adding one is validated by the same label rule the naming invariant uses | server/orgadmin.go, orgs.go, store.ValidOrgLabel |
| The API-key listing the membership view renders has no field for `salt`, `key_lookup` or `key_hash` — the absent fields, not a promise, are what stops a leak | store.ListAPIKeys, org_test.go |
| **Agent supervision restarts on failure, not on any exit**, so exit 0 means stop: a retirement actually retires, and the update path's detached replacement is not raced by a resurrected old image | agent/install.go systemdUnit, launchdPlist |
| Hourly pairing cleanup (24h retention) | server.New goroutine |

## Command policy: where it is enforced, and what it can promise

Two layers, one grammar (`internal/policy`), so a rule means the same thing
wherever it is written. Both layers are evaluated on **both** command paths —
one-shot `exec` and the streaming console — because a block list that only
covers one of them is a suggestion.

1. **On the machine** — `MACH_POLICY` or `<state>/policy.txt`, read by the
   agent process. Nothing upstream can override it: not a compromised control
   plane, not a stolen API key, not a bad console. This is the layer that
   protects the machine from the people who control the fleet. It is the only
   layer that survives a sealed command, since it runs where the command is
   decrypted.
2. **On the control plane** — `MACH_EXEC_POLICY` (inline) or
   `MACH_EXEC_POLICY_FILE` (a file, re-read on mtime change every 15s, so
   editing it does not need a restart). Enforced in `handleExec` and in the
   relay's `exec_stream` path, after the caller is authorized and before
   anything is dispatched, for every key, every scope, and every machine. This
   is the layer that answers "block this command across the whole fleet". A
   blocked attempt is audited with exit code 126 rather than silently dropped.
   Because it matches text, it cannot judge a sealed command — which is why
   sealing is refused while this layer is configured (see "Trust model").

The fleet-wide rules are **also mirrored onto every machine** and evaluated
there, because that is the only place a sealed command's text exists: a control
plane that cannot read a command cannot apply a text-matching rule to it. The
ruleset is pushed when an agent connects and again on every change (a runtime
`SetExecPolicy`, or an edit to `MACH_EXEC_POLICY_FILE`, which is re-read on mtime
change), and the agent acknowledges the version it is enforcing. Two
consequences worth knowing:

- **The rules now run in two places**: the control plane checks every plaintext
  command before dispatch (and can audit a refusal with the rule named even
  though it never dispatches anything), and the machine checks everything it is
  asked to run, sealed or not. Both refuse with exit code 126.
- **What the control plane sends cannot loosen what the machine owner wrote.**
  Both layers are evaluated and a refusal from either stands; the local rules are
  not replaced, appended to, or overridable, and an empty fleet ruleset is not a
  way past them. The refusal says which layer refused, because the two rule sets
  usually have different authors.

Grammar: `deny:<substring>`, `allowonly`, `allow:<prefix>`, matched against
whitespace-normalized text so `r''m` and `r${IFS}m` do not slip past a
`deny:rm` rule. Shell-mode commands are split on separators and every segment
must satisfy the allowlist independently; argv (`--`) mode is never split,
because an argument list is one command and a semicolon inside an argument is
a character, not a boundary.

**This is a block list for mistakes and policy violations, not a confinement
boundary.** It matches text. Text can be obfuscated in ways a normalizer
cannot enumerate (`$(printf ...)`, base64 through a second program, a program
that does the dangerous thing itself), and no amount of pattern work fixes
that. Use OS-level confinement — containers, systemd sandboxing, SELinux/AppArmor,
network policy — when the threat is a determined attacker rather than an
operator, a script, or an LLM that reached for the wrong command. Do not read
the rules above as anything more than a seatbelt.

A configured `MACH_EXEC_POLICY_FILE` that cannot be read at startup is
**fatal**: a control plane that boots with its block list silently missing is
worse than one that refuses to start, because the operator cannot tell the
difference. A file that becomes unreadable later keeps the last good rules.

## Streaming, and what a machine's output can and cannot do

Two command paths, and they are different on purpose.

**One-shot (`mach exec`)**: the agent runs the command, buffers the output, and
returns a single `ExecResult` — exit code, stdout, stderr. Being one object in
each direction is what makes it sealable, and it is the path that carries the
8 MiB cap. The console prints the machine's bytes to stdout and its own
diagnostics to stderr with a `mach: ` prefix; `--json` prints that one result
object instead, so a program reads the exit status as a field rather than
parsing it out of bytes a command printed.

**Streaming (`mach console`)**: the console opens
`/v1/console/stream` WebSocket, the control plane binds it to the target
machine's agent connection, and frames relay in both directions —
`exec_stream` in, `stream_out` (agent output, chunked at 32 KiB) back,
`stream_stdin` and `stream_kill` for input and Ctrl-C, and a terminal
`stream_end` carrying the exit status. Failures after dispatch (the agent's
error, a timeout, an agent connection lost) are reported *inside* the stream as
that terminal record, never as an HTTP status: after the socket upgrade there
is no status line left to use. The relay keeps an audit row per command, so
streaming is not a hole in the record.

Three properties follow from how the frames are carried, and all three are
load bearing:

- **Output cannot forge a control fact.** Output travels as base64 inside a
  typed frame (`stream`, `b64`). A command that prints an entire exit record, a
  `mach: ` line, a fake prompt, or a frame of its own gets those characters
  copied to the console as output and nothing else happens: the exit status is
  a typed field on the terminal record, set from the process's real exit code.
  Tested directly (`internal/console/client_test.go
  TestOutputCannotForgeControlFacts`).
- **A stream that dies is not success.** If the relay disappears without a
  terminal record, the console does not report 0 and does not replay the
  command: it prints that the command may still be running and exits with a
  distinct status. Only a stream that was never reached is retryable. The
  command already ran on the machine; re-running it because the *relay* failed
  would be a second execution nobody asked for.
- **Nothing in the agent reads output back.** The agent executes; it does not
  interpret. The only things it acts on are frames from the control plane, and
  a frame is only accepted after the pinned-key check in `dialAndServe`. A
  command whose output mimics a mach message, a protocol frame, or a new
  command is a command that printed text — it is not prompt injection and it
  is not a command channel, because there is no path from output back into
  anything the agent does. The console applies the same rule in the other
  direction: it prints whatever arrives and takes its own view of the outcome
  from typed fields only.

**Stdin is a second input path, and that is a deliberate trade.** A streaming
session can feed a running command (`stream_stdin`, used by `mach console`) and
kill it (Ctrl-C → `stream_kill`). Stdin only reaches a machine through a
command the control plane already asked for, but it does mean the text-matching
policy judges the command as launched and cannot judge what is typed into it
afterwards. There is no honest way to match a byte stream against a block list;
a rule that appeared to would be worse than saying so. If that matters, keep
`mach console` out of the fleet's hands: `exec:*` scoping and the `readonly`
refusal are the levers, and the agent's own `MACH_POLICY` still governs the
command itself.

Note that a machine can print `mach: something` to its stdout. The prefix
distinguishes mach's own diagnostics from the machine's output on the stream,
but a human reading a terminal cannot tell them apart by content alone — that
ambiguity is inherent to showing a remote machine's bytes to a person.

Limits: the buffered path truncates at 8 MiB with a visible marker. A streamed
session is uncapped; the relay drops frames rather than stalling an agent whose
console has stopped reading, because that frame pump serves every other command
on the connection. Neither truncation nor a drop is recoverable, and both are
visible rather than silent.

## Updates and release attestations

Agents apply an update only after verifying a manifest signed by the pinned
control-plane key over `version|sha256`, and only if the payload's sha256
matches. That is what protects the wire.

What it does not establish is where the binary came from. So each released
agent binary gets an **in-toto attestation**: a Statement v1 naming the
artifact by sha256, carrying a predicate that records the toolchain version,
GOOS/GOARCH, CGO setting, build flags, the module graph (read out of the
binary by Go's linker, with each module's `go.sum` hash) and the VCS revision
with a dirty-tree flag. It is wrapped in a DSSE envelope signed by the same
control-plane identity key, so any DSSE-aware tool can check it, and
`mach-server push-update --attestation` refuses to queue a binary the
attestation does not describe, or one built from a modified tree.

The attestation is a release-pipeline and audit control, not a runtime one:
agents do not receive or check it. That is deliberate — verifying it onboard
would duplicate what the pinned-key manifest signature already does, at the
cost of shipping the statement over the wire. The two are complementary: the
signature protects delivery, the attestation records provenance.

## Known gaps (pre-1.0 — do not treat as closed)

1. **The command policy is a string guard, not a sandbox** — see the section
   above for exactly what it can and cannot promise, including its blindness to
   what is typed into a streaming session's stdin. Use OS-level confinement for
   real isolation.
2. **Single control plane** = availability + integrity SPOF. Signed updates
   prevent code injection, but a malicious DB can still push any correctly
   signed binary, and an operator with DB access can read the audit log. There
   is no multi-server or HA story yet (issue #5).
3. **Streaming is plaintext, and there is no PTY.** `mach console` has stdin
   and Ctrl-C but no echo/line discipline, so full-screen TUI programs still
   need a real PTY (issue #3). `mach exec` can be sealed but cannot feed input.
   The two properties are in tension by construction: sealing needs the whole
   command and result at once, a live session is neither.
4. **Output caps are per-path and lossy at the edges**: a buffered command
   producing more than 8 MiB loses the tail; a slow console loses streamed
   frames. Both are marked visibly, but they are not recoverable.
5. **The control plane hands out the key the seal uses**, so it can substitute one
   before a console has ever sealed to a machine. Trust-on-first-use pinning makes
   a later substitution loud and one-shot, not impossible (see "Trust model"), and
   nothing here is a key-transparency mechanism. A console that has never sealed
   to a machine has no protection at all.
6. **Rate limiting is per-IP and in-memory**: a restart clears the counters,
   and a distributed source is not one IP. The pairing and enrollment paths
   are single indexed lookups, so the amplification that would have justified
   tighter limits is gone; the limits that remain are there to slow scanning.
7. **The fleet-wide block list applies to sealed commands by running on the
   machine, and that has a residue worth naming.** The rules have to travel to
   the agent and be evaluated there, which means: an agent that has not yet
   received them (it is connecting, or the control plane is mid-change) enforces
   whatever it held before; the rules are only as trustworthy as the control
   plane that sends them, which could in principle send none — that is why the
   machine's own `MACH_POLICY` remains the layer that holds against a hostile
   control plane, and it is still the only one that does; and a refusal on this
   path is audited by the control plane as `[E2E sealed command]` with exit 126,
   so the rule that refused it is visible to the console but not to the audit
   log (which cannot read what it cannot decrypt). The agent acknowledges the
   ruleset version it holds, so "which machines have the current rules" is
   answerable rather than assumed.
8. **The copies of the agent binaries baked into the container image are not
   attested** by `push-update --attestation`, which covers runtime pushes only
   (issue #4).
9. **The web UI's only gate is the identity provider.** Block is fleet-wide and
   delete is irreversible, so anyone who can obtain an identity the configured
   issuer verifies can do both. With a public issuer that permits
   self-registration, that is the internet. The honest calibration: the CLI's
   `mach-server delete-machine` already grants equivalent power **with no
   authentication at all** to anyone with a shell on the control-plane host, so
   the UI extends an existing authority rather than inventing one — but
   **adding an org is a new capability with no CLI equivalent**, since it makes a
   prefix enrollable. `MACH_OIDC_ALLOWED_DOMAINS` is the knob; with it unset, the
   issuer's registration policy *is* the authorization model, and the control
   plane says so at startup rather than leaving it to be discovered.
10. **The UI relaxes the CSP on two pages, and that is a real widening.**
    `/ui/*` and the public enrollment page need `script-src 'self'` for the
    vendored htmx and the copy button. No `'unsafe-eval'` and no inline script:
    htmx's `Function()` call sites are reachable only through `hx-on:` and
    JS-valued `hx-vals`, which these templates never use, and `form-action
    'self'` is required because `default-src 'none'` falls back to it. The pair
    page keeps its strict `default-src 'none'` — it is the page a phone reaches
    from a QR code and it needs no script. The enrollment page is
    unauthenticated, so this is the one place the widening touches an anonymous
    visitor.
11. **Block is a freeze on dispatch, not containment.** A blocked machine is
    still connected and still running whatever already executes on that host; it
    is sent no *new* commands. An in-flight exec is not cancelled, and an
    interactive session's command keeps running when the session is torn down —
    that is the existing "a command is not cancelled by the console going away"
    rule, and synthesising a `stream_kill` here would be a new remote-kill
    capability rather than a freeze. Use OS-level confinement for real isolation.
12. **UI sessions are in-memory**, so a control-plane restart signs every
    operator out. That is the safe direction — no part of UI authorization is on
    disk, so a leaked database grants no UI access — but it is worth knowing
    before someone reports it as a bug.
13. **A delete cannot be delivered to an agent that is offline, and the two
    cases are deliberately indistinguishable.** An agent that restarts after its
    machine was deleted dials a name that no longer exists, which the control
    plane answers exactly as it answers a typo — upgrade, close, no frame — to
    keep the unauthenticated endpoint free of a name-enumeration oracle. So it
    retries on backoff until it is stopped on the host. Harmless (it holds no
    privilege), not graceful, and the UI says so on the confirmation page.
14. **The CLI admin commands do not touch live connections.** `mach-server
    revoke-machine` and `delete-machine` open their own store in a separate
    process and write the flag; only the HTTP paths — the console API
    (`/v1/admin/*`) and the UI — also terminate the socket and end live sessions.
    So a machine revoked from the CLI keeps accepting commands until it next
    reconnects. There is no `block-machine` subcommand: blocking is reachable
    over HTTP and from the UI, and a CLI version would have the same gap.
15. **Revocation is recoverable, so there is no permanent ban.** A revoked
    machine comes back through a fresh enrollment, which is operator-gated (an
    `enroll`-scoped key, or a phone approval with the challenge code) but does
    mean anyone who can enroll can also un-revoke. The property revocation still
    holds is the one that matters for day-to-day safety: **it cannot be used to
    take over an active machine**, since only a revoked row may be revived.
    Deleting is not a ban either — it frees the name precisely so a re-imaged box
    can enroll. A true ban means removing the enrollment paths themselves (revoke
    the enroll keys, or drop the org). Say this plainly rather than implying
    `revoke` is permanent.
16. **A temporary session leaves its enrollment behind, on purpose.** The row is
    the record — a connection needs one — so a host that ran plain `mach` stays
    enrolled, holding its name. It is recorded as *temporary*, which is what lets
    the next run take that name straight back over with no operator action, and
    that matters most in the case that has no tidy path: a session killed
    outright, or cut off before it can retire itself. Nothing else about the host
    persists: no key, no config, no E2E key on disk.
17. **A temporary machine can retire itself; a permanent one cannot.** The
    `retire` frame is scoped to the connection's own machine, so it grants an
    agent power over itself and nothing else — and it is refused outright for a
    permanent enrollment, so a compromised permanent agent cannot retire the
    machine it runs on. The one thing it can do is remove itself from the fleet,
    which is visible (the row shows revoked) and recoverable (re-enroll).

## Deployment checklist

- [ ] Control plane behind TLS reverse proxy; `MACH_TRUST_PROXY=1`.
- [ ] `MACH_ORG` set to your org; `MACH_ORGS` lists every approvable org.
- [ ] `MACH_EXEC_POLICY` (or `_FILE`) set to the fleet-wide block list, and
      each agent's own `MACH_POLICY` set for what that machine must never run.
- [ ] Decide the E2E setting per org (`mach-server e2e`), with the trade in
      mind: sealing off means the block list can read commands; sealing on means
      the one-shot path is opaque to the control plane and the fleet rules are
      enforced on the machine instead. `MACH_E2E` pins it deployment-wide if a
      container spec should win over a runtime change.
- [ ] On each console, the first sealed command to a machine pins its key
      (`mach trust` lists what is pinned). Treat a "key changed" refusal as an
      incident question, not a nuisance: `mach trust <machine>` accepts the new
      key, and it is the only thing that does.
- API keys minted per consumer with least scope (enroll keys only where
  enrollment happens; per-machine allowlists for consoles; `readonly` for
  dashboards and monitoring).
- `bin/mach-server` bound to loopback only (compose default).
- Agent binaries attested (`mach-server attest`) and the `.intoto.jsonl` kept
  with the artifacts; `push-update --attestation` used so nothing unattested
  ships.
- Regular `mach audit` reviews; revoke machines on decommission with
  `--purge-audit` if their output contained secrets (though inserts are
  already redacted).
