# SECURITY-NOTES.md — mach security model and threat notes

Audience: operators and security reviewers. Read before exposing the
control plane beyond a household.

## Trust model

```
phone ──TLS──▶ control plane ◀──TLS(wss)── agents (outbound only)
                 ▲
console (mach) ──┘ (TLS, bearer key)
```

- The control plane is the **only public component** and the **single
  point of command authority**: it brokers exec, holds the audit log, and
  can read command content. Treat its host as high-value; access to its
  DB = control of every machine.
- Agents trust exactly: (a) their pinned control-plane identity key
  (`server_key` in config.json), (b) TLS to the enrolled URL.
- The phone/admin is trusted only after presenting the challenge code
  that was printed on the agent's console (12 chars, ~60 bits) — the QR
  token alone grants nothing.

There is no application-layer end-to-end encryption between the console and
the agent, and none is planned. The control plane is a broker that must see
what it brokers (that is what the audit log is), so encrypting content past it
would mean either a second key distribution problem or an audit trail that
records nothing. The honest statement is the one above: the control plane is
trusted, and TLS protects the wire.

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
| **Fleet-wide command block list** (`MACH_EXEC_POLICY` / `MACH_EXEC_POLICY_FILE`), enforced for every key, scope and machine before dispatch | server/policy.go, consoleapi.go handleExec |
| Per-machine command policy on the agent itself (`MACH_POLICY` / `policy.txt`), evaluated where no upstream can override it | agent/policy.go, internal/policy |
| Streaming output with per-stream caps (8 MiB) and visible truncation markers | agent/stream.go, protocol.ExecStreamFrame |
| Machine output is data, never input: the agent decides nothing from it, and the console labels it rather than parsing it | agent/run.go, console/client.go |
| Audit log with secret-value redaction; refusal of a blocked command is audited too; optional purge on revoke | store.RedactScrubs/AuditInsert/RemoveMachineAudit |
| Signed in-toto attestations for released agent binaries, verified before an update can be queued | internal/release, controlplane/attest.go |
| Revocation: self-retiring agents, revoked keys can't re-enroll, names stay reserved | store.RevokeMachine, agent errRevoked |
| Agent privilege drop on linux root (MACH_USER, default nobody) | agent/droppriv_linux.go |
| X-Forwarded-For honored only with MACH_TRUST_PROXY=1 | server.New + SetTrustProxy |
| Pair-page security headers (CSP default-src 'none', XFO DENY, nosniff, no-referrer); cross-site POST refused | pairpages.go |
| Hourly pairing cleanup (24h retention) | server.New goroutine |

## Command policy: where it is enforced, and what it can promise

Two layers, one grammar (`internal/policy`), so a rule means the same thing
wherever it is written.

1. **On the machine** — `MACH_POLICY` or `<state>/policy.txt`, read by the
   agent process. Nothing upstream can override it: not a compromised control
   plane, not a stolen API key, not a bad console. This is the layer that
   protects the machine from the people who control the fleet.
2. **On the control plane** — `MACH_EXEC_POLICY` (inline) or
   `MACH_EXEC_POLICY_FILE` (a file, re-read on mtime change every 15s, so
   editing it does not need a restart). Enforced in `handleExec` after the
   caller is authorized and before anything is dispatched, for every key,
   every scope, and every machine. This is the layer that answers "block this
   command across the whole fleet". A blocked attempt is audited with exit
   code 126 rather than silently dropped.

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

Commands stream: output is chunked to the console as the process writes it
(8 KiB or 100 ms, whichever comes first), one JSON object per line over
chunked HTTP, ending with an exit record. The response status is committed at
200 as soon as output starts, so failures after dispatch — the agent's error,
a timeout — are reported *inside* the stream; a client learns how the command
ended from the exit record, never from the status line.

Two properties follow from how the bytes are carried, and both are load
bearing:

- **Output cannot forge a control fact.** Chunks travel as base64 inside a
  typed frame (`stream`, `data_b64`). A command that prints an entire exit
  record, a `mach: ` line, a fake prompt, or a chunk frame of its own gets
  those characters copied to the console as output and nothing else happens:
  the exit status is a typed field on its own frame, set from the process's
  real exit code. This is tested directly
  (`internal/console/client_test.go TestOutputCannotForgeControlFacts`).
- **Nothing in the agent reads output back.** The agent executes; it does not
  interpret. The only things it acts on are frames from the control plane, and
  a frame is only accepted after the pinned-key check in `dialAndServe`. A
  command whose output mimics a mach message, a protocol frame, or a new
  command is a command that printed text — it is not prompt injection and it
  is not a command channel, because there is no path from output back into
  anything the agent does.

On the console side, `mach`'s own diagnostics go to **stderr** with a `mach: `
prefix, and machine output goes to **stdout** unmodified. `mach exec --json`
emits the labeled frames unchanged for programs, so a script reads the exit
status as a field rather than parsing it out of text. Note that a machine can
still print `mach: something` to its stdout — the prefix distinguishes mach's
own messages from the machine's, but only on the stream, not by content alone.

Limits: 8 MiB per stream, after which output is truncated and a marker is
appended. If the console stops reading, the server's buffer (512 chunks, ~4 MiB)
fills and further chunks are dropped rather than blocking the agent's frame
pump — that pump serves every other command on the connection — and the
console is told the output was dropped.

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
   above for exactly what it can and cannot promise. Use OS-level confinement
   for real isolation.
2. **Single control plane** = availability + integrity SPOF. Signed updates
   prevent code injection, but a malicious DB can still push any correctly
   signed binary, and an operator with DB access can read the audit log.
3. **No stdin, no PTY.** `mach exec` streams output but cannot feed input, so
   interactive and TUI programs do not work; `mach console` is line-based.
   Streaming is one-directional by design — a stdin channel would add a second
   way for input to reach a machine, and the current model has exactly one:
   a command the control plane asked for.
4. **Output caps are per-stream and lossy at the edges**: a command producing
   more than 8 MiB loses the tail, and a slow console can cause drops. Both
   are marked visibly, but they are not recoverable.
5. **Rate limiting is per-IP and in-memory**: a restart clears the counters,
   and a distributed source is not one IP. The pairing and enrollment paths
   are single indexed lookups, so the amplification that would have justified
   tighter limits is gone; the limits that remain are there to slow scanning.

## Deployment checklist

- [ ] Control plane behind TLS reverse proxy; `MACH_TRUST_PROXY=1`.
- [ ] `MACH_ORG` set to your org; `MACH_ORGS` lists every approvable org.
- [ ] `MACH_EXEC_POLICY` (or `_FILE`) set to the fleet-wide block list, and
      each agent's own `MACH_POLICY` set for what that machine must never run.
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
