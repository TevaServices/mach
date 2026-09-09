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
  (until E2E lands) can read command content. Treat its host as
  high-value; access to its DB = control of every machine.
- Agents trust exactly: (a) their pinned control-plane identity key
  (`server_key` in config.json), (b) TLS to the enrolled URL.
- The phone/admin is trusted only after presenting the challenge code
  that was printed on the agent's console (12 chars, ~60 bits) — the QR
  token alone grants nothing.

## Controls implemented (v0.2)

| Control | Where |
|---|---|
| Per-connection challenge-bound agent hello (replay-proof) | server/agent.go, agent/run.go |
| Control-plane identity key persisted & pinned by agents; signed update manifests (sig over version\|sha256) | server/serverkey.go, agent/run.go handleUpdate |
| Pairing tokens: 256-bit, single-use, ~10 min TTL | store.CreatePairing |
| Challenge codes: 12 chars, agent-console-only, typed blind on phone; 5 wrong attempts expire the pairing | store.NewChallengeCode, server/pairpages.go |
| Pair-start rate limit (5 per IP / 10 min) and auth-failure rate limit (20 / 10 min) | server.go, consoleapi.go |
| Org-prefixed machine names, no hostname-derived suggestions, conflicts error | store.ValidOrgName, server/orgs.go, pairpages.go |
| Scoped API keys (enroll / readonly / exec:* / exec:m1\|m2), server-generated 192-bit secrets, stretched salted hashes | controlplane.AddAPIKey, store |
| Output caps (8 MiB/stream) with truncation markers | agent/run.go cappedBuffer |
| Audit log with secret-value redaction; optional purge on revoke | store.RedactScrubs/AuditInsert/RemoveMachineAudit |
| Revocation: self-retiring agents, revoked keys can't re-enroll, names stay reserved | store.RevokeMachine, agent errRevoked |
| Agent privilege drop on linux root (MACH_USER, default nobody) | agent/droppriv_linux.go |
| Per-command policy: deny: / allowonly / allow: (whitespace-normalized matching) | agent/policy.go |
| X-Forwarded-For honored only with MACH_TRUST_PROXY=1 | server.New + SetTrustProxy |
| Pair-page security headers (CSP default-src 'none', XFO DENY, nosniff, no-referrer) | pairpages.go |
| Hourly pairing cleanup (24h retention) | server.New goroutine |

## Known gaps (pre-1.0 — do not treat as closed)

1. **No app-layer E2E encryption**: the control plane can read command
   content and output. TLS protects the wire only. Mitigation until E2E:
   treat the control plane host as trusted/high-value.
2. **Policy is a foot-guard, not a sandbox**: substring matching is
   bypassable by creative commands; use OS-level confinement for real
   isolation.
3. **Single control plane** = availability + integrity SPOF (signed
   updates prevent code injection, but a malicious DB can still push
   any *correctly signed* binary).
4. `mach console` is line-based, no PTY; `mach exec` buffers output
   (capped) rather than streaming.
5. No signed releases / reproducible-build manifest for the agent
   binaries shipped in the container image.

## Deployment checklist

- [ ] Control plane behind TLS reverse proxy; `MACH_TRUST_PROXY=1`.
- [ ] `MACH_ORG` set to your org; `MACH_ORGS` lists every approvable org.
- API keys minted per consumer with least scope (enroll keys only where
  enrollment happens; per-machine allowlists for consoles).
- `bin/mach-server` bound to loopback only (compose default).
- Regular `mach audit` reviews; revoke machines on decommission with
  `--purge-audit` if their output contained secrets (though inserts are
  already redacted).