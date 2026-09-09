# mach

Remote CLI access to registered machines — quick interactive troubleshooting
plus long-running named access — with **zero inbound firewall holes or port
forwards** on target machines. Every target only ever makes *outbound*
connections; the control plane is the only publicly reachable component.

```
┌──────────┐  outbound   ┌───────────────┐  outbound   ┌──────────┐
│  machd   │◄──WebSocket──│ control plane │◄──WebSocket──│  machd   │   targets (no open ports)
│ (target) │              │    (Docker)   │              │ (target) │
└──────────┘              └───────▲───────┘              └──────────┘
                                  │ HTTPS (REST + pair pages)
                          ┌───────┴───────┐
                          │  mach CLI     │   you / the LLM troubleshooter
                          └───────────────┘
```

## Components (one codebase, three binaries)

| Binary | Runs where | Purpose |
|---|---|---|
| `machd` | target machines | Enrollment (QR or API key), outbound-only daemon, executes commands, systemd install for the long-running mode |
| `mach` | anywhere | Console: `list`, `exec`, `console`, `audit` |
| `machctl` | control plane host | `serve` (control plane), `add-api-key`, `remove-machine` |

## Enrollment

**QR (interactive, WhatsApp-Web-style):** on the new machine run
`machd register --server https://mach.example.com`. It prints a QR whose URL
points at the **control plane** (the phone never needs to reach the agent),
plus a challenge code *not* embedded in the QR. Scan, compare codes, approve,
name the machine — the agent finishes enrollment over its own outbound
connection.

**API key (headless):** `machd register --server https://… --api-key KEY --name web-01`.
Create keys with `machctl add-api-key`.

## Running the control plane (Docker)

```bash
MACH_PUBLIC_URL=https://mach.example.com docker compose up -d --build
# create a console/agent API key
MACH_PUBLIC_URL=... docker compose run --rm mach add-api-key hermes-console "$KEY"
```

Put Caddy/nginx in front for TLS (the agent speaks wss://). State lives in
`./data/mach.db` (SQLite: machines, keys, pairings, full command audit log).

## Console

`~/.mach/console.json`:
```json
{"server": "https://mach.example.com", "api_key": "…"}
```

```bash
mach list                          # fleet status
mach exec web-01 "journalctl -u nginx --since -1h | tail -50"
mach console web-01                # interactive
mach audit web-01 100              # who ran what, when, with which exit code
```

`mach exec` exits with the remote command's exit code — scriptable, and the
primary interface for an LLM troubleshooter driving the fleet.

## Security posture (v1)

- Agents hold only their own Ed25519 identity (no shared master secret);
  hellos are signed with a ±5-minute replay window.
- Pairing tokens are single-use, ~10-minute TTL; pair-start is rate-limited
  and grants nothing until phone approval + challenge-code match.
- Every command is audit-logged (machine, timestamp, command, source key,
  exit code, output snippets) in the control plane's SQLite.
- Control plane binds to loopback by default; expose only via your TLS proxy.

### Known limitations (pre-1.0, honest list)

- WebSocket messages from console→agent are not yet end-to-end encrypted at
  the application layer — the control plane can read command content. (TLS
  protects the wire; per-machine E2E encryption is the obvious v1.1 item.)
- No per-machine command allow/deny policies yet.
- `mach console` is line-based, not a PTY (no TUI apps / streaming).
- SQLite = single-writer; fine for a household fleet, not a datacenter.

## Build

Any host with Docker (no Go needed): `docker build -t mach .` — binaries are
built in-stage; the control-plane image ships all three. To cross-compile
agent binaries for other machines: `docker run --rm -v "$PWD:/src" -w /src
golang:1.24-alpine sh -c "go build -o machd-linux-amd64 ./cmd/machd" ` with
`GOOS/GOARCH` env set as needed.