# packaging/ — artifacts and tools for the distribution pipeline

Layout:

- `systemd/machd.service` — the unit the deb/rpm packages install
  (`/lib/systemd/system/machd.service`). `Restart=on-failure`, `User=mach`,
  `Environment=MACH_STATE_DIR=/var/lib/mach` — the supervision contract the
  binary used to generate under `mach install` (#44 removed it; AGENTS.md
  invariant 22 — exit 0 means stop).
- `openrc/machd` — OpenRC init script the apk installs
  (`/etc/init.d/machd`). Alpine has no systemd. Deliberately
  **unsupervised** (`command_background="yes"`, no supervise-daemon): an
  unsupervised crashed agent stays down, while a supervised one would also
  respawn a deliberately-retired agent (exit 0 = stop).
- `nfpm/<format>/…` — maintainer scripts per format (create the `mach`
  system account, set up `/var/lib/mach` 0700, enable — never start — the
  service: an unenrolled machd would crash-loop, enrollment is a person at
  the machine).
- `goreleaser/attest-hook.sh` — goreleaser per-target post build hook:
  attests each built binary, refuses a WARNING (dirty tree / no VCS rev).
- `homebrew/mach.rb.tmpl` — the tap formula TEMPLATE; rendered per release
  by `scripts/brew-bump.sh` (URLs + sha256s from goreleaser's checksums).
- `wix/mach.wxs` — the Windows MSI definition (#43): per-machine install of
  `mach.exe`, registers the `machd` Task Scheduler job (ONLOGON, /RL
  HIGHEST, /RI 1).
- `winget/` — the winget manifest template + submission runbook (#43).

## The schtasks restart caveat (worth knowing)

The issue's design asks for `schtasks /RI 1` — "restart every 1 minute on
failure". Two schtasks facts shape what the MSI can honestly deliver:

1. `/RI` (repeat interval) requires `/SC ONLOGON` tasks to also be
   duration-limited; more importantly, **`/RI` re-RUNS the task on its
   schedule — it does not watch the task and restart a failed instance**
   (that is `/RI` + `/K` semantics for long-running applications, which
   does not apply to a task whose single instance is still running).
2. The honest supervision on Windows for "restart on failure, not on clean
   exit" is the task's `<FailureActions>` — settable only via XML/Scheduled
   Task Module, not schtasks CLI flags.

The MSI therefore registers the task with ONLOGON + HIGHEST + the mach
binary, and the /RI 1 flag is included exactly as the issue asks; the
"restart on failure only" semantic depends on the agent's own exit codes
(exit 0 = stop). This is documented here as a known Windows-serviceable
limitation, matching the Linux packages' enable-not-start contract.
If harder enforcement is wanted, a follow-up can replace the schtasks
CustomAction with a Scheduled Task XML file installed by the MSI —
the FailureActions block gives exact failure-only restarts.