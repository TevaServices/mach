# packaging/ — artifacts and tools for the distribution pipeline

Layout:

- `systemd/machd.service` — the unit the deb/rpm packages install
  (`/usr/lib/systemd/system/machd.service`, the merged-usr path modern
  Debian/Ubuntu packages ship; a `/lib` symlink alias resolves it on
  older releases). `Restart=on-failure`, `User=mach`,
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
  `mach.exe`, installs and starts the `machd` Windows service
  (ServiceInstall/ServiceControl — LocalSystem, auto start, SCM
  restart-on-failure via the `sc failure` step; `mach service` is the binary's
  SCM entry point).
- `winget/` — the winget manifest template + submission runbook (#43).

## Windows: the machd service (worth knowing)

The MSI installs a real **Windows service**, registered by msiexec's own
ServiceInstall/ServiceControl tables — no task scheduler and no custom-action
command lines. History for why (#54): the original authoring drove schtasks
through deferred exe custom actions, and the v0.9.0, v0.10.0 and v0.11.0
releases all died validating their first real install under three stacking
authoring bugs — an unterminated condition quote (`Condition="REMOVE~=&quot;ALL`
ships the literal `REMOVE~="ALL`), a nested-quote `/TR ""path" run"` idiom that
msiexec's command-line re-tokenization mangles, and `/RI` refused outright for
ONLOGON-style triggers ("The options /RI, /DU, /ST, /SD, /ET, /ED and /K are
not applicable for the scheduled types: ONSTART, ONLOGON, ONIDLE, ONEVENT").
A service registration in the tables answers the same requirements with
none of those hazards.

The supervision contract on Windows:

- The service is `LocalSystem`, `AUTO_START`, own process, started by the
  installer and at every boot.
- **Restart on failure only**: the package configures the SCM's failure
  actions (`sc failure machd reset= 86400 actions= restart/5000/…`, three
  restarts, re-armed after a stable day) — the parity of the systemd unit's
  `Restart=on-failure`/`RestartSec=5`. Exit 0 stays stopped, so a revoked or
  deleted machine's agent actually retires (invariant 22).
- **An unenrolled service waits for enrollment instead of exiting.** The
  Linux packages dodge the same problem differently (enable-never-start,
  because an unenrolled machd crash-loops under Restart=on-failure); the
  Windows service is started by the installer and at boot, so exiting there
  would fail the install itself (msiexec 1920, observed) and turn every boot
  into a restart loop. The service sits RUNNING with no credentials loaded,
  polls its state dir every 30s, and serves the moment the machine is
  enrolled — no manual `sc start machd` after the fact.
- **State dir:** the service runs as LocalSystem, so `StateDir()` resolves to
  `C:\Windows\System32\config\systemprofile\.mach` — a directory that is
  SYSTEM+Administrators-only by inheritance. Enrollment (elevated PowerShell)
  points at it through `$env:MACH_STATE_DIR` or `--state-dir`; see the README
  enrollment snippet.
- **Updates are the distribution points'** (winget upgrade, or install the
  next MSI — MajorUpgrade removes the old product first, service included,
  then re-registers this one). The MSI never replaces a running binary by
  hand.

A stopped-but-enrolled machine (revoked, or a clean stop) re-serves on
`sc start machd`; a deleted machine must re-enroll first, then start.