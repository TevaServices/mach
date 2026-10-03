# winget manifests (TevaServices.mach) — what lives here and why

The winget manifests for `winget install TevaServices.mach` are generated
AT RELEASE TIME from templates (like the Homebrew formula), because two of
their fields are release-artifact values: the InstallerUrl (the release
download) and InstallerSha256 (the MSI's hash, written by release.yml's msi
job as `mach-exe-sha256-*.txt` / computed over the MSI itself).

- `TevaServices.mach.yaml.tmpl` — the version manifest
- `TevaServices.mach.installer.yaml.tmpl` — the installer manifest
- `TevaServices.mach.locale.en-US.yaml.tmpl` — the default locale manifest

scripts/winget-gen.sh renders them into dist/winget/ at release time;
SUBMISSION to microsoft/winget-pkgs is a manual step (see the runbook
below) — a PR to a microsoft repo is a human review process, and the
manifests must be submitted from a fork with the real version folder.

## Submission runbook (once the first signed or unsigned MSI is wanted in winget)

1. Fork microsoft/winget-pkgs with a human account (bots cannot open PRs
   there; the repo requires a human-linked submission).
2. `wingetcreate new <msi-url>` (on Windows) scaffolds the three manifests;
   or render ours and copy them into
   `manifests/T/Tevaservices/mach/<version>/`.
3. Validate locally: `winget validate`.
4. Open the PR. The automated pipeline runs `winget validate` + SmartScreen
   scanning on the installer; unsigned installers are accepted for
   packages without a signing certificate today, but the PR is flagged for
   manual moderator review — expect that round to take days, and possibly a
   request for a signed binary. If signing is added later, update
   InstallerUrl/InstallerSha256 in a new version folder and resubmit.
5. After merge: `winget install TevaServices.mach` resolves.

## Why the MSI, and what it registers

The MSI (packaging/wix/mach.wxs) installs `mach.exe` per-machine and
registers the `machd` scheduled task: ONLOGON trigger, run level HIGHEST,
restart interval 1 minute (see packaging/README.md's schtasks caveat for
what /RI can and cannot promise), matching the Linux packages'
enable-not-start contract: the agent will not be started by the installer
when it has no enrollment; on first logon after enrollment it runs (`mach
run` under the task); enrollment on Windows: run `mach` from a terminal
after install.