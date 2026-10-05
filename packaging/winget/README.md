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
4. Open the PR. The automated pipeline validates the manifest and runs
   install/uninstall testing; per the repository policies (learn.microsoft.com:
   windows/package-manager/package/windows-package-manager-policies), a
   code-signing certificate is NOT a submission requirement — policy 1.2
   bans malware per Microsoft's PUA criteria, not unsigned binaries. What
   IS required: the InstallerUrl must be the ISV's own release location
   (our GitHub Releases URL qualifies — no redirectors), silent
   install/uninstall must work, and every submission passes multi-engine
   antivirus scanning. NOTE for mach specifically: an unsigned
   remote-access daemon is the exact category Defender PUA heuristics
   flag — if the PR draws Validation-Defender-Error, the documented
   remedy is submitting the installer to the Microsoft Defender team for
   analysis (microsoft.com/wdsi/filesubmission) and commenting on the PR;
   a signed MSI would preempt this class of failure. Expect manual
   moderator review (days) regardless.
5. After merge: `winget install TevaServices.mach` resolves.

## Why the MSI, and what it registers

The MSI (packaging/wix/mach.wxs) installs `mach.exe` per-machine and
installs the `machd` **Windows service** (native ServiceInstall/ServiceControl
— LocalSystem, own process, auto start at boot, SCM failure actions give it
restart-on-failure: `sc failure machd` shows them; see packaging/README.md's
Windows section). There is no scheduled task and no schtasks custom action.
Enrollment on Windows (elevated PowerShell): point `MACH_STATE_DIR` at the
service's state dir (the LocalSystem profile's `.mach` — the README names the
path), run `mach register`; the installed service is RUNNING and polls, so it
picks the enrollment up without a manual start. Updates: `winget upgrade` /
the next MSI — the control plane does not push agent binaries.