// Package main — packaging artifact assertions.
//
// The distribution packages register the OS service (#40/#44): the binary
// no longer self-installs, so the supervision semantics that used to be
// pinned on the generated unit (internal/agent/install.go, removed in #44)
// are now pinned on the SHIPPED artifacts instead. These tests read the
// packaging sources the way a distributor would and assert the properties
// the repo's security model depends on (AGENTS.md invariant 22: the agent
// exits 0 to mean stop — a supervisor must restart on FAILURE, never on a
// clean exit; a retire or an update handoff is a clean exit).
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readPackaging reads a file under packaging/ (repo root relative to this
// test's working directory, which go test sets to the package dir — cmd/mach
// — so the repo root is one level above that).
func readPackaging(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../..", rel))
	if err != nil {
		t.Fatalf("packaging file not found: %s", rel)
	}
	return string(b)
}

// readPackagingCode strips comment lines: must-not assertions for maintainer
// scripts should judge executable lines. Comments legitimately mention the
// operator's own commands ("start it after enrollment") — those are
// documentation, not behavior.
func readPackagingCode(t *testing.T, rel string) string {
	t.Helper()
	var keep []string
	for _, ln := range strings.Split(readPackaging(t, rel), "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		keep = append(keep, ln)
	}
	return strings.Join(keep, "\n")
}

// extractPurgeBranch returns the line indexes that belong to the
// `if [ "$1" = "purge" ]` branch (nesting-aware) — the only honest way to
// assert a command runs only on purge and not on a plain remove.
func extractPurgeBranch(t *testing.T, s string) []string {
	t.Helper()
	var out []string
	depth := 0
	inPurge := false
	for _, ln := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(ln)
		if !inPurge {
			if strings.Contains(trimmed, `"purge"`) {
				inPurge = true
			}
			continue
		}
		if strings.HasPrefix(trimmed, "if ") {
			depth++
		}
		if trimmed == "fi" || strings.HasPrefix(trimmed, "fi ") {
			if depth == 0 {
				break
			}
			depth--
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func mustContain(t *testing.T, s, what string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(s, p) {
			t.Errorf("%s: missing %q", what, p)
		}
	}
}

func mustNotContain(t *testing.T, s, what string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if strings.Contains(s, p) {
			t.Errorf("%s: must NOT contain %q", what, p)
		}
	}
}

// Systemd unit: restart-on-failure supervision, dedicated unprivileged
// account, state dir pinned to the package convention.
func TestShippedSystemdUnitRestartsOnFailureNotAlways(t *testing.T) {
	s := readPackaging(t, "packaging/systemd/machd.service")
	mustContain(t, s, "machd.service",
		"Restart=on-failure",
		"User=mach",
		"Group=mach",
		"Environment=MACH_STATE_DIR=/var/lib/mach",
		`ExecStart="/usr/bin/mach" run`,
		"Type=simple",
	)
	mustNotContain(t, s, "machd.service", "Restart=always")
}

// The unit's ExecStart quoting: a path with spaces stays one argv element
// (the old generated unit escaped the same way).
func TestShippedSystemdUnitExecStartIsQuoted(t *testing.T) {
	s := readPackaging(t, "packaging/systemd/machd.service")
	if !strings.HasPrefix(strings.TrimSpace(strings.SplitN(s, "ExecStart=", 2)[1]), `"`) {
		t.Errorf("machd.service: ExecStart value is not quoted — a spaced install path would split into two argv elements")
	}
}

// deb postinst: create the account, enable — never start. machd on an
// unenrolled state dir must not be started by the package (crash-loop;
// enrollment is a person at the machine).
func TestDebPostinstEnablesAndRestartsOnlyWhatWasRunning(t *testing.T) {
	s := readPackagingCode(t, "packaging/nfpm/deb/postinst")
	mustContain(t, s, "deb postinst",
		"adduser --system",
		"/var/lib/mach",
		"systemctl enable machd.service",
		// The upgrade restart is gated on the prerm's was-running marker:
		// a serving agent comes back, a deliberately stopped one (revoked
		// machine, operator stop) stays stopped. First installs never
		// start (unenrolled machd crash-loops; enrollment is a person at
		// the machine, #41).
		"/run/machd.was-running",
	)
	mustContain(t, s, "deb postinst", "systemctl restart machd.service")
	mustNotContain(t, s, "deb postinst", "systemctl start", "enable --now")
	if restart := strings.Index(s, "systemctl restart machd.service"); restart >= 0 {
		if marker := strings.Index(s, "/run/machd.was-running"); marker < 0 || marker > restart {
			t.Fatalf("deb postinst: restart is not gated on the was-running marker")
		}
	}
}

// deb postrm: state survives a plain remove (re-install keeps the machine's
// identity); purge takes it and the account away.
func TestDebPostrmKeepsStateOnRemoveRemovesOnPurge(t *testing.T) {
	s := readPackagingCode(t, "packaging/nfpm/deb/postrm")
	branch := extractPurgeBranch(t, s)
	joined := "\n" + strings.Join(branch, "\n") + "\n"
	if !strings.Contains(joined, "rm -rf /var/lib/mach") {
		t.Errorf("deb postrm: purge branch does not remove /var/lib/mach")
	}
	if !strings.Contains(joined, "deluser") {
		t.Errorf("deb postrm: purge branch does not remove the service account")
	}
	// The executable lines OUTSIDE the purge branch must not touch the
	// state dir or the account.
	outside := []string{}
	inPurge := false
	depth := 0
	for _, ln := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(ln)
		if !inPurge {
			if strings.Contains(trimmed, `"purge"`) {
				inPurge = true
			} else if trimmed != "" && trimmed != "#DEBHELPER#" {
				outside = append(outside, trimmed)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "if ") {
			depth++
		}
		if trimmed == "fi" || strings.HasPrefix(trimmed, "fi ") {
			if depth == 0 {
				inPurge = false
				continue
			}
			depth--
		}
	}
	joinedOut := "\n" + strings.Join(outside, "\n") + "\n"
	mustNotContain(t, joinedOut, "deb postrm (remove path)",
		"rm -rf /var/lib/mach", "deluser")
}

// rpm scriptlets: user before files (%pre), enable not start (%post), stop
// on erase (%preun), state removed on final erase only (%postun).
func TestRpmScriptletsLifecycle(t *testing.T) {
	pre := readPackaging(t, "packaging/nfpm/rpm/pre.sh")
	mustContain(t, pre, "rpm pre", "useradd --system")
	// %pre records whether the agent is serving: %post restarts exactly
	// that on upgrade (rpm never stops the unit on upgrade, so this is
	// also what swaps the old binary for the new one).
	mustContain(t, pre, "rpm pre", "/run/machd.was-running")

	post := readPackagingCode(t, "packaging/nfpm/rpm/post.sh")
	mustContain(t, post, "rpm post", "systemctl enable machd.service")
	mustContain(t, post, "rpm post", "/run/machd.was-running")
	mustContain(t, post, "rpm post", "systemctl restart machd.service")
	mustNotContain(t, post, "rpm post", "systemctl start")

	preun := readPackaging(t, "packaging/nfpm/rpm/preun.sh")
	mustContain(t, preun, "rpm preun", "-eq 0") // upgrade (arg 1) vs erase (arg 0)
	mustContain(t, preun, "rpm preun", "systemctl stop machd.service")

	postun := readPackagingCode(t, "packaging/nfpm/rpm/postun.sh")
	mustContain(t, postun, "rpm postun", `-eq 0`, "/var/lib/mach", "systemctl disable")
	// A %postun upgrade run (arg 1) must leave everything alone: nothing
	// executable outside the -eq 0 branch may touch the service or state.
	after := readPackagingCode(t, "packaging/nfpm/rpm/postun.sh")
	idx := strings.Index(after, "-eq 0")
	mustNotContain(t, after[:idx], "rpm postun (upgrade path)",
		"systemctl disable", "/var/lib/mach", "userdel")
}

// alpine: OpenRC, not systemd (alpine has no systemd), account before
// files, enable not start, and NO unconditional respawner: exit 0 must
// mean stop (invariant 22). command_background without a supervisor leaves
// a crashed agent down instead of restarting a retired one. Judged on
// executable lines: the script's comments legitimately explain the
// supervisor it deliberately avoids.
func TestApkShipsOpenRCWithoutUnconditionalRestart(t *testing.T) {
	rc := readPackagingCode(t, "packaging/openrc/machd")
	mustContain(t, rc, "openrc machd", `command_background="yes"`)
	mustContain(t, rc, "openrc machd", "--user mach")
	mustNotContain(t, rc, "openrc machd",
		"supervise-daemon", "supervised", "respawn")

	pre := readPackaging(t, "packaging/nfpm/apk/pre-install.sh")
	mustContain(t, pre, "apk pre-install", "adduser -S")

	post := readPackagingCode(t, "packaging/nfpm/apk/post-install.sh")
	mustContain(t, post, "apk post-install", "rc-update add machd")
	// Upgrade restarts an ENROLLED machine — the pre-deinstall stopped it,
	// and the enrollment marker (config.json) is the only state that
	// survives the stop. But the restart must stay INSIDE that gate: an
	// unconditional rc-service start would respawn a retired machine's
	// agent, and exit 0 must mean stop (invariant 22).
	mustContain(t, post, "apk post-install", "[ -f /var/lib/mach/config.json ]")
	mustContain(t, post, "apk post-install", "rc-service machd restart")
	mustNotContain(t, post, "apk post-install", "rc-service machd start")
}

// goreleaser config: the apk entry must not carry the systemd unit (no
// systemd on alpine) — split off as its own nfpms entry (per-format
// maintainer scripts), shipping the OpenRC script instead.
func TestGoreleaserApkEntryShipsOpenRCNotSystemd(t *testing.T) {
	s := readPackaging(t, ".goreleaser.yaml")
	idx := strings.Index(s, "id: packages-apk")
	if idx < 0 {
		t.Fatalf(".goreleaser.yaml: no packages-apk nfpms entry")
	}
	apkEntry := s[idx:]
	mustContain(t, apkEntry, "packages-apk entry",
		"formats: [apk]", "packaging/openrc/machd", "/etc/init.d/machd")
	mustNotContain(t, apkEntry, "packages-apk entry", "machd.service")

	// deb/rpm entries ship the systemd unit.
	for _, id := range []string{"id: packages-deb", "id: packages-rpm"} {
		i := strings.Index(s, id)
		if i < 0 {
			t.Fatalf(".goreleaser.yaml: missing nfpms entry %s", id)
		}
		mustContain(t, s[i:], id, "machd.service")
	}
}

// The Homebrew formula template carries the supervision contract in the
// service DSL: keep_alive successful_exit: false — restart on failure only
// (invariant 22; brew services renders it as launchd's
// KeepAlive SuccessfulExit=false and as the matching systemd unit on Linuxbrew).
func TestBrewTemplateServiceKeepsFailureOnlyRestart(t *testing.T) {
	s := readPackaging(t, "packaging/homebrew/mach.rb.tmpl")
	mustContain(t, s, "mach.rb.tmpl",
		"keep_alive successful_exit: false",
		"service do",
		"MACH_STATE_DIR",
		"system \"#{bin}/mach\", \"version\"", // test block: the formula validates itself
	)
	mustNotContain(t, s, "mach.rb.tmpl", "keep_alive true", "__VER__\n  ")
}

// attest hook refuses to ship an attestation that reports a WARNING
// (modified tree / missing VCS revision) — the release.yml rule, now also
// carried by the goreleaser path.
func TestAttestHookRefusesWarnings(t *testing.T) {
	s := readPackaging(t, "packaging/goreleaser/attest-hook.sh")
	mustContain(t, s, "attest hook",
		"verify-attestation",
		"*WARNING*",
		"exit 1",
	)
}

// The Windows MSI registers a real Windows service (machd), not a scheduled
// task: the schtasks authoring died in every release that validated its
// first real install (#51/#54 — an unterminated condition quote, a nested
// /TR idiom msiexec re-tokenizes, and /RI refused outright for ONLOGON
// triggers). These pins hold the service authoring's supervision semantics:
// auto-start at boot, restart-on-failure-only (exit 0 means stop, invariant
// 22), service removed on uninstall, and the SCM entry-point argument.
func TestWixRegistersTheMachdService(t *testing.T) {
	s := readPackaging(t, "packaging/wix/mach.wxs")
	mustContain(t, s, "mach.wxs",
		`Name="machd"`,
		`Arguments="service"`,
		`Start="auto"`,
		`Remove="uninstall"`,
	)
	// Restart on FAILURE only: restart actions present, and no unconditional
	// or interval-based rescheduling that would respawn a clean exit.
	mustContain(t, s, "mach.wxs",
		"sc.exe failure machd reset=",
		"actions= restart/5000",
		`Condition="NOT REMOVE"`,
		"Return=\"check\"",
	)
	mustNotContain(t, s, "mach.wxs", "/RI ")
}

// And no schtasks authoring may return: the service replaced it. A CA that
// shells out to schtasks again is exactly the class the three burned tags
// paid for.
func TestWixHasNoSchtasksAuthoring(t *testing.T) {
	s := readPackaging(t, "packaging/wix/mach.wxs")
	mustNotContain(t, s, "mach.wxs", "schtasks")
	mustNotContain(t, s, "mach.wxs", "Task Scheduler")
}
