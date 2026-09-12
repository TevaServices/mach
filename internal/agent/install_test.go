package agent

// Tests for the generated service definitions.
//
// The property under test is the one that makes "the client can exit gracefully"
// true rather than aspirational: the supervisor restarts on FAILURE, so exit 0
// means stop. The agent exits 0 when the control plane retires it — revoked, or
// deleted — and a supervisor that treats that as a crash turns a deliberate
// retirement into a restart loop on the operator's machine.
//
// These are string assertions on the rendered unit because that is the whole
// artefact: there is no systemd or launchd in the test environment, and the
// failure mode this guards against only appears on a machine being retired.

import (
	"strings"
	"testing"
)

func TestSystemdUnitRestartsOnFailureNotAlways(t *testing.T) {
	unit := systemdUnit("bcross-web-1", "", "", "/usr/local/bin/mach")

	if !strings.Contains(unit, "Restart=on-failure") {
		t.Fatalf("unit does not restart on failure:\n%s", unit)
	}
	// Restart=always is the regression: it resurrects a retired agent.
	if strings.Contains(unit, "Restart=always") {
		t.Fatalf("unit restarts unconditionally, so a clean exit cannot mean stop:\n%s", unit)
	}
	if strings.Contains(unit, "Restart=no") || strings.Contains(unit, "Restart=on-success") {
		t.Fatalf("unit would not restart a crashed agent:\n%s", unit)
	}
	if !strings.Contains(unit, `ExecStart="/usr/local/bin/mach" run`) {
		t.Fatalf("unit does not run the agent:\n%s", unit)
	}
	if !strings.Contains(unit, "mach agent (bcross-web-1)") {
		t.Fatalf("unit does not name the machine:\n%s", unit)
	}
}

// The privileged-service variant has to keep both the user line and the restart
// semantics: dropping to an unprivileged user is a separate control.
func TestSystemdUnitKeepsPrivilegeAndEnvLines(t *testing.T) {
	unit := systemdUnit("bcross-web-1", "User=mach\n", "Environment=MACH_SERVER=https://x\n", "/bin/mach")
	for _, want := range []string{"User=mach", "Environment=MACH_SERVER=https://x", "Restart=on-failure"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit lost %q:\n%s", want, unit)
		}
	}
}

func TestLaunchdPlistStopsOnSuccessfulExit(t *testing.T) {
	plist := launchdPlist("/usr/local/bin/mach", "/tmp/mach.log")

	// SuccessfulExit=false is the launchd spelling of "exit 0 means stop".
	if !strings.Contains(plist, "<key>SuccessfulExit</key><false/>") {
		t.Fatalf("plist does not gate KeepAlive on a successful exit:\n%s", plist)
	}
	// KeepAlive <true/> is the regression.
	if strings.Contains(plist, "<key>KeepAlive</key><true/>") {
		t.Fatalf("plist keeps the agent alive unconditionally:\n%s", plist)
	}
	// It must still start at login, or an agent is not running at all.
	if !strings.Contains(plist, "<key>RunAtLoad</key><true/>") {
		t.Fatalf("plist does not run at load:\n%s", plist)
	}
	if !strings.Contains(plist, "<string>/usr/local/bin/mach</string>") {
		t.Fatalf("plist does not run the agent:\n%s", plist)
	}
}

// A path with XML metacharacters must not be able to break out of the plist.
func TestLaunchdPlistEscapesTheExecutablePath(t *testing.T) {
	plist := launchdPlist("/opt/a&b/mach", "/tmp/x.log")
	if strings.Contains(plist, "a&b") {
		t.Fatalf("an unescaped ampersand reached the plist:\n%s", plist)
	}
	if !strings.Contains(plist, "a&amp;b") {
		t.Fatalf("the path was not escaped as expected:\n%s", plist)
	}
}
