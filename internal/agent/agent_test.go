package agent

import (
	"os"
	"strings"
	"testing"
)

// The agent's guardrail is a thin lazy wrapper over internal/policy (which
// owns the grammar and matching semantics and has its own tests); what is
// worth testing here is that the wrapper loads once and evaluates.
func TestAgentPolicyLoadsFromEnv(t *testing.T) {
	t.Setenv("MACH_POLICY", "deny:rm -rf\ndeny:mkfs\n")
	var lp lazyPolicy
	if r := lp.Evaluate("rm -rf /", nil); r == "" {
		t.Error("rm -rf not denied")
	}
	if r := lp.Evaluate("ls -la", nil); r != "" {
		t.Errorf("ls refused: %s", r)
	}
	// argv mode: joined args checked too, whitespace-normalized.
	if r := lp.Evaluate("", []string{"bash", "-c", "rm  -rf /"}); r == "" {
		t.Error("argv rm -rf not denied")
	}
}

func TestAgentPolicyLoadsFromFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MACH_STATE_DIR", dir)
	t.Setenv("MACH_POLICY", "")
	if err := os.WriteFile(policyPath(), []byte("allowonly\nallow:systemctl\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	var lp lazyPolicy
	if r := lp.Evaluate("systemctl status nginx", nil); r != "" {
		t.Errorf("allowed command refused: %s", r)
	}
	if r := lp.Evaluate("", []string{"systemctl", "status", "nginx"}); r != "" {
		t.Errorf("allowed argv command refused: %s", r)
	}
	if r := lp.Evaluate("cat /etc/shadow", nil); r == "" {
		t.Error("non-allowlisted command allowed in allowonly mode")
	}
}

// A policy.txt that exists and cannot be read must not leave an empty ruleset
// with nothing said about it — which is exactly what happened when the load was
// lazy, at the first command, and therefore *after* DropPrivileges(): a
// root-installed agent that dropped to an unprivileged user got EACCES on a
// root-owned file, and every command, sealed or not, then ran with the one
// layer SECURITY-NOTES says "survives a hostile control plane" silently absent.
//
// The read is now eager, before the drop, and an unreadable file is an error
// that also fails closed if anyone ignores it: a machine whose own guardrail is
// missing is the case this layer exists to prevent. A directory stands in for
// the unreadable file because the failure is then independent of which user the
// test runs as — chmod 000 does not stop root.
func TestAgentPolicyFailsClosedWhenTheFileCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MACH_STATE_DIR", dir)
	t.Setenv("MACH_POLICY", "")
	if err := os.Mkdir(policyPath(), 0o700); err != nil {
		t.Fatalf("make policy.txt unreadable: %v", err)
	}
	var lp lazyPolicy
	if err := lp.loadStartup(); err == nil {
		t.Fatal("an unreadable policy.txt loaded without error")
	}
	// And if a caller ignores that error, the failure is still not silent.
	if r := lp.Evaluate("ls -la", nil); r == "" {
		t.Fatal("a machine with an unreadable policy.txt ran a command")
	}
	// An *absent* file is not an error. That is the default, not a fault, and
	// refusing to run over it would make the default configuration unusable.
	t.Setenv("MACH_STATE_DIR", t.TempDir())
	var lp2 lazyPolicy
	if err := lp2.loadStartup(); err != nil {
		t.Fatalf("an absent policy.txt was treated as a failure: %v", err)
	}
	if r := lp2.Evaluate("ls -la", nil); r != "" {
		t.Fatalf("no local policy refused a command: %s", r)
	}
}

// The load happens at startup, not at the first command: rules written to
// policy.txt are in force before anything is asked of the agent, which is what
// makes "loaded before the privilege drop" true rather than aspirational.
func TestAgentPolicyLoadsAtStartup(t *testing.T) {
	t.Setenv("MACH_STATE_DIR", t.TempDir())
	t.Setenv("MACH_POLICY", "")
	if err := os.WriteFile(policyPath(), []byte("allowonly\nallow:systemctl\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	var lp lazyPolicy
	if err := lp.loadStartup(); err != nil {
		t.Fatalf("loadStartup: %v", err)
	}
	// The rules are already in force — no Evaluate has run yet.
	if r := lp.Evaluate("cat /etc/shadow", nil); r == "" {
		t.Fatal("the allowlist was not loaded at startup")
	}
}

func TestResolveShellPerOS(t *testing.T) {
	sh, err := resolveShell()
	if err != nil {
		t.Fatalf("no shell on this machine: %v", err)
	}
	if sh.path == "" {
		t.Fatal("empty shell path")
	}
	switch goos := runtimeGOOS(); goos {
	case "linux":
		if !strings.Contains(sh.path, "sh") {
			t.Errorf("linux shell = %q, want bash/sh", sh.path)
		}
	case "darwin":
		if !strings.Contains(sh.path, "sh") {
			t.Errorf("darwin shell = %q", sh.path)
		}
	}
}

func TestShellArgs(t *testing.T) {
	cases := []struct {
		kind shellKind
		want []string
	}{
		{shellPosix, []string{"-c", "echo hi"}},
		{shellPowerShell, []string{"-NoProfile", "-NonInteractive", "-Command", "echo hi"}},
		{shellCmd, []string{"/c", "echo hi"}},
	}
	for _, c := range cases {
		got := resolvedShell{kind: c.kind}.args("echo hi")
		if len(got) != len(c.want) {
			t.Fatalf("args len %d, want %d", len(got), len(c.want))
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("args[%d] = %q, want %q", i, got[i], c.want[i])
			}
		}
	}
}

func TestCappedBufferTruncates(t *testing.T) {
	cb := &cappedBuffer{max: 10}
	if _, err := cb.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	// Overflow write must be discarded, not grown.
	if _, err := cb.Write([]byte("ABCDEFGHIJ")); err != nil {
		t.Fatal(err)
	}
	s := cb.String()
	if !strings.HasSuffix(s, "[mach: output truncated at cap]") {
		t.Errorf("missing truncation marker: %q", s)
	}
	if !strings.HasPrefix(s, "0123456789") {
		t.Errorf("head content lost: %q", s)
	}
}

func TestConfinementNote(t *testing.T) {
	note := confinementNote()
	if note == "" {
		t.Fatal("empty confinement note")
	}
	switch runtimeGOOSConfine() {
	case "linux":
		if !strings.Contains(note, "pgroup") {
			t.Errorf("linux note = %q", note)
		}
	case "windows":
		if !strings.Contains(note, "caps") {
			t.Errorf("windows note = %q", note)
		}
	}
}

func TestE2EKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	kp1, err := LoadOrCreateE2EKey(dir)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	hex1 := kp1.PublicKeyHex()
	if len(hex1) != 64 {
		t.Fatalf("pub key length = %d", len(hex1))
	}
	kp2, err := LoadOrCreateE2EKey(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if kp2.PublicKeyHex() != hex1 {
		t.Fatal("E2E key not persisted across loads")
	}
}
