package agent

import (
	"strings"
	"testing"
)

func TestPolicyDeny(t *testing.T) {
	p := &policy{}
	p.parse("deny:rm -rf\ndeny:mkfs\n")
	if r := p.Evaluate("rm -rf /", nil); r == "" {
		t.Error("rm -rf not denied")
	}
	if r := p.Evaluate("ls -la", nil); r != "" {
		t.Errorf("ls refused: %s", r)
	}
	// argv mode: joined args checked too, whitespace-normalized.
	if r := p.Evaluate("", []string{"bash", "-c", "rm  -rf /"}); r == "" {
		t.Error("argv rm -rf not denied")
	}
}

func TestPolicyAllowlist(t *testing.T) {
	p := &policy{}
	p.parse("allowonly\nallow:systemctl\nallow:journalctl\n")
	if r := p.Evaluate("systemctl status nginx", nil); r != "" {
		t.Errorf("allowed command refused: %s", r)
	}
	if r := p.Evaluate("", []string{"systemctl", "status", "nginx"}); r != "" {
		t.Errorf("allowed argv command refused: %s", r)
	}
	if r := p.Evaluate("cat /etc/shadow", nil); r == "" {
		t.Error("non-allowlisted command allowed in allowonly mode")
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