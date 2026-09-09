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
	// On linux we expect bash or sh; on macOS bash/zsh; on windows PS.
	goos := runtimeGOOS()
	switch goos {
	case "linux":
		if !strings.Contains(sh.path, "bash") && !strings.Contains(sh.path, "sh") {
			t.Errorf("linux shell = %q, want bash/sh", sh.path)
		}
	case "darwin":
		if !strings.Contains(sh.path, "bash") && !strings.Contains(sh.path, "zsh") && !strings.Contains(sh.path, "sh") {
			t.Errorf("darwin shell = %q", sh.path)
		}
	case "windows":
		if !strings.Contains(strings.ToLower(sh.path), "powershell") && !strings.Contains(strings.ToLower(sh.path), "cmd") {
			t.Errorf("windows shell = %q", sh.path)
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
	n, _ := cb.Write([]byte("0123456789"))
	_ = n
	// Overflow write must be discarded, not grown.
	_, _ = cb.Write([]byte("ABCDEFGHIJ"))
	s := cb.String()
	if len(s) != 10+len("\n[mach: output truncated at cap]") {
		t.Errorf("capped buffer len = %d", len(s))
	}
	if !strings.HasSuffix(s, "[mach: output truncated at cap]") {
		t.Errorf("missing truncation marker: %q", s)
	}
	if !strings.HasPrefix(s, "0123456789") {
		t.Errorf("head content lost: %q", s)
	}
}
