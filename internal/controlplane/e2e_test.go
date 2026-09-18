package controlplane

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TevaServices/mach/internal/server"
	"github.com/TevaServices/mach/internal/store"
)

// captureStdout runs f with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	f()
	w.Close()
	b, _ := io.ReadAll(r)
	r.Close()
	return string(b)
}

// The admin command is the operator's only handle on the E2E setting, so the
// plumbing between it and the rows the server reads is worth pinning: a typo in
// the flag parsing would otherwise look like a setting that silently did not
// take.
func TestE2ECommandSetsPerOrgAndReportsIt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MACH_DB", filepath.Join(dir, "mach.db"))
	t.Setenv("MACH_ORG", "bcross")
	t.Setenv("MACH_ORGS", "acme")
	t.Setenv("MACH_E2E", "")

	// Set one org off: the default and the other org are untouched.
	out := captureStdout(t, func() {
		if err := E2E("off", "acme"); err != nil {
			t.Fatalf("e2e off --org acme: %v", err)
		}
	})
	if !strings.Contains(out, "org acme: sealed exec off") {
		t.Errorf("output = %q, want it to report acme off", out)
	}

	st, err := store.Open(filepath.Join(dir, "mach.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if mode, _ := server.E2EMode(st, "acme"); mode != "off" {
		t.Errorf("acme = %q, want off", mode)
	}
	if mode, _ := server.E2EMode(st, "bcross"); mode != "on" {
		t.Errorf("bcross = %q, want on (unaffected)", mode)
	}
	if mode, _ := server.E2EMode(st, ""); mode != "on" {
		t.Errorf("default = %q, want on (unaffected)", mode)
	}

	// The report without a value lists every configured org.
	out = captureStdout(t, func() {
		if err := E2E("", ""); err != nil {
			t.Fatalf("e2e report: %v", err)
		}
	})
	for _, want := range []string{"default: sealed exec on", "org bcross: sealed exec on", "org acme: sealed exec off"} {
		if !strings.Contains(out, want) {
			t.Errorf("report %q is missing %q", out, want)
		}
	}

	// inherit drops the override, and the org follows the default again.
	out = captureStdout(t, func() {
		if err := E2E("inherit", "acme"); err != nil {
			t.Fatalf("e2e inherit --org acme: %v", err)
		}
	})
	if !strings.Contains(out, "override removed") {
		t.Errorf("output = %q, want it to say the override is gone", out)
	}
	if mode, _ := server.E2EMode(st, "acme"); mode != "on" {
		t.Errorf("acme after inherit = %q, want the default (on)", mode)
	}

	// Bad input is refused rather than stored.
	for _, c := range []struct{ set, org string }{
		{"maybe", "acme"},
		{"off", "NOT A LABEL"},
		{"inherit", ""},
	} {
		if err := E2E(c.set, c.org); err == nil {
			t.Errorf("E2E(%q, %q) was accepted, want an error", c.set, c.org)
		}
	}
}
