//go:build !windows

package store

// The mode/umask assertions are POSIX: Windows files do not carry the same
// permission model, and syscall.Umask does not exist there — so this test
// compiles only where the tightening it pins applies.

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The database holds the audit trail — command text and output snippets, and
// exactly the secrets RedactScrubs exists to catch — plus the API-key lookup
// and hash columns, and the identity key beside it is deliberately 0600. The
// driver created it with the process umask, so with the compose bind mount the
// docs describe, every local user on the control-plane host could read it.
//
// The WAL sidecar gets the same treatment, and needs it more: in WAL mode the
// most recent transactions — the newest rows, which are the ones an operator
// just ran — live there rather than in the database file.
func TestSQLiteDatabaseIsNotWorldReadable(t *testing.T) {
	if testing.Short() {
		t.Skip("opens a real database")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "mach.db")

	// A database created under a loose umask, which is the case that leaked.
	old := syscall.Umask(0)
	st, err := Open(path)
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if got := modeOf(t, path); got != 0o600 {
		t.Fatalf("a freshly created database is mode %04o, want 0600", got)
	}

	// A loose mode on an existing database is corrected on the next open: a
	// volume restored from a backup arrives readable, and so does one created
	// before this rule existed.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	if got := modeOf(t, path); got != 0o600 {
		t.Fatalf("database mode after reopen = %04o, want 0600", got)
	}
	// And an already-correct mode is left alone, so a deployment that managed
	// its own permissions is not disturbed.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	st3, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st3.Close()
	if got := modeOf(t, path); got != 0o600 {
		t.Fatalf("database mode = %04o, want 0600", got)
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}
