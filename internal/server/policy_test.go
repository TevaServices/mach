package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bcross/mach/internal/store"
)

// The point of the server-side policy: one block list, applied to every key,
// every scope and every machine — and applied before anything is dispatched,
// so a blocked command never reaches an agent even if that agent is online.
func TestGlobalExecPolicyBlocksFleetWide(t *testing.T) {
	s, st := newAuthTestServer(t)
	s.SetExecPolicy("deny:rm -rf /")
	if err := st.CreateMachine("bcross-a", "pub", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	for _, scopes := range []string{"exec:*", "exec:bcross-a"} {
		key := adminKey(t, s, scopes)
		code, body := execReq(t, s, key, `{"machine":"bcross-a","command":"rm -rf / --no-preserve-root"}`)
		if code != http.StatusForbidden {
			t.Fatalf("scopes %q: blocked command returned %d, want 403 (%s)", scopes, code, body)
		}
		if !strings.Contains(body, "global exec policy") {
			t.Errorf("scopes %q: refusal does not name the policy: %s", scopes, body)
		}
		// The refusal must be the policy's, not the "machine offline" path:
		// the block happens first, so the reason is never "offline".
		if strings.Contains(body, "offline") {
			t.Errorf("scopes %q: a blocked command reached dispatch (%s)", scopes, body)
		}
	}

	// A command the policy does not match is left alone. Asserted on the check
	// itself rather than through the endpoint: an allowed command proceeds to
	// dispatch and then waits the full offline timeout, which would make this
	// test cost 15 seconds to learn nothing extra.
	for _, cmd := range []string{"uptime", "df -h", "echo rm"} {
		if why := s.execPolicyCheck(cmd, nil); why != "" {
			t.Errorf("command %q was blocked: %s", cmd, why)
		}
	}
}

// A blocked attempt is recorded. A block list that silently drops commands
// would hide exactly the attempts an operator wants to see.
func TestGlobalExecPolicyRefusalIsAudited(t *testing.T) {
	s, st := newAuthTestServer(t)
	s.SetExecPolicy("deny:shutdown")
	if err := st.CreateMachine("bcross-a", "pub", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key := adminKey(t, s, "exec:*")
	if code, _ := execReq(t, s, key, `{"machine":"bcross-a","command":"shutdown -h now"}`); code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}
	entries, err := st.AuditList("bcross-a", 10)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("a refused command was not audited")
	}
	e := entries[0]
	if !strings.Contains(e.Command, "shutdown") {
		t.Errorf("audit command = %q, want the attempt", e.Command)
	}
	if !e.ExitCode.Valid || e.ExitCode.Int64 != execRefused {
		t.Errorf("audit exit = %v, want %d (refused)", e.ExitCode, execRefused)
	}
	if !strings.Contains(e.StderrSnip, "deny") {
		t.Errorf("audit stderr = %q, want the policy reason", e.StderrSnip)
	}
}

// argv mode carries an argument list, not a shell string: the whole list is
// one command, so the allowlist must not invent extra commands out of
// separators that appear inside an argument. (The same text in shell mode IS
// two commands, and must be judged as such.)
func TestGlobalExecPolicyAndArgvMode(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.CreateMachine("bcross-a", "pub", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key := adminKey(t, s, "exec:*")

	// A deny rule matches the text of an argv-mode request the same way it
	// matches a shell command: the rule is about what is being asked for.
	s.SetExecPolicy("deny:rm -rf /")
	code, body := execReq(t, s, key, `{"machine":"bcross-a","argv":["rm","-rf","/"]}`)
	if code != http.StatusForbidden {
		t.Fatalf("argv-mode blocked command returned %d, want 403 (%s)", code, body)
	}

	// allowonly: `echo a;b` in argv mode is one command whose text starts with
	// an allowed prefix. Nothing splits it, so nothing beyond the prefix has
	// to be allowed — there is no second command, only a semicolon in a word.
	s.SetExecPolicy("allowonly\nallow:echo")
	if why := s.execPolicyCheck("", []string{"echo", "a;b"}); why != "" {
		t.Errorf("argv mode was split on a separator inside an argument: %s", why)
	}
	if why := s.execPolicyCheck("", []string{"curl", "x"}); why == "" {
		t.Error("argv mode allowed a command with no matching allow rule")
	}
	// The same text as a shell string is two commands, and the second one is
	// not allowed: shell mode splits, argv mode does not. That difference is
	// the whole reason the two modes are matched separately.
	if why := s.execPolicyCheck("echo a;b", nil); why == "" {
		t.Error("shell mode did not split on a separator — the allowlist can be bypassed with a semicolon")
	}
}

// allowonly mode is the other direction: everything not explicitly allowed is
// refused, including by a key that could otherwise run it.
func TestGlobalExecPolicyAllowOnlyFleetWide(t *testing.T) {
	s, st := newAuthTestServer(t)
	s.SetExecPolicy("allowonly\nallow:uptime\nallow:df")
	if err := st.CreateMachine("bcross-a", "pub", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key := adminKey(t, s, "exec:*")
	if code, _ := execReq(t, s, key, `{"machine":"bcross-a","command":"whoami"}`); code != http.StatusForbidden {
		t.Fatalf("unlisted command returned %d, want 403", code)
	}
	if why := s.execPolicyCheck("whoami", nil); why == "" {
		t.Error("allowonly mode did not refuse an unlisted command")
	}
	if why := s.execPolicyCheck("uptime", nil); why != "" {
		t.Errorf("allowonly mode refused a listed command: %s", why)
	}
}

// The policy file is editable at runtime — that is how an operator changes the
// fleet's block list — and an unreadable file must not silently boot an
// unprotected control plane.
func TestExecPolicyFileReloadAndFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.txt")
	if err := os.WriteFile(path, []byte("deny:mkfs\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("MACH_EXEC_POLICY_FILE", path)

	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()
	s := New(st, nil, "bcross", filepath.Join(dir, "key"))

	if s.execPolicyCheck("mkfs.ext4 /dev/sda", nil) == "" {
		t.Fatal("a rule from the policy file was not loaded")
	}
	if s.execPolicyCheck("uptime", nil) != "" {
		t.Fatal("the policy file blocked an unrelated command")
	}

	// Rewrite the file: the next reload must pick up the new rules, and must
	// drop the old ones rather than accumulating them.
	if err := os.WriteFile(path, []byte("deny:dd if=\n"), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	// Backdate the recorded mtime so the reload sees a change without the test
	// having to sleep through the poll interval.
	s.execPolicy.mu.Lock()
	s.execPolicy.mod = time.Now().Add(-time.Hour)
	s.execPolicy.mu.Unlock()
	if !s.execPolicy.reloadFile() {
		t.Fatal("reload reported no change after the file was rewritten")
	}
	if s.execPolicyCheck("dd if=/dev/zero of=/dev/sda", nil) == "" {
		t.Fatal("the new rule was not applied")
	}
	if s.execPolicyCheck("mkfs.ext4 /dev/sda", nil) != "" {
		t.Fatal("the replaced rule is still in force — rules accumulated across a reload")
	}

	// A file that cannot be read keeps the last good rules rather than
	// silently unblocking the fleet.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	s.execPolicy.mu.Lock()
	s.execPolicy.mod = time.Now().Add(-time.Hour)
	s.execPolicy.mu.Unlock()
	s.execPolicy.reloadFile()
	if s.execPolicyCheck("dd if=/dev/zero of=/dev/sda", nil) == "" {
		t.Fatal("an unreadable policy file cleared the block list")
	}
}

// A configured-but-unreadable file at startup is fatal: a control plane that
// boots with its block list quietly missing is worse than one that refuses to
// start, because the operator has no way to tell the difference.
func TestExecPolicyFileMissingAtStartupIsFatal(t *testing.T) {
	t.Setenv("MACH_EXEC_POLICY_FILE", filepath.Join(t.TempDir(), "does-not-exist.txt"))
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("New started with an unreadable policy file instead of refusing")
		}
		if !strings.Contains(fmt.Sprint(r), "MACH_EXEC_POLICY_FILE") {
			t.Errorf("panic = %v, want it to name the policy file", r)
		}
	}()
	New(st, nil, "bcross", filepath.Join(t.TempDir(), "key"))
}
