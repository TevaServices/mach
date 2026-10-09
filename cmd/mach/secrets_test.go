package main

// `mach secrets` on-box: enrolled-machine requirement, org requirement, and
// the never-prints-a-value property. The value travels by stdin (never argv).

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/TevaServices/mach/internal/agent"
)

// writeEnrolledConfig lays down a config.json for the state dir the command
// will read (StateDir() honors MACH_STATE_DIR).
func writeEnrolledConfig(t *testing.T, org string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MACH_STATE_DIR", dir)
	cfg := &agent.Config{Server: "https://mach.example.com", Name: "orgA-m1", Org: org}
	if err := agent.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runSecrets runs SecretsCommand with stdin swapped for a pipe carrying value
// and stdout/stderr captured, so the test can assert on what was printed.
func runSecrets(t *testing.T, args []string, stdin string) (code int, stdout string) {
	t.Helper()
	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inW.WriteString(stdin); err != nil {
		t.Fatal(err)
	}
	inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin, os.Stdout, os.Stderr = inR, outW, errW
	t.Cleanup(func() {
		os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
		inR.Close()
		outR.Close()
		errR.Close()
		errW.Close()
	})
	code = agent.SecretsCommand(args)
	outW.Close()
	errW.Close()
	buf := make([]byte, 8192)
	n, _ := outR.Read(buf)
	out := string(buf[:n])
	n, _ = errR.Read(buf)
	return code, out + string(buf[:n])
}

func TestSecretsCommandRequiresEnrollment(t *testing.T) {
	t.Setenv("MACH_STATE_DIR", t.TempDir()) // nothing enrolled here
	code, out := runSecrets(t, []string{"secrets", "list"}, "")
	if code != 2 {
		t.Errorf("unenrolled exit = %d, want 2", code)
	}
	if !strings.Contains(out, "not enrolled") {
		t.Errorf("unenrolled message = %q", out)
	}
}

func TestSecretsCommandRequiresOrg(t *testing.T) {
	writeEnrolledConfig(t, "") // enrolled before the feature: no org
	code, out := runSecrets(t, []string{"secrets", "add", "DB_PASSWORD"}, "s3cr3tvalue\n")
	if code != 2 {
		t.Errorf("no-org exit = %d, want 2", code)
	}
	if !strings.Contains(out, "re-enroll") {
		t.Errorf("no-org message = %q", out)
	}
}

func TestSecretsCommandAddListRemove(t *testing.T) {
	dir := writeEnrolledConfig(t, "orgA")

	// add: value via stdin, exit 0.
	code, out := runSecrets(t, []string{"secrets", "add", "DB_PASSWORD"}, "s3cr3tvalue\n")
	if code != 0 {
		t.Fatalf("add exit = %d, stdout %q", code, out)
	}
	if strings.Contains(out, "s3cr3tvalue") {
		t.Errorf("the add status line printed the value: %q", out)
	}
	st, err := os.Stat(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatalf("store file missing: %v", err)
	}
	// 0600 is a POSIX property (chmod is a no-op on Windows; the file is
	// protected by the profile's ACLs there) — the same skip the agent's
	// store mode test takes.
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("secrets.json mode = %o, want 600", st.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "s3cr3tvalue") {
		t.Error("the value was not stored")
	}

	// list --local: names only. (A plain `mach secrets list` belongs to the
	// control plane's registry and is routed before this command runs.)
	code, out = runSecrets(t, []string{"secrets", "list", "--local"}, "")
	if code != 0 || !strings.Contains(out, "DB_PASSWORD") {
		t.Fatalf("list = %d / %q", code, out)
	}
	if strings.Contains(out, "s3cr3tvalue") {
		t.Errorf("list printed a value: %q", out)
	}

	// remove.
	code, _ = runSecrets(t, []string{"secrets", "remove", "DB_PASSWORD"}, "")
	if code != 0 {
		t.Fatalf("remove exit = %d", code)
	}
	code, out = runSecrets(t, []string{"secrets", "list", "--local"}, "")
	if code != 0 || strings.Contains(out, "DB_PASSWORD") {
		t.Errorf("after remove, list = %d / %q", code, out)
	}
}

func TestSecretsCommandRejectsBadNameAndExtraArgs(t *testing.T) {
	writeEnrolledConfig(t, "orgA")
	// An invalid name is refused before the value is even read.
	if code, _ := runSecrets(t, []string{"secrets", "add", "MACH_TOKEN"}, "s3cr3tvalue\n"); code != 2 {
		t.Errorf("reserved name exit = %d, want 2", code)
	}
	// Extra arguments are refused: there is no argv shape that carries a value.
	if code, _ := runSecrets(t, []string{"secrets", "add", "DB_PASSWORD", "s3cr3tvalue"}, ""); code != 2 {
		t.Errorf("argv value exit = %d, want 2", code)
	}
	// A too-short value is refused.
	if code, _ := runSecrets(t, []string{"secrets", "add", "DB_PASSWORD"}, "short\n"); code != 2 {
		t.Errorf("short value exit = %d, want 2", code)
	}
}
