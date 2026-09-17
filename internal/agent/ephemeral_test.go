package agent

// Tests for the temporary session.
//
// The property under test is "nothing is written to disk", because that is what
// makes the mode temporary in the way that matters: Ctrl-C is a shutdown and
// running `mach` again enrolls from scratch. If a key or a config were written,
// the next run would silently reuse it and the session would be permanent in all
// but name.
//
// The other half of the property, tested by construction here and by the caller
// in cmd/mach, is that the temporary path never touches the *installed* agent's
// state: it cannot read, re-key or delete an enrollment an `mach install` made.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bcross/mach/internal/protocol"
)

// fakePlane approves a pairing immediately, so the QR flow completes without a
// phone. It records the pubkeys the agent presented, so the test can prove the
// in-memory identity is the one that was enrolled.
func fakePlane(t *testing.T) (*httptest.Server, *struct{ pub, pubE2E, name string }) {
	t.Helper()
	got := &struct{ pub, pubE2E, name string }{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pair/start", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.PairStartReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		got.pub, got.pubE2E = req.PubKey, req.PubE2E
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.PairStartResponse{
			PairID: "p1", Token: "tok", Code: "CODE", Expires: "2030-01-01T00:00:00Z",
		})
	})
	mux.HandleFunc("/v1/pair/status", func(w http.ResponseWriter, r *http.Request) {
		// Approved on the first poll: no waiting, no phone.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.PairStatusResponse{State: "approved", Machine: "bcross-web"})
	})
	mux.HandleFunc("/v1/pair/claim", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.PairClaimRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		got.name = req.Name
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ok": "enrolled", "machine": "bcross-web", "server_key": "deadbeef",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, got
}

// A successful temporary enrollment writes nothing at all — not the identity key,
// not the E2E key, not the config. That is the whole difference from
// `mach register`, and the reason a second run re-enrolls.
func TestTemporaryEnrollmentKeepsEverythingInMemory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MACH_STATE_DIR", dir)
	srv, got := fakePlane(t)

	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	e2eKey, err := NewE2EKeyPair()
	if err != nil {
		t.Fatalf("e2e key: %v", err)
	}
	cfg, err := registerQRCore(srv.URL, "bcross", id, e2eKey, true)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// The enrollment is real: the control plane saw this process's in-memory keys.
	if cfg.Name != "bcross-web" || cfg.Server != srv.URL || cfg.ServerKey != "deadbeef" {
		t.Fatalf("config wrong: %+v", cfg)
	}
	if got.pub != id.PubHex {
		t.Fatalf("enrolled key %q is not the in-memory identity %q", got.pub, id.PubHex)
	}
	if got.pubE2E != e2eKey.PublicKeyHex() {
		t.Fatalf("registered an E2E key that is not the in-memory one")
	}

	// And the state directory is untouched — the point of the whole mode.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read state dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the temporary session wrote to the state dir: %v", names)
	}
}

// The persistent path still writes, so the test above is about the ephemeral
// path and not about enrollment having stopped persisting altogether.
func TestPersistentRegistrationStillWrites(t *testing.T) {
	dir := t.TempDir()
	srv, _ := fakePlane(t)

	if _, err := RegisterQR(srv.URL, "bcross", dir); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, f := range []string{"agent.key", "e2e.key", "config.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("persistent registration did not write %s: %v", f, err)
		}
	}
}

// A temporary session must not disturb an installed agent: it neither reads nor
// writes that state, so an `mach install` survives someone typing `mach`.
func TestTemporarySessionLeavesAnInstalledEnrollmentAlone(t *testing.T) {
	dir := t.TempDir()
	srv, _ := fakePlane(t)

	// Install this host.
	if _, err := RegisterQR(srv.URL, "bcross", dir); err != nil {
		t.Fatalf("register: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	keyBefore, err := os.ReadFile(filepath.Join(dir, "agent.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	// Now run a temporary enrollment against the same state dir. It uses its own
	// in-memory keys and never consults the directory.
	id, _ := NewIdentity()
	e2eKey, _ := NewE2EKeyPair()
	if _, err := registerQRCore(srv.URL, "bcross", id, e2eKey, true); err != nil {
		t.Fatalf("temporary register: %v", err)
	}

	after, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	keyAfter, _ := os.ReadFile(filepath.Join(dir, "agent.key"))
	if string(before) != string(after) {
		t.Fatal("a temporary session changed an installed agent's config")
	}
	if string(keyBefore) != string(keyAfter) {
		t.Fatal("a temporary session changed an installed agent's key")
	}
}

// The console trace, driven through the real command path: a temporary session
// prints one quoted line when a command arrives and one when it finishes.
//
// Quoting is the security-relevant half. The command text comes from the control
// plane, and a command carrying a newline must not be able to print a second
// line of this machine's console that reads like mach's own — so the test runs a
// command with a newline in it and counts the lines that came out.
func TestTemporarySessionTracesTheCommandsItRuns(t *testing.T) {
	globalPolicy.install("")
	conn, peer := streamPipe(t)

	payload, _ := json.Marshal(protocol.ExecCommand{Command: "echo traced\necho forged", Timeout: 5})
	got := captureStdout(t, func() {
		handleExec(conn, protocol.Envelope{Type: "exec", ReqID: "trace-1", Payload: payload},
			make(chan struct{}, 1), newSessionCtl())
	})

	// The command still ran and still answered: tracing is a side channel, not a
	// replacement for the protocol.
	env := readEnvelope(t, peer)
	if env.Type != "exec_result" {
		t.Fatalf("reply frame = %q, want exec_result", env.Type)
	}
	var res protocol.ExecResult
	if err := json.Unmarshal(env.Payload, &res); err != nil {
		t.Fatalf("exec_result payload: %v", err)
	}
	if !strings.Contains(res.Stdout, "traced") || !strings.Contains(res.Stdout, "forged") {
		t.Errorf("stdout = %q, want both echoed lines", res.Stdout)
	}

	if !strings.Contains(got, `mach: exec: "echo traced\necho forged"`) {
		t.Errorf("trace = %q, want the command quoted on one line", got)
	}
	if !strings.Contains(got, "mach: exec: exit 0") {
		t.Errorf("trace = %q, want the exit status reported", got)
	}
	// Exactly two lines: the command's own newline was escaped, not printed.
	if n := strings.Count(got, "\n"); n != 2 {
		t.Errorf("trace has %d lines, want 2 — a command forged an extra console line:\n%s", n, got)
	}
}

// Only a temporary session traces: the permanent agent passes a nil *sessionCtl,
// and a session that is already shutting down has said its farewell already.
func TestAnnounceIsSilentWithoutALiveTemporarySession(t *testing.T) {
	got := captureStdout(t, func() {
		var noSession *sessionCtl // the installed agent's case
		noSession.announce("exec: %q", "echo hi")

		stopped := newSessionCtl()
		stopped.shutDown()
		stopped.announce("exec: %q", "echo hi")
	})
	if got != "" {
		t.Errorf("something with no console to trace to printed %q", got)
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it
// wrote. The agent writes its console trace with fmt.Fprintf rather than through
// the logger, so there is no seam to inject — this is the seam.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	os.Stdout = old
	_ = w.Close()
	defer r.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}
