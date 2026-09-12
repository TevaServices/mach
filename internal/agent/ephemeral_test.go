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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
