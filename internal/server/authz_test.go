package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/TevaServices/mach/internal/protocol"
	"github.com/TevaServices/mach/internal/store"
)

// exec posts an exec request and returns the status and body.
func execReq(t *testing.T, s *Server, key, body string) (int, string) {
	t.Helper()
	return bearerJSON(t, s.Routes(), "POST", "/v1/exec", key, body)
}

func adminKey(t *testing.T, s *Server, scopes string) string {
	t.Helper()
	key := "mach_" + store.RandToken(24)
	if err := s.st.CreateAPIKey("k", key, scopes); err != nil {
		t.Fatalf("create key: %v", err)
	}
	return key
}

// A readonly key is for watching, not for running: it must see the whole
// fleet and the whole audit trail, and must not be able to execute anything.
// (The regression this guards: readonly keys were routed through the exec
// allowlist path and saw an empty fleet and an empty audit.)
func TestReadonlyKeySeesEverythingButRunsNothing(t *testing.T) {
	s, st := newAuthTestServer(t)
	h := s.Routes()
	for _, name := range []string{"bcross-a", "bcross-b"} {
		// No E2E key: this machine is exercised over the plaintext path.
		if err := st.CreateMachine(name, "pub-"+name, "h", "linux", "amd64", "v", "", false); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		_ = st.AuditInsert("2026-01-01T00:00:00Z", name, "echo hi", "console:x", sql.NullInt64{Int64: 0, Valid: true}, "hi", "")
	}
	key := "mach_" + store.RandToken(24)
	if err := st.CreateAPIKey("ro", key, "readonly"); err != nil {
		t.Fatalf("create key: %v", err)
	}

	code, body := bearerJSON(t, h, "GET", "/v1/machines", key, "")
	if code != http.StatusOK {
		t.Fatalf("readonly machines: %d %s", code, body)
	}
	for _, want := range []string{"bcross-a", "bcross-b"} {
		if !strings.Contains(body, want) {
			t.Errorf("readonly key cannot see %s: %s", want, body)
		}
	}

	code, body = bearerJSON(t, h, "GET", "/v1/audit", key, "")
	if code != http.StatusOK {
		t.Fatalf("readonly audit: %d %s", code, body)
	}
	for _, want := range []string{"bcross-a", "bcross-b"} {
		if !strings.Contains(body, want) {
			t.Errorf("readonly key cannot see %s's audit: %s", want, body)
		}
	}

	// Read-only means read-only: exec is refused, and for the scope reason.
	code, body = execReq(t, s, key, `{"machine":"bcross-a","command":"uptime"}`)
	if code != http.StatusForbidden {
		t.Fatalf("readonly key exec returned %d, want 403 (%s)", code, body)
	}
	if !strings.Contains(body, "scoped") {
		t.Errorf("readonly exec refusal = %s, want the scope reason", body)
	}
	// And it must not be able to revoke the machines it can watch.
	if code, _ := bearerJSON(t, h, "POST", "/v1/admin/revoke", key, `{"machine":"bcross-b"}`); code != http.StatusForbidden {
		t.Fatalf("readonly key revoke returned %d, want 403", code)
	}
}

// A key scoped to one machine must not reach a different machine whose name
// merely differs in case. Machine names are case-sensitive everywhere they are
// stored and looked up, and nothing normalizes them at enrollment, so
// `bcross-web` and `bcross-Web` are two machines that can both be enrolled — and
// folding case in the scope check made a key for one authorize exec, the fleet
// listing and the audit trail of the other.
func TestScopedKeyDoesNotReachACaseVariant(t *testing.T) {
	s, st := newAuthTestServer(t)
	for _, name := range []string{"bcross-web", "bcross-Web"} {
		if err := st.CreateMachine(name, "pub-"+name, "h", "linux", "amd64", "v", "", false); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	key := adminKey(t, s, "exec:bcross-web")

	// exec: refused on the case variant, before dispatch.
	if code, body := execReq(t, s, key, `{"machine":"bcross-Web","command":"echo hi"}`); code != http.StatusForbidden {
		t.Errorf("exec on a case-variant machine returned %d, want 403 (%s)", code, body)
	}
	// The positive control, on a surface that answers without dispatching to an
	// agent (so the test does not wait out a machine that is simply offline):
	// the key's own machine passes the same scope predicate.
	if code, body := bearerJSON(t, s.Routes(), "GET", "/v1/machines/bcross-web/e2epub", key, ""); code == http.StatusForbidden {
		t.Fatalf("the key was refused on its own machine: %d %s", code, body)
	}
	if code, body := bearerJSON(t, s.Routes(), "GET", "/v1/machines/bcross-Web/e2epub", key, ""); code != http.StatusForbidden {
		t.Errorf("e2epub for a case-variant machine returned %d, want 403 (%s)", code, body)
	}
	// The read surfaces are scoped the same way: a key must not be handed the
	// fleet entry or the audit trail of a machine it cannot exec on.
	code, body := bearerJSON(t, s.Routes(), "GET", "/v1/machines", key, "")
	if code != http.StatusOK {
		t.Fatalf("machines: %d %s", code, body)
	}
	var resp protocol.MachinesResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Machines) != 1 || resp.Machines[0].Name != "bcross-web" {
		t.Errorf("fleet listing for a scoped key = %+v, want only bcross-web", resp.Machines)
	}
	if code, body := bearerJSON(t, s.Routes(), "GET", "/v1/audit?machine=bcross-Web", key, ""); code != http.StatusForbidden {
		t.Errorf("audit read for a case-variant machine returned %d, want 403 (%s)", code, body)
	}
}

// The E2E public key is the key a command is sealed to, so a key that may not
// run commands has no business fetching it: the scope table promises a readonly
// key sees the fleet and the audit trail "and nothing else". (Nothing is
// disclosed by a public key, and a readonly key cannot dispatch — the defect is
// that the predicate said otherwise, and nothing exercised it.)
func TestE2EPubRequiresExecScope(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", "e2epub-a", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ro := adminKey(t, s, "readonly")
	if code, body := bearerJSON(t, s.Routes(), "GET", "/v1/machines/bcross-a/e2epub", ro, ""); code != http.StatusForbidden {
		t.Errorf("readonly /e2epub returned %d, want 403 (%s)", code, body)
	}
	// The positive control: the same request from a key that may exec is served,
	// and carries the key.
	ex := adminKey(t, s, "exec:*")
	code, body := bearerJSON(t, s.Routes(), "GET", "/v1/machines/bcross-a/e2epub", ex, "")
	if code != http.StatusOK {
		t.Fatalf("exec key /e2epub returned %d (%s)", code, body)
	}
	if !strings.Contains(body, "e2epub-a") {
		t.Errorf("e2epub response carries no key: %s", body)
	}
}
