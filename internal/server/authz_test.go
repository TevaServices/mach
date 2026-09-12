package server

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/bcross/mach/internal/store"
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
		if err := st.CreateMachine(name, "pub-"+name, "h", "linux", "amd64", "v", ""); err != nil {
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
