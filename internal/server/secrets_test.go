package server

// Secrets registry and guard tests, server side. The push relay's happy
// path needs a live agent; what is pinned here without one is the
// authorization shape — the org boundary, the E2E gate, and the fail-closed
// injection guard — which is where a tenancy regression would hide.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TevaServices/mach/internal/store"
)

func newSecretsTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	s := newTestServer(t)
	st := testServerStore(t, s)
	return s, st
}

func seedTwoOrgs(t *testing.T, st *store.Store) {
	t.Helper()
	if err := st.CreateMachine("bcross-web", "pub-a", "h", "linux", "amd64", "v", "11", false, "bcross"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.CreateMachine("xy-web", "pub-b", "h", "linux", "amd64", "v", "22", false, "xy"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A blocked machine, for the dispatch-refusal path.
	if err := st.CreateMachine("bcross-blocked", "pub-c", "h", "linux", "amd64", "v", "", false, "bcross"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := st.SetMachineBlocked("bcross-blocked", true); err != nil {
		t.Fatalf("block: %v", err)
	}
}

func TestSecretPushRefusesCrossOrgAndUnknown(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedTwoOrgs(t, st)
	h := s.Routes()

	post := func(key, machine, name string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/secrets/push",
			strings.NewReader(`{"machine":"`+machine+`","name":"`+name+`","sealed":"AAAA"}`))
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if err := st.CreateAPIKey("ops", "mach_bcross", "exec:*", "bcross"); err != nil {
		t.Fatalf("key: %v", err)
	}
	// Another org's machine: unknown machine, exactly like an absent one.
	code, body := post("mach_bcross", "xy-web", "DB_PASSWORD")
	if code != http.StatusNotFound || !strings.Contains(body, "unknown machine") {
		t.Fatalf("cross-org push = %d %s, want 404 unknown machine", code, body)
	}
	// A machine that does not exist at all: the same answer.
	code, _ = post("mach_bcross", "bcross-nope", "DB_PASSWORD")
	if code != http.StatusNotFound {
		t.Fatalf("unknown push = %d, want 404", code)
	}
	// An invalid name is refused on a REAL machine before anything is
	// dispatched — and without an agent connected, which is the point: a
	// malformed request must not depend on machine state.
	code, body = post("mach_bcross", "bcross-web", "MACH_TOKEN")
	if code != http.StatusBadRequest || !strings.Contains(body, "reserved") {
		t.Fatalf("bad name push = %d %s, want 400 reserved", code, body)
	}
}

func TestSecretPushRefusedWhileE2EOff(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedTwoOrgs(t, st)
	if err := st.SetSetting("e2e:bcross", "off"); err != nil {
		t.Fatalf("e2e off: %v", err)
	}
	if err := st.CreateAPIKey("ops", "mach_bcross", "exec:*", "bcross"); err != nil {
		t.Fatalf("key: %v", err)
	}
	h := s.Routes()
	req := httptest.NewRequest(http.MethodPost, "/v1/secrets/push",
		strings.NewReader(`{"machine":"bcross-web","name":"DB_PASSWORD","sealed":"AAAA"}`))
	req.Header.Set("Authorization", "Bearer mach_bcross")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("push with E2E off = %d, want 403", rec.Code)
	}
	// The refusal is in the audit trail: a value that could not be sent
	// sealed is an attempt worth recording.
	rows, err := st.AuditList("bcross", "*", 10)
	if err != nil || len(rows) == 0 {
		t.Fatalf("audit rows = %v err=%v", rows, err)
	}
	found := false
	for _, r := range rows {
		if strings.Contains(r.Command, "secret push DB_PASSWORD") {
			found = true
		}
	}
	if !found {
		t.Fatalf("push refusal not audited: %+v", rows)
	}
}

func TestSecretPushRefusedWhileBlocked(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedTwoOrgs(t, st)
	if err := st.CreateAPIKey("ops", "mach_bcross", "exec:*", "bcross"); err != nil {
		t.Fatalf("key: %v", err)
	}
	h := s.Routes()
	req := httptest.NewRequest(http.MethodPost, "/v1/secrets/push",
		strings.NewReader(`{"machine":"bcross-blocked","name":"DB_PASSWORD","sealed":"AAAA"}`))
	req.Header.Set("Authorization", "Bearer mach_bcross")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "blocked") {
		t.Fatalf("push to blocked machine = %d %s, want 403 blocked", rec.Code, rec.Body.String())
	}
}

func TestSecretsRegistryListIsOrgScoped(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedTwoOrgs(t, st)
	_ = st.UpsertSecret("bcross", "DB_PASSWORD", "console:ops")
	_ = st.UpsertSecret("xy", "AWS_KEY", "agent")
	if err := st.CreateAPIKey("ops", "mach_bcross", "exec:*", "bcross"); err != nil {
		t.Fatalf("key: %v", err)
	}
	h := s.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer mach_bcross")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("registry list = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "DB_PASSWORD") {
		t.Fatalf("registry list missing the org's secret: %s", body)
	}
	if strings.Contains(body, "AWS_KEY") {
		t.Fatalf("registry list leaked another org's secret name: %s", body)
	}
}

func TestInjectRefusal(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedTwoOrgs(t, st)
	_ = st.UpsertSecret("bcross", "DB_PASSWORD", "console:ops")

	if got := s.injectRefusal("bcross", "bcross-web", nil); got != "" {
		t.Fatalf("no names = %q, want empty", got)
	}
	if got := s.injectRefusal("bcross", "bcross-web", []string{"DB_PASSWORD"}); got != "" {
		t.Fatalf("registered name refused: %q", got)
	}
	// A name registered to ANOTHER org is unknown here: the registry is
	// tenant-scoped, like every other read.
	if got := s.injectRefusal("bcross", "bcross-web", []string{"AWS_KEY"}); got == "" || !strings.Contains(got, "AWS_KEY") {
		t.Fatalf("cross-org inject = %q, want a refusal naming the secret", got)
	}
	// An invalid name is refused before the lookup that could leak anything.
	if got := s.injectRefusal("bcross", "bcross-web", []string{"path"}); got == "" || !strings.Contains(got, "must match") {
		t.Fatalf("invalid name = %q", got)
	}
	// Too many names: a resource bound, refused with the number in it.
	many := make([]string, 65)
	for i := range many {
		many[i] = "N_" + string(rune('A'+i%26)) + string(rune('A'+(i/26)%26)) + string(rune('0'+i%10))
	}
	if got := s.injectRefusal("bcross", "bcross-web", many); got == "" || !strings.Contains(got, "too many") {
		t.Fatalf("oversized inject list = %q", got)
	}
}
