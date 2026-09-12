package server

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bcross/mach/internal/broker"
	"github.com/bcross/mach/internal/store"
)

func TestIPLimiter(t *testing.T) {
	l := newIPLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if l.record("1.2.3.4") {
			t.Fatalf("hit %d rejected, want allowed", i+1)
		}
	}
	if !l.record("1.2.3.4") {
		t.Fatal("4th hit allowed, want over-limit")
	}
	if l.record("5.6.7.8") {
		t.Fatal("different IP affected by another IP's limit")
	}
	if !l.blocked("1.2.3.4") {
		t.Fatal("blocked() should report over-limit IP")
	}
	if l.blocked("5.6.7.8") {
		t.Fatal("blocked() reports limit for unhit IP")
	}
}

func TestClientIPStripsPort(t *testing.T) {
	s := New(nil, nil, "bcross", t.TempDir()+"/key")
	r := httptest.NewRequest("POST", "/v1/pair/start", nil)
	r.RemoteAddr = "10.0.0.9:54321"
	if got := s.clientIP(r); got != "10.0.0.9" {
		t.Fatalf("clientIP = %q, want host only (port-keyed limiters never trip)", got)
	}
	r2 := httptest.NewRequest("POST", "/v1/pair/start", nil)
	r2.RemoteAddr = "10.0.0.9:11111"
	r2.Header.Set("X-Forwarded-For", "9.9.9.9, 10.0.0.1:1234")
	s.trustProxy = true
	if got := s.clientIP(r2); got != "10.0.0.1" {
		t.Fatalf("clientIP (trust proxy) = %q, want rightmost XFF entry host", got)
	}
}

func newAuthTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, broker.New(), "bcross", filepath.Join(t.TempDir(), "key"))
	return s, st
}

func bearerJSON(t *testing.T, h http.Handler, method, target, key string, body string) (int, string) {
	t.Helper()
	var rd *strings.Reader
	if body == "" {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// TestConsoleAPIAuthz: enroll-scoped keys (distributed into provisioning)
// must not read audits across the fleet, revoke machines, or purge trails.
func TestConsoleAPIAuthz(t *testing.T) {
	s, st := newAuthTestServer(t)
	h := s.Routes()
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "arm64", "v", "", false); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	if err := st.CreateMachine("other-b", "pub-b", "h", "linux", "arm64", "v", "", false); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	_ = st.AuditInsert("2026-01-01T00:00:00Z", "bcross-a", "echo hi", "console:x", sql.NullInt64{Int64: 0, Valid: true}, "hi", "")
	_ = st.AuditInsert("2026-01-01T00:00:01Z", "other-b", "echo other", "console:x", sql.NullInt64{Int64: 0, Valid: true}, "other", "")

	mk := func(name, scopes string) string {
		key := "mach_" + store.RandToken(24)
		if err := st.CreateAPIKey(name, key, scopes); err != nil {
			t.Fatalf("create key %s: %v", name, err)
		}
		return key
	}
	enrollKey := mk("enroll", "enroll")
	allowKey := mk("scoped", "exec:bcross-a")
	adminKey := mk("admin", "exec:*")

	// 1. Enroll key cannot read audit (any machine, or the whole log).
	if code, _ := bearerJSON(t, h, "GET", "/v1/audit", enrollKey, ""); code != http.StatusForbidden {
		t.Fatalf("enroll key read audit: %d, want 403", code)
	}
	if code, _ := bearerJSON(t, h, "GET", "/v1/audit?machine=bcross-a", enrollKey, ""); code != http.StatusForbidden {
		t.Fatalf("enroll key read targeted audit: %d, want 403", code)
	}
	// 2. Enroll key cannot revoke or purge.
	body := `{"machine":"other-b","purge_audit":true}`
	if code, _ := bearerJSON(t, h, "POST", "/v1/admin/revoke", enrollKey, body); code != http.StatusForbidden {
		t.Fatalf("enroll key revoked a machine: %d, want 403", code)
	}
	// 3. Allowlist exec key sees only its machine's audit and machine list.
	code, bodyStr := bearerJSON(t, h, "GET", "/v1/audit", allowKey, "")
	if code != http.StatusOK {
		t.Fatalf("allowlist audit: %d %s", code, bodyStr)
	}
	if strings.Contains(bodyStr, "other-b") {
		t.Fatalf("allowlist key saw another machine's audit: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "bcross-a") {
		t.Fatal("allowlist key missing its own machine's audit")
	}
	if code, _ := bearerJSON(t, h, "GET", "/v1/audit?machine=other-b", allowKey, ""); code != http.StatusForbidden {
		t.Fatalf("allowlist key read other machine audit: %d, want 403", code)
	}
	// 4. Enroll key cannot list machines.
	if code, _ := bearerJSON(t, h, "GET", "/v1/machines", enrollKey, ""); code != http.StatusForbidden {
		t.Fatalf("enroll key listed machines: %d, want 403", code)
	}
	// 5. Admin key can revoke.
	if code, _ := bearerJSON(t, h, "POST", "/v1/admin/revoke", adminKey, body); code != http.StatusOK {
		t.Fatalf("admin revoke: %d, want 200", code)
	}
	if m, _ := st.MachineByName("other-b"); m == nil || !m.Revoked {
		t.Fatal("revoke did not take effect")
	}
}

func TestHasScope(t *testing.T) {
	cases := []struct {
		scopes, want string
		ok           bool
	}{
		{"exec:*", "exec", true},
		{"exec:*", "enroll", false},
		{"enroll", "enroll", true},
		{"enroll", "exec", false},
		{"readonly", "enroll", false},
		{"exec:bcross-a", "exec", true}, // allowlist keys carry exec capability
		{"exec:bcross-a|bcross-b", "exec", true},
		{"", "exec", false},
		{"readonly", "exec", false},
	}
	for _, c := range cases {
		if got := hasScope(c.scopes, c.want); got != c.ok {
			t.Errorf("hasScope(%q, %q) = %v, want %v", c.scopes, c.want, got, c.ok)
		}
	}
}

func TestKeyCanExecOn(t *testing.T) {
	cases := []struct {
		scopes, machine string
		want            bool
	}{
		{"exec:*", "bcross-a", true},
		{"exec:*", "*", true},
		{"exec:bcross-a", "bcross-a", true},
		{"exec:bcross-a|bcross-b", "bcross-b", true},
		{"exec:bcross-a|bcross-b", "bcross-c", false},
		// comma-separated allowlists must work too, not just pipes
		{"exec:bcross-a,bcross-b", "bcross-b", true},
		{"exec:bcross-a,bcross-b", "bcross-c", false},
		// case-insensitive against the enrollment-normalized name
		{"exec:bcross-Web-1", "bcross-web-1", true},
		{"exec:bcross-web-1", "bcross-Web-1", true},
		{"readonly", "bcross-a", false},
		{"enroll", "bcross-a", false},
	}
	for _, c := range cases {
		if got := keyCanExecOn(c.scopes, c.machine); got != c.want {
			t.Errorf("keyCanExecOn(%q, %q) = %v, want %v", c.scopes, c.machine, got, c.want)
		}
	}
}

func TestListOrgs(t *testing.T) {
	t.Setenv("MACH_ORGS", "alpha, beta,Gamma,gamma,dup,")
	s := New(nil, nil, "bcross", t.TempDir()+"/key")
	got := s.ListOrgs()
	want := []string{"bcross", "alpha", "beta", "gamma", "dup"}
	if len(got) != len(want) {
		t.Fatalf("ListOrgs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ListOrgs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestOrgRegistered(t *testing.T) {
	s := New(nil, nil, "bcross", t.TempDir()+"/key")
	if !s.orgRegistered("bcross") {
		t.Error("primary org not registered")
	}
	if s.orgRegistered("nope") {
		t.Error("unknown org accepted")
	}
}

func TestNormalizeCode(t *testing.T) {
	cases := [][2]string{
		{"abcd-efgh-jklm", "ABCDEFGHJKLM"},
		{"ABCD EFGH JKLM", "ABCDEFGHJKLM"},
		{"  ab12-cd34-ef56  ", "AB12CD34EF56"},
	}
	for _, c := range cases {
		if got := normalizeCode(c[0]); got != c[1] {
			t.Errorf("normalizeCode(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestPairPageRendersOrgList(t *testing.T) {
	t.Setenv("MACH_ORGS", "alpha,beta")
	s := New(nil, nil, "bcross", t.TempDir()+"/key")
	rec := httptest.NewRecorder()
	renderPair(rec, pairPageData{
		Hostname: "host1", OS: "linux", Arch: "arm64", AgentVer: "v1",
		Token: "tok", Orgs: s.ListOrgs(),
	})
	body := rec.Body.String()
	for _, want := range []string{"bcross", "alpha", "beta", "challenge code", "Machine name"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}
