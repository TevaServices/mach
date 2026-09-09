package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func bigString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func TestValidOrgName(t *testing.T) {
	cases := []struct {
		org, name string
		want      bool
	}{
		{"bcross", "bcross-web-01", true},
		{"bcross", "bcross-a", true},
		{"bcross", "test-01", false}, // wrong prefix
		{"bcross", "bcross-", false}, // empty machine part
		{"bcross", "bcross-has space", false},
		{"b", "b-x", false}, // org too short
		{"mach", "mach-1", true},
		{"bcross", "bcross-" + bigString(49), false},
		{"bcross", "bcross-" + bigString(48), true},
	}
	for _, c := range cases {
		if got := ValidOrgName(c.org, c.name); got != c.want {
			t.Errorf("ValidOrgName(%q, %q) = %v, want %v", c.org, c.name, got, c.want)
		}
	}
}

func TestNewChallengeCodeEntropyAndFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c := NewChallengeCode()
		if len(c) != 14 { // 12 + 2 dashes
			t.Fatalf("bad length: %q", c)
		}
		if c[4] != '-' || c[9] != '-' {
			t.Fatalf("bad format: %q", c)
		}
		stripped := c[:4] + c[5:9] + c[10:]
		for _, ch := range stripped {
			if ch == '0' || ch == 'O' || ch == '1' || ch == 'I' || ch == 'L' {
				t.Fatalf("ambiguous char in %q", c)
			}
		}
		seen[c] = true
	}
	if len(seen) < 190 { // collisions astronomically unlikely at ~60 bits
		t.Errorf("codes repeat: %d unique of 200", len(seen))
	}
}

func TestAPIKeyScopes(t *testing.T) {
	st := testStore(t)
	if err := st.CreateAPIKey("console", "mach_abc", "exec:*"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.CreateAPIKey("enroll", "mach_def", "enroll"); err != nil {
		t.Fatalf("create: %v", err)
	}
	ok, name, scopes, err := st.APIKeyExists("mach_abc")
	if err != nil || !ok || name != "console" || scopes != "exec:*" {
		t.Fatalf("ok=%v name=%q scopes=%q err=%v", ok, name, scopes, err)
	}
	ok, _, scopes, err = st.APIKeyExists("mach_def")
	if err != nil || !ok || scopes != "enroll" {
		t.Fatalf("enroll key: ok=%v scopes=%q err=%v", ok, scopes, err)
	}
	if ok, _, _, _ := st.APIKeyExists("mach_wrong"); ok {
		t.Fatal("wrong key accepted")
	}
}

func TestPairingChallengeLockout(t *testing.T) {
	st := testStore(t)
	id, token, code, err := st.CreatePairing("pub", "host", "linux", "arm64", "v1", 10*time.Minute)
	if err != nil || id == "" || token == "" || code == "" {
		t.Fatalf("create pairing: %v", err)
	}
	p := mustPairingByToken(t, st, token)
	// 4 wrong attempts: still alive.
	for i := 1; i <= 4; i++ {
		alive, err := st.RecordPairingAttempt(id, 5)
		if err != nil || !alive {
			t.Fatalf("attempt %d: alive=%v err=%v", i, alive, err)
		}
	}
	// 5th wrong attempt expires.
	alive, err := st.RecordPairingAttempt(id, 5)
	if err != nil {
		t.Fatalf("attempt 5: %v", err)
	}
	if alive {
		t.Fatal("expected lockout after 5 attempts")
	}
	if got := st.PairingState(p); got != "expired" {
		t.Fatalf("state = %q, want expired", got)
	}
}

func TestPairingApproveFlow(t *testing.T) {
	st := testStore(t)
	id, token, code, err := st.CreatePairing("pubkey-hex", "host", "linux", "arm64", "v1", time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Wrong code does not approve.
	ok, why, err := st.ApprovePairing(id, "AAAA-AAAA-AAAA", "bcross-x")
	if ok || why != "bad-code" {
		t.Fatalf("wrong code: ok=%v why=%q err=%v", ok, why, err)
	}
	// Correct code approves (client normalizes dashes already).
	ok, why, err = st.ApprovePairing(id, code, "bcross-x")
	if err != nil || !ok || why != "" {
		t.Fatalf("approve: ok=%v why=%q err=%v", ok, why, err)
	}
	p := mustPairingByToken(t, st, token)
	consumed, err := st.ConsumePairing(p)
	if err != nil || !consumed {
		t.Fatalf("consume: %v %v", consumed, err)
	}
	if m, err := st.MachineByName("bcross-x"); err != nil || m == nil {
		t.Fatalf("machine missing after consume: %v", err)
	}
	// Second consume attempt fails (single use).
	consumed2, _ := st.ConsumePairing(p)
	if consumed2 {
		t.Fatal("pairing consumable twice")
	}
}

func TestPairingTokenLookup(t *testing.T) {
	st := testStore(t)
	_, token1, _, _ := st.CreatePairing("p1", "h", "", "", "", time.Hour)
	_, token2, _, _ := st.CreatePairing("p2", "h", "", "", "", time.Hour)
	p1 := mustPairingByToken(t, st, token1)
	p2 := mustPairingByToken(t, st, token2)
	if p1.ID == p2.ID {
		t.Fatal("two pairings resolved to the same ID")
	}
	if p, err := st.PairingByToken("nonexistent-token"); err != nil || p != nil {
		t.Fatalf("unknown token resolved a pairing: %v %v", p, err)
	}
}

func TestPairingExpiry(t *testing.T) {
	st := testStore(t)
	_, token, _, _ := st.CreatePairing("p", "h", "", "", "", time.Nanosecond)
	p := mustPairingByToken(t, st, token)
	time.Sleep(2 * time.Millisecond)
	if got := st.PairingState(p); got != "expired" {
		t.Fatalf("state = %q, want expired", got)
	}
}

func TestAuditRedaction(t *testing.T) {
	cases := [][2]string{
		{"echo password=hunter2", "echo password=[REDACTED]"},
		{"cat /etc/shadow", "cat /etc/shadow"},
		{"export TOKEN=abc", "export TOKEN=[REDACTED]"},
		{"Authorization: Bearer xyz", "Authorization=[REDACTED]"},
	}
	for _, c := range cases {
		got := RedactScrubs(c[0])
		if got != c[1] {
			t.Errorf("RedactScrubs(%q):\n got %q\nwant %q", c[0], got, c[1])
		}
	}
	// The API-key case separately (the trailing quote is preserved).
	if got := RedactScrubs(`curl -H 'X-API-Key: secret123'`); !strings.HasSuffix(got, "[REDACTED]'") || !strings.HasPrefix(got, "curl") {
		t.Errorf("api-key redaction wrong: len=%d prefix=%q", len(got), got[:min(len(got), 30)])
	}
	if got := RedactScrubs("cat /etc/shadow"); got != "cat /etc/shadow" {
		t.Errorf("non-secret line mangled: %q", got)
	}
}

func TestAuditInsertList(t *testing.T) {
	st := testStore(t)
	if err := st.AuditInsert(now(), "bcross-a", "echo hi", "console:k", sql.NullInt64{Int64: 0, Valid: true}, "hi\n", ""); err != nil {
		t.Fatalf("insert: %v", err)
	}
	entries, err := st.AuditList("bcross-a", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list: %v len=%d", err, len(entries))
	}
	if entries[0].Machine != "bcross-a" || entries[0].Command != "echo hi" || entries[0].StdoutSnip != "hi\n" {
		t.Fatalf("entry = %+v", entries[0])
	}
}

func TestMachineRevocation(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-a", "pub", "host", "linux", "arm64", "v"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.RevokeMachine("bcross-a"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	m, err := st.MachineByName("bcross-a")
	if err != nil || m == nil || !m.Revoked {
		t.Fatalf("revoked flag missing: %v %+v", err, m)
	}
}

func TestCleanupExpiredPairings(t *testing.T) {
	st := testStore(t)
	// Old terminal pairing: expires immediately; force-created in the past.
	id, _, _, _ := st.CreatePairing("p1", "h", "", "", "", time.Nanosecond)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	st.db.Exec(`UPDATE pairings SET state='expired', created_at=? WHERE id=?`, past, id)
	// Fresh pending pairing must survive.
	_, _, _, _ = st.CreatePairing("p2", "h", "", "", "", time.Hour)
	n, err := st.CleanupExpiredPairings(0)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 removal, got %d", n)
	}
	var remaining int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM pairings`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("expected 1 remaining pairing, got %d", remaining)
	}
}

func mustPairingByToken(t *testing.T, st *Store, token string) *Pairing {
	t.Helper()
	p, err := st.PairingByToken(token)
	if err != nil || p == nil {
		t.Fatalf("pairing lookup by token: %v", err)
	}
	return p
}