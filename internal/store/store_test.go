package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	consumed, err := st.ConsumePairing(p, "", false)
	if err != nil || !consumed {
		t.Fatalf("consume: %v %v", consumed, err)
	}
	if m, err := st.MachineByName("bcross-x"); err != nil || m == nil {
		t.Fatalf("machine missing after consume: %v", err)
	}
	// Second consume attempt fails (single use).
	consumed2, _ := st.ConsumePairing(p, "", false)
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

// TestAuditRedactionQuotedValues is the case that used to leak: a value that is
// *immediately* quoted. The unquoted character class excludes quotes, so it
// matched the empty string at the opening quote and the replacement left the
// secret sitting in the row — `PASSWORD=[REDACTED]'hunter2'` — which is exactly
// the value a person writes and exactly what an audit reader must not see.
//
// The assertion is on the secret's absence rather than on an exact string: what
// matters is that the value is gone, not which way the quotes were tidied.
func TestAuditRedactionQuotedValues(t *testing.T) {
	for _, in := range []string{
		`export PGPASSWORD='s3cretpw'`,
		`export PGPASSWORD="s3cretpw"`,
		`mysql --password='hunter2' -e 'select 1'`,
		`mysql --password="hunter2" -e "select 1"`,
		`echo token='abc123'`,
		`echo api_key="abc123"`,
		`curl -H "Authorization: 'Bearer tok123'"`,
	} {
		got := RedactScrubs(in)
		for _, secret := range []string{"s3cretpw", "hunter2", "abc123", "tok123"} {
			if strings.Contains(got, secret) {
				t.Errorf("secret survived redaction:\n in %q\n got %q", in, got)
			}
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("nothing was redacted in %q: %q", in, got)
		}
	}
	// A quoted value must not swallow what follows it on the line: the rest of
	// the command stays readable, which is the point of keeping the keyword in
	// place rather than dropping the whole line.
	got := RedactScrubs(`psql "postgres://u:pw@h/db" -c 'echo secret="hunter2"; ls'`)
	if !strings.Contains(got, "ls") {
		t.Errorf("redaction ran past the closing quote: %q", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("secret survived: %q", got)
	}
}

// Three shapes that carried a secret straight into the row. Each is a shape
// people actually type, and each defeated the keyword rule for a different
// reason: the separator was whitespace rather than '=' or ':' (a long option),
// the keyword was not followed immediately by a separator (an env name built
// from underscores), or the secret was not next to a keyword at all (a URL's
// userinfo — including the DSN shape this project's own MACH_TEST_POSTGRES
// uses, so a pasted connection string leaked its password to every readonly
// key's audit view).
func TestAuditRedactionCoversRealSecretShapes(t *testing.T) {
	for _, in := range []string{
		`psql postgres://mach:S3cret@127.0.0.1:5432/mach`,
		`pg_dump -d "postgresql://mach:hunter2@db.internal/mach"`,
		`AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI`,
		`export AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI'`,
		`MY_APP_API_TOKEN=abc123`,
		`mysql --password hunter2 -e "select 1"`,
		`curl --api-key abc123 https://example.com`,
	} {
		got := RedactScrubs(in)
		for _, secret := range []string{"S3cret", "hunter2", "wJalrXUtnFEMI", "abc123"} {
			if strings.Contains(got, secret) {
				t.Errorf("secret survived redaction:\n in %q\n got %q", in, got)
			}
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("nothing was redacted in %q: %q", in, got)
		}
	}
	// Redaction is a mask, not a deletion: the host and the rest of the line
	// stay readable, which is the point of keeping the keyword in place.
	if got := RedactScrubs(`pg_dump postgres://mach:S3cret@db.internal/mach`); !strings.Contains(got, "db.internal") {
		t.Errorf("redaction ate the host: %q", got)
	}
	// And a credential-free URL is not a secret: it must come through untouched.
	if got := RedactScrubs("curl https://example.com/health"); got != "curl https://example.com/health" {
		t.Errorf("a credential-free URL was mangled: %q", got)
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
	if err := st.CreateMachine("bcross-a", "pub", "host", "linux", "arm64", "v", "", false); err != nil {
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

func TestConsumePairingFailureDoesNotBurnToken(t *testing.T) {
	st := testStore(t)
	// A machine with the target name already exists: the claim insert will
	// fail on UNIQUE. The pairing must survive un-consumed and inspectable.
	if err := st.CreateMachine("bcross-x", "other-pub", "", "", "", "", "", false); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	id, token, code, err := st.CreatePairing("pubkey-hex", "host", "", "", "", time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ok, why, err := st.ApprovePairing(id, code, "bcross-x"); err != nil || !ok || why != "" {
		t.Fatalf("approve: ok=%v why=%q err=%v", ok, why, err)
	}
	p := mustPairingByToken(t, st, token)
	consumed, err := st.ConsumePairing(p, "", false)
	if err == nil || consumed {
		t.Fatalf("expected error from conflicting insert, got consumed=%v err=%v", consumed, err)
	}
	// The pairing must NOT be consumed: state still readable, machine absent.
	if got := st.PairingState(p); got != "approved" {
		t.Fatalf("state after failed claim = %q, want approved (token burned)", got)
	}
	if m, _ := st.MachineByPubKey("pubkey-hex"); m != nil {
		t.Fatal("machine created despite insert failure")
	}
}

func TestApproveAfterDenyCannotResurrect(t *testing.T) {
	st := testStore(t)
	id, _, code, err := st.CreatePairing("p", "h", "", "", "", time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if changed, err := st.DenyPairing(id); err != nil || !changed {
		t.Fatalf("deny: changed=%v err=%v", changed, err)
	}
	ok, why, err := st.ApprovePairing(id, code, "bcross-x")
	// Either the pre-check sees "denied", or the guard catches the race and
	// reports "not-pending" — either way a denied pairing must not resurrect.
	if ok || err != nil || (why != "denied" && why != "not-pending") {
		t.Fatalf("approve after deny: ok=%v why=%q err=%v (denied pairing resurrected)", ok, why, err)
	}
	// Read state by ID directly.
	var state string
	if err := st.db.QueryRow(`SELECT state FROM pairings WHERE id=?`, id).Scan(&state); err != nil {
		t.Fatalf("state read: %v", err)
	}
	if state != "denied" {
		t.Fatalf("state = %q, want denied (deny lost to a concurrent approve)", state)
	}
}

func TestApprovedPairingCleanup(t *testing.T) {
	st := testStore(t)
	// Approved-but-never-claimed pairings age out of the table too: an
	// approval token must not remain claimable forever.
	id, token, code, err := st.CreatePairing("p", "h", "", "", "", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ok, why, err := st.ApprovePairing(id, code, "bcross-old"); err != nil || !ok {
		t.Fatalf("approve: %v %q %v", ok, why, err)
	}
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if _, err := st.db.Exec(`UPDATE pairings SET created_at=? WHERE id=?`, past, id); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if n, err := st.CleanupExpiredPairings(0); err != nil || n != 1 {
		t.Fatalf("cleanup removed %d (err %v), want 1", n, err)
	}
	if p, _ := st.PairingByToken(token); p != nil {
		t.Fatal("stale approved pairing still claimable after cleanup")
	}
}

func TestAuditCommandRedacted(t *testing.T) {
	st := testStore(t)
	if err := st.AuditInsert(now(), "bcross-a", `curl -H 'Authorization: Bearer tok123'`, "console:k",
		sql.NullInt64{Int64: 0, Valid: true}, "", ""); err != nil {
		t.Fatalf("insert: %v", err)
	}
	entries, err := st.AuditList("bcross-a", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list: %v len=%d", err, len(entries))
	}
	if strings.Contains(entries[0].Command, "tok123") {
		t.Fatalf("command stored unredacted: %q", entries[0].Command)
	}
	if !strings.Contains(entries[0].Command, "Authorization=[REDACTED]") {
		t.Fatalf("redaction marker missing: %q", entries[0].Command)
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

// Control-plane settings: absent means "never set" (the caller's default
// applies), reading is not an error, and writing replaces.
func TestSettingsRoundTrip(t *testing.T) {
	st := testStore(t)

	// Never set is not an error and is not a value: the caller must be able to
	// tell "absent" from "someone stored an empty string".
	v, err := st.Setting("e2e")
	if err != nil {
		t.Fatalf("read unset: %v", err)
	}
	if v != "" {
		t.Errorf("unset setting = %q, want empty", v)
	}

	if err := st.SetSetting("e2e", "off"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if v, _ := st.Setting("e2e"); v != "off" {
		t.Errorf("setting = %q, want off", v)
	}
	// Writing again replaces rather than failing on the primary key.
	if err := st.SetSetting("e2e", "on"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if v, _ := st.Setting("e2e"); v != "on" {
		t.Errorf("setting after replace = %q, want on", v)
	}

	all, err := st.Settings()
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if len(all) != 1 || all["e2e"] != "on" {
		t.Errorf("settings = %+v, want just e2e=on", all)
	}
}

// Statements are written once in the "?" form and translated for Postgres. The
// translation is what keeps one schema and one set of queries instead of two
// dialects drifting apart, so it is pinned here.
func TestRebindTranslatesPlaceholdersForPostgres(t *testing.T) {
	pg := &Store{known: "postgres"}
	sq := &Store{known: "sqlite"}
	cases := []struct {
		in   string
		want string
	}{
		{"SELECT * FROM machines WHERE name = ?", "SELECT * FROM machines WHERE name = $1"},
		{"UPDATE machines SET hostname=?, os=? WHERE id=?", "UPDATE machines SET hostname=$1, os=$2 WHERE id=$3"},
		{"SELECT 1", "SELECT 1"},
		// A ? inside a literal is data, not a parameter: counting it would
		// shift every parameter after it.
		{"SELECT '?' || name FROM machines WHERE name = ?", "SELECT '?' || name FROM machines WHERE name = $1"},
		// An escaped quote does not end the literal.
		{"SELECT 'it''s ?' WHERE a = ?", "SELECT 'it''s ?' WHERE a = $1"},
		{`SELECT "od?d" FROM machines WHERE name = ?`, `SELECT "od?d" FROM machines WHERE name = $1`},
	}
	for _, c := range cases {
		if got := pg.rebind(c.in); got != c.want {
			t.Errorf("postgres rebind(%q) = %q, want %q", c.in, got, c.want)
		}
		// The sqlite form is already correct and must pass through untouched.
		if got := sq.rebind(c.in); got != c.in {
			t.Errorf("sqlite rebind(%q) = %q, want it unchanged", c.in, got)
		}
	}
}

// Every query the package issues must be translatable: a stray "?" that means
// something else, or a query already written with $1, would break on one driver
// or the other. This walks the statements this package actually runs.
//
// Migration DDL is stricter: it carries no parameters at all, so it is
// rebind-safe for both drivers by construction, and no migration may leave a
// {{ID}} marker behind after substitution.
func TestSchemaAndQueriesTranslate(t *testing.T) {
	pg := &Store{known: "postgres"}
	sq := &Store{known: "sqlite"}
	if got := pg.idColumn(); got != "BIGSERIAL PRIMARY KEY" {
		t.Errorf("postgres id column = %q", got)
	}
	if got := sq.idColumn(); got != "INTEGER PRIMARY KEY" {
		t.Errorf("sqlite id column = %q", got)
	}
	if len(migrationSet) == 0 {
		t.Fatal("no migrations embedded")
	}
	for _, m := range migrationSet {
		if got := sq.rebind(m.sql); got != m.sql {
			t.Errorf("sqlite rebind alters migration %s: %q", m.version, got)
		}
		sql := strings.ReplaceAll(m.sql, "{{ID}}", pg.idColumn())
		if strings.Contains(sql, "{{") {
			t.Errorf("migration %s still carries a placeholder after substitution", m.version)
		}
		if strings.Contains(sql, "?") {
			t.Errorf("migration %s carries a '?' character: migration DDL must be parameter-free to translate for both drivers", m.version)
		}
		if got := pg.rebind(sql); got != sql {
			t.Errorf("postgres rebind alters migration %s DDL: %q", m.version, got)
		}
	}
	// The baseline DDL must carry the translated id column and the indexed
	// lookup column the unauthenticated bearer-key probe depends on.
	var baseline string
	for _, m := range migrationSet {
		if m.version == "0001_baseline" {
			baseline = strings.ReplaceAll(m.sql, "{{ID}}", pg.idColumn())
		}
	}
	if baseline == "" {
		t.Fatal("no 0001_baseline migration in the embedded set")
	}
	for _, want := range []string{"BIGSERIAL PRIMARY KEY", "key_lookup TEXT NOT NULL UNIQUE"} {
		if !strings.Contains(baseline, want) {
			t.Errorf("schema is missing %q", want)
		}
	}
}

// The Postgres path is exercised only when a server is available, so the suite
// stays green on a laptop without one — but the run is one env var away, and it
// covers the same surface the SQLite tests do.
//
//	MACH_TEST_POSTGRES=postgres://user:pass@localhost:5432/mach_test go test ./internal/store/
func TestPostgresStoreEndToEnd(t *testing.T) {
	dsn := os.Getenv("MACH_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set MACH_TEST_POSTGRES to run the Postgres suite")
	}
	st, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if st.Known() != "postgres" {
		t.Fatalf("driver = %q, want postgres", st.Known())
	}
	// Clear any rows a previous run left, so the test is repeatable.
	for _, q := range []string{"DELETE FROM audit", "DELETE FROM pending_updates", "DELETE FROM pairings", "DELETE FROM api_keys", "DELETE FROM machines", "DELETE FROM settings"} {
		if _, err := st.exec(q); err != nil {
			t.Fatalf("reset %q: %v", q, err)
		}
	}

	// A setting upsert (ON CONFLICT ... DO UPDATE is spelled the same way by
	// both drivers, which is why the store uses it rather than a dialect fork).
	if err := st.SetSetting("e2e", "off"); err != nil {
		t.Fatalf("set setting: %v", err)
	}
	if err := st.SetSetting("e2e", "on"); err != nil {
		t.Fatalf("replace setting: %v", err)
	}
	if v, err := st.Setting("e2e"); err != nil || v != "on" {
		t.Fatalf("setting = %q, %v", v, err)
	}

	// An auto-assigned primary key (BIGSERIAL, not INTEGER PRIMARY KEY).
	name := "pgtest-" + RandToken(4)
	if err := st.CreateMachine(name, "pub-"+name, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("create machine: %v", err)
	}
	if m, err := st.MachineByName(name); err != nil || m == nil {
		t.Fatalf("machine by name: %v %+v", err, m)
	}
	// A parameterized lookup on the indexed path.
	key := "mach_" + RandToken(24)
	if err := st.CreateAPIKey("k", key, "exec:*"); err != nil {
		t.Fatalf("create key: %v", err)
	}
	ok, gotName, scopes, err := st.APIKeyExists(key)
	if err != nil || !ok || gotName != "k" || scopes != "exec:*" {
		t.Fatalf("APIKeyExists = %v %q %q %v", ok, gotName, scopes, err)
	}
	// A transaction, an audit insert with a NULL-able exit code, and cleanup.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, token, code, err := st.CreatePairing(hex.EncodeToString(pub), "h", "linux", "amd64", "v", time.Minute)
	if err != nil {
		t.Fatalf("create pairing: %v", err)
	}
	p, err := st.PairingByToken(token)
	if err != nil || p == nil {
		t.Fatalf("pairing by token: %v %+v", err, p)
	}
	if ok, reason, err := st.ApprovePairing(p.ID, code, name+"-2"); err != nil || !ok {
		t.Fatalf("approve: ok=%v reason=%q err=%v", ok, reason, err)
	}
	if st.PairingState(p) != "approved" {
		t.Fatalf("state = %q, want approved", st.PairingState(p))
	}
	if err := st.AuditInsert(now(), name, "echo hi", "console:test", sql.NullInt64{}, "hi", ""); err != nil {
		t.Fatalf("audit insert: %v", err)
	}
	entries, err := st.AuditList(name, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit list = %+v %v", entries, err)
	}
	if err := st.DeleteMachine(name); err != nil {
		t.Fatalf("delete machine: %v", err)
	}
	if m, _ := st.MachineByName(name); m != nil {
		t.Error("machine survived DeleteMachine")
	}
	// Deleting a machine keeps its audit trail: who ran what is a record about
	// the fleet, not a property of the machine row.
	if entries, err := st.AuditList(name, 10); err != nil || len(entries) != 1 {
		t.Errorf("audit trail after delete = %+v %v", entries, err)
	}
}

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

// The challenge code is documented as ~60 bits, so every letter of the
// 31-character alphabet has to be exactly as likely as every other. `b % 31`
// is not that: 256 is not a multiple of 31, so the first eight letters came up
// on nine of the 256 byte values and the rest on eight — a sliver of the
// entropy, negligible in practice and free to remove.
//
// The mapping is asserted exactly rather than sampled: every alphabet position
// must be reachable from the same number of byte values, and the bytes that
// would break that balance must be redrawn rather than folded in.
func TestChallengeCodeBytesMapUniformly(t *testing.T) {
	counts := map[int]int{}
	for i := 0; i < 256; i++ {
		idx, ok := challengeIndex(byte(i))
		if !ok {
			continue
		}
		if idx < 0 || idx >= len(challengeAlphabet) {
			t.Fatalf("challengeIndex(%d) = %d, out of range", i, idx)
		}
		counts[idx]++
	}
	if len(counts) != len(challengeAlphabet) {
		t.Fatalf("%d of %d letters are reachable", len(counts), len(challengeAlphabet))
	}
	want := counts[0]
	for idx, n := range counts {
		if n != want {
			t.Fatalf("letter %q is reachable from %d bytes and letter %q from %d — the code is biased",
				challengeAlphabet[idx], n, challengeAlphabet[0], want)
		}
	}
	// The redrawn bytes are exactly the ones above the largest multiple of the
	// alphabet, which is what makes the counts above equal.
	if _, ok := challengeIndex(255); ok {
		t.Fatal("a byte above the rejection limit was accepted")
	}
	if _, ok := challengeIndex(247); !ok {
		t.Fatal("a byte inside the limit was rejected")
	}
}
