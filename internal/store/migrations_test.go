package store

// The migration runner: fresh installs, idempotent reopens, adoption of a
// pre-migration database, and the three ways history can disagree with this
// binary (an edited migration, a newer database, a missing middle step) —
// each of which must be a loud startup failure rather than a silently
// divergent schema.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// appliedMigrationRows reads the version table directly, bypassing the
// runner: what the tests assert is what the database holds.
func appliedMigrationRows(t *testing.T, st *Store) map[string]string {
	t.Helper()
	rows, err := st.db.Query(`SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var v, c, at string
		if err := rows.Scan(&v, &c, &at); err != nil {
			t.Fatalf("scan schema_migrations: %v", err)
		}
		out[v] = c + "\x00" + at
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	return out
}

// baselineDDL returns the baseline migration's SQL with the sqlite id column
// filled in, for building a database the way a pre-migration binary would
// have. It reads the embedded file rather than a copy, so the test exercises
// the same DDL the runner applies.
func baselineDDL(t *testing.T) string {
	t.Helper()
	for _, m := range migrationSet {
		if m.version == "0001_baseline" {
			return strings.ReplaceAll(m.sql, "{{ID}}", "INTEGER PRIMARY KEY")
		}
	}
	t.Fatal("no 0001_baseline in the embedded migration set")
	return ""
}

// seedPreMigrationDB creates a database exactly as the pre-migration code
// did: the schema executed directly on the raw sqlite driver, with no
// schema_migrations table.
func seedPreMigrationDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(baselineDDL(t)); err != nil {
		t.Fatalf("exec baseline DDL: %v", err)
	}
}

func TestMigrationSetIsWellFormed(t *testing.T) {
	if len(migrationSet) == 0 {
		t.Fatal("no migrations embedded")
	}
	prev := 0
	for _, m := range migrationSet {
		if !strings.HasSuffix(m.filename, ".sql") {
			t.Errorf("migration %s filename %q is not .sql", m.version, m.filename)
		}
		if m.version != strings.TrimSuffix(m.filename, ".sql") {
			t.Errorf("migration version %q does not match filename %q", m.version, m.filename)
		}
		seq, err := migrationSeq(m.version)
		if err != nil {
			t.Fatalf("migration %s: %v", m.version, err)
		}
		if seq <= prev {
			t.Errorf("migrations out of order at %s (seq %d after %d)", m.version, seq, prev)
		}
		prev = seq
		sum := sha256.Sum256([]byte(m.sql))
		if m.sha256 != hex.EncodeToString(sum[:]) {
			t.Errorf("migration %s checksum does not match its content", m.version)
		}
	}
}

func TestFreshDatabaseMigratesToHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mach.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if st.Known() != "sqlite" {
		t.Fatalf("driver = %q, want sqlite", st.Known())
	}
	want := make([]string, 0, len(migrationSet))
	for _, m := range migrationSet {
		want = append(want, m.version)
	}
	got := map[string]bool{}
	for v := range appliedMigrationRows(t, st) {
		got[v] = true
	}
	if len(got) != len(want) {
		t.Fatalf("applied versions = %v, want %v", got, want)
	}
	for _, v := range want {
		if !got[v] {
			t.Errorf("version %s missing from schema_migrations", v)
		}
	}
	// The migrated schema has to work, not just exist.
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", "", false); err != nil {
		t.Fatalf("create machine: %v", err)
	}
	if m, err := st.MachineByName("bcross-a"); err != nil || m == nil || m.Name != "bcross-a" {
		t.Fatalf("machine by name: %v %+v", err, m)
	}
}

func TestReopenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mach.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	first := appliedMigrationRows(t, st)
	st.Close()

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	second := appliedMigrationRows(t, st2)
	// Versions unchanged AND applied_at unchanged: a reopen must stamp
	// nothing, or "when did this schema change" becomes unknowable.
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("reopen changed the version table:\nfirst  %v\nsecond %v", first, second)
	}
}

func TestAdoptionOfPreMigrationDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre.db")
	seedPreMigrationDB(t, path)
	// Data written before the adoption must survive it.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO machines (name, pubkey, hostname, os, arch, agent_version, created_at, pub_e2e, temporary)
		VALUES ('bcross-old','pub-old','host','linux','arm64','v0','2026-01-01T00:00:00Z','',0)`); err != nil {
		db.Close()
		t.Fatalf("seed machine: %v", err)
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open over pre-migration database: %v", err)
	}
	defer st.Close()
	rows := appliedMigrationRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("applied versions = %v, want exactly 0001_baseline", rows)
	}
	if _, ok := rows["0001_baseline"]; !ok {
		t.Fatalf("applied versions = %v, want 0001_baseline", rows)
	}
	// The pre-existing row is readable through the normal path.
	m, err := st.MachineByName("bcross-old")
	if err != nil || m == nil || m.PubKey != "pub-old" {
		t.Fatalf("data did not survive adoption: %v %+v", err, m)
	}
	// And the store still writes.
	if err := st.CreateMachine("bcross-new", "pub-new", "host", "linux", "arm64", "v", "", false); err != nil {
		t.Fatalf("create after adoption: %v", err)
	}
}

// The pre-1.0 refusal is preserved verbatim: a pre-migration database that
// verifySchema would have refused is refused with the same message, adoption
// or not.
func TestAdoptionRefusesStaleDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.db")
	seedPreMigrationDB(t, path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := db.Exec(`ALTER TABLE machines DROP COLUMN blocked`); err != nil {
		db.Close()
		t.Skipf("this driver cannot DROP COLUMN (%v); the refusal is still pinned by TestVerifySchemaRejectsDatabaseWithoutBlocked", err)
	}
	db.Close()

	st, err := Open(path)
	if err == nil {
		st.Close()
		t.Fatal("adopted a database missing machines.blocked; want a refusal")
	}
	if !strings.Contains(err.Error(), "machines.blocked") {
		t.Fatalf("refusal does not name the missing column: %v", err)
	}
}

// An applied migration whose stored checksum no longer matches the embedded
// file means history was edited after the fact. Startup must refuse, naming
// the version, rather than build on a schema nobody can vouch for.
func TestChecksumMismatchRefusesStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tampered.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE schema_migrations SET checksum='deadbeef'`); err != nil {
		st.Close()
		t.Fatalf("tamper: %v", err)
	}
	st.Close()

	st2, err := Open(path)
	if err == nil {
		st2.Close()
		t.Fatal("opened a database whose recorded checksum was tampered with")
	}
	if !strings.Contains(err.Error(), "0001_baseline") {
		t.Fatalf("refusal does not name the version: %v", err)
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("refusal does not name the problem: %v", err)
	}
}

func TestNewerDatabaseRefusesStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.db.Exec(`INSERT INTO schema_migrations (version, checksum, applied_at) VALUES ('9999_future','abc','2026-01-01T00:00:00Z')`); err != nil {
		st.Close()
		t.Fatalf("seed future row: %v", err)
	}
	st.Close()

	st2, err := Open(path)
	if err == nil {
		st2.Close()
		t.Fatal("opened a database newer than this binary")
	}
	// Either refusal is correct — "newer than this binary" (the sequence check)
	// or "which this binary does not have" (the unknown-version check); both
	// fire on the same condition and both name the version.
	if !strings.Contains(err.Error(), "newer than this binary") &&
		!strings.Contains(err.Error(), "which this binary does not have") {
		t.Fatalf("refusal does not say the database is newer: %v", err)
	}
	if !strings.Contains(err.Error(), "9999_future") {
		t.Fatalf("refusal does not name the offending version: %v", err)
	}
}

// A row naming a migration this binary does not embed is refused even when
// its sequence would not make the database "newer": a renamed, renumbered or
// hand-inserted step is unknown history either way, and silently tolerating
// one is exactly the drift the checksum check refuses for embedded versions.
func TestUnknownAppliedMigrationRefusesStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// A row that REPLACED the baseline: same sequence, different name. The
	// database is not "newer", but this binary has never seen the step.
	if _, err := st.db.Exec(`UPDATE schema_migrations SET version='0001_rewritten'`); err != nil {
		st.Close()
		t.Fatalf("rewrite version row: %v", err)
	}
	st.Close()

	st2, err := Open(path)
	if err == nil {
		st2.Close()
		t.Fatal("opened a database carrying a migration this binary does not embed")
	}
	if !strings.Contains(err.Error(), "0001_rewritten") {
		t.Fatalf("refusal does not name the unknown version: %v", err)
	}
}

func syntheticTestShapeMigration() migration {
	body := "CREATE TABLE test_shape (id {{ID}}, v TEXT NOT NULL);\n"
	sum := sha256.Sum256([]byte(body))
	return migration{
		version:  "0002_test_shape",
		filename: "0002_test_shape.sql",
		sql:      body,
		sha256:   hex.EncodeToString(sum[:]),
	}
}

// swapMigrationSet replaces migrationSet for the duration of the test.
// Cleanup restores the ORIGINAL embedded set, not whatever was current when
// this was called: two swaps in one test (apply a synthetic migration, then
// revert to the baseline-only set to simulate an older binary) must not have
// the second swap's cleanup overwrite the first's restore — LIFO would leave
// the synthetic set in place and the "newer database" refusal silently
// untested.
func swapMigrationSet(t *testing.T, set []migration) {
	t.Helper()
	if !swappedOnce {
		origMigrationSet = migrationSet
		swappedOnce = true
		t.Cleanup(func() {
			migrationSet = origMigrationSet
			swappedOnce = false
		})
	}
	migrationSet = set
}

// origMigrationSet/swappedOnce back swapMigrationSet: the embedded set is
// captured once per test and restored exactly once, at cleanup.
var (
	origMigrationSet []migration
	swappedOnce      bool
)

func copyMigrationSet() []migration {
	out := make([]migration, len(migrationSet))
	copy(out, migrationSet)
	return out
}

// baselineOnlySet returns the embedded set reduced to the baseline alone:
// what a binary one step older than a database holds.
func baselineOnlySet() []migration {
	var out []migration
	for _, m := range migrationSet {
		if m.version == "0001_baseline" {
			out = append(out, m)
		}
	}
	return out
}

// Two migrations apply in ascending order, each stamped in its own
// transaction; and a binary that predates the second refuses the database it
// left behind, rather than running against a schema it does not know.
//
// The sets handed to swapMigrationSet are captured BEFORE the swap that
// changes what copyMigrationSet would return: "the baseline-only set" is
// built from the ORIGINAL embedded set (via cleanup restoration), never from
// the synthetic set that is live mid-test.
func TestSyntheticMigrationOrderingAndNewerRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shape.db")
	synth := syntheticTestShapeMigration()

	swapMigrationSet(t, append(copyMigrationSet(), synth))
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open with synthetic set: %v", err)
	}
	rows := appliedMigrationRows(t, st)
	if _, ok := rows["0001_baseline"]; !ok {
		t.Fatalf("baseline not applied: %v", rows)
	}
	if _, ok := rows["0002_test_shape"]; !ok {
		t.Fatalf("synthetic migration not applied: %v", rows)
	}
	var tables int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test_shape'`).Scan(&tables); err != nil {
		t.Fatalf("probe test_shape: %v", err)
	}
	if tables != 1 {
		t.Fatalf("test_shape table missing after migration; sqlite_master count = %d", tables)
	}
	st.Close()

	// The same database under a binary that only knows the baseline: refuse.
	swapMigrationSet(t, baselineOnlySet())
	st2, err := Open(path)
	if err == nil {
		st2.Close()
		t.Fatal("opened a database with a migration this binary does not have")
	}
	// The refusal is the newer-database message OR the unknown-migration one
	// (same condition, whichever check fires first); both name the version.
	if !strings.Contains(err.Error(), "newer than this binary") &&
		!strings.Contains(err.Error(), "which this binary does not have") {
		t.Fatalf("refusal does not say the database is ahead of the binary: %v", err)
	}
	if !strings.Contains(err.Error(), "0002_test_shape") {
		t.Fatalf("refusal does not name the offending version: %v", err)
	}

	// And the right binary reopens it idempotently: nothing re-applied.
	swapMigrationSet(t, append(copyMigrationSet(), synth))
	st3, err := Open(path)
	if err != nil {
		t.Fatalf("reopen with synthetic set: %v", err)
	}
	defer st3.Close()
	if again := appliedMigrationRows(t, st3); !reflect.DeepEqual(rows, again) {
		t.Fatalf("reopen re-stamped the migrations:\nfirst  %v\nsecond %v", rows, again)
	}
}
