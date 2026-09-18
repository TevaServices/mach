package store

// The two drivers do not just differ in syntax: SQLite is opened with
// MaxOpenConns(1), so every statement in the suite above runs serialized, and
// Postgres is opened with 25 — genuinely concurrent. Statements that are correct
// only because nothing can interleave are therefore correct on one driver and
// not the other, and nothing in the SQLite suite can show it.
//
// These cover the paths where that matters: two enrollments racing for one name,
// a takeover racing a permanent re-enrollment, the single-delivery update pop
// (which used to be a SELECT followed by a DELETE, safe only while one caller
// existed), and plain concurrent inserts.
//
// Skipped unless MACH_TEST_POSTGRES names a throwaway server: every test here
// empties the tables it uses.

import (
	"database/sql"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// postgresStore opens the Postgres store and clears the rows these tests share.
// It is a fresh-enough database, not an isolated one: they are written for a
// scratch server, which is what MACH_TEST_POSTGRES is for.
func postgresStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("MACH_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set MACH_TEST_POSTGRES to run the Postgres suite")
	}
	st, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	for _, q := range []string{"DELETE FROM audit", "DELETE FROM pending_updates", "DELETE FROM pairings", "DELETE FROM api_keys", "DELETE FROM machines", "DELETE FROM settings"} {
		if _, err := st.exec(q); err != nil {
			t.Fatalf("reset %q: %v", q, err)
		}
	}
	return st
}

// Four enrollments of one new name racing: exactly one wins, the rest get a
// duplicate-key error, and one row exists. On SQLite this is decided by the
// single connection; here it is decided by the constraint, which is the property
// that actually has to hold.
func TestPostgresConcurrentEnrollOfOneName(t *testing.T) {
	st := postgresStore(t)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = st.CreateMachine("pg-race", "pub", "h", "linux", "amd64", "v", "", false)
		}(i)
	}
	wg.Wait()

	won, lost := 0, 0
	for _, e := range errs {
		switch {
		case e == nil:
			won++
		case isDuplicateKey(e):
			lost++
		default:
			t.Errorf("unexpected error from a concurrent enroll: %v", e)
		}
	}
	if won != 1 || lost != 3 {
		t.Fatalf("winners=%d duplicate-errors=%d, want 1 and 3", won, lost)
	}
	ms, err := st.ListMachines()
	if err != nil || len(ms) != 1 {
		t.Fatalf("rows = %d (%v), want exactly 1", len(ms), err)
	}
}

// isDuplicateKey recognizes a unique-constraint violation on either driver,
// without the store having to expose one.
func isDuplicateKey(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "duplicate") || strings.Contains(s, "unique") ||
		strings.Contains(s, "constraint failed")
}

// Two takeovers of the same revoked row racing: at most one may report that it
// took the row over — the second must not believe it displaced something — and
// there must still be exactly one row.
func TestPostgresConcurrentTakeoverOfOneRow(t *testing.T) {
	st := postgresStore(t)
	if err := st.CreateMachine("pg-take", "old", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.RevokeMachine("pg-take"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	var wg sync.WaitGroup
	took := make([]bool, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// The same key and temp-ness for both, so whichever won is the row's
			// state either way — what is asserted is that only one reports a
			// takeover, and that no second row appeared.
			took[i], errs[i] = st.ReenrollMachine("pg-take", "newkey", "h", "linux", "amd64", "v", "", false)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("takeover %d errored: %v", i, err)
		}
	}
	winners := 0
	for _, tk := range took {
		if tk {
			winners++
		}
	}
	if winners != 1 {
		t.Errorf("%d of 2 concurrent takeovers reported taking the row, want exactly 1", winners)
	}
	ms, err := st.ListMachines()
	if err != nil || len(ms) != 1 {
		t.Fatalf("rows = %d (%v), want exactly 1", len(ms), err)
	}
	if ms[0].Revoked {
		t.Error("the row is still revoked after a takeover")
	}
}

// The invariant that matters most about reenroll, checked under a live
// concurrent enrollment: an ACTIVELY enrolled, PERMANENT machine is never
// displaced — not its name, not its key. The guard is the WHERE clause, so this
// fails if anyone ever loosens it to a caller-side check.
func TestPostgresTakeoverNeverDisplacesAnActiveMachine(t *testing.T) {
	st := postgresStore(t)
	if err := st.CreateMachine("pg-live", "live", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = st.ReenrollMachine("pg-live", "attacker", "h", "linux", "amd64", "v", "", false)
		}()
	}
	wg.Wait()
	m, err := st.MachineByName("pg-live")
	if err != nil || m == nil {
		t.Fatalf("machine gone: %v", err)
	}
	if m.PubKey != "live" {
		t.Fatalf("an active permanent machine's key was replaced: %q", m.PubKey)
	}
	if m.Revoked {
		t.Fatal("an active permanent machine was revoked by a takeover attempt")
	}
}

// The update pop is one statement (DELETE ... RETURNING) precisely so that
// concurrent callers cannot both be handed the same signed manifest — delivering
// one update twice would make the agent apply it twice. Two callers exist now
// (the connect path and unblock), which is what makes this reachable.
func TestPostgresUpdatePopDeliversOnceUnderConcurrency(t *testing.T) {
	st := postgresStore(t)
	if err := st.CreateMachine("pg-up", "pk", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.QueueUpdate("pg-up", "2.0", "sha", "", "ZGF0YQ==", "sig"); err != nil {
		t.Fatalf("queue: %v", err)
	}
	var wg sync.WaitGroup
	delivered := make([]bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _, _, _, ok, err := st.PopPendingUpdate("pg-up")
			if err != nil {
				t.Errorf("pop: %v", err)
				return
			}
			delivered[i] = ok
		}(i)
	}
	wg.Wait()
	n := 0
	for _, d := range delivered {
		if d {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the update was delivered %d times, want exactly once", n)
	}
}

// Concurrent audit inserts all land. The audit trail is the record the rest of
// the design leans on, and Postgres is where they can actually interleave.
func TestPostgresConcurrentAuditInserts(t *testing.T) {
	st := postgresStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := st.AuditInsert(time.Now().UTC().Format(time.RFC3339), "pg-a",
				"echo hi", "console:test", sql.NullInt64{Int64: 0, Valid: true}, "out", ""); err != nil {
				t.Errorf("audit insert: %v", err)
			}
		}()
	}
	wg.Wait()
	e, err := st.AuditList("pg-a", 50)
	if err != nil || len(e) != 16 {
		t.Fatalf("audit rows = %d (%v), want 16", len(e), err)
	}
}
