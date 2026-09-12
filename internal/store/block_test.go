package store

// Tests for the operator's soft block, the non-reserving delete, and the
// single-delivery guarantee on the queued-update pop. These back the control
// plane's web UI, where a missed or mis-ordered statement is a security hole
// rather than a cosmetic bug.

import (
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSetMachineBlockedRoundTripAndSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if ok, err := st.SetMachineBlocked("bcross-a", true); err != nil || !ok {
		t.Fatalf("block: ok=%v err=%v", ok, err)
	}
	m, err := st.MachineByName("bcross-a")
	if err != nil || m == nil || !m.Blocked {
		t.Fatalf("blocked flag missing: %v %+v", err, m)
	}
	// The point of storing this in the database rather than the broker: it has
	// to outlive the process. The broker survives nothing, so a block held there
	// would silently clear on every restart.
	st.Close()

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	m2, err := st2.MachineByName("bcross-a")
	if err != nil || m2 == nil || !m2.Blocked {
		t.Fatalf("block did not survive reopen: %v %+v", err, m2)
	}
	if ok, err := st2.SetMachineBlocked("bcross-a", false); err != nil || !ok {
		t.Fatalf("unblock: ok=%v err=%v", ok, err)
	}
	m3, err := st2.MachineByName("bcross-a")
	if err != nil || m3 == nil || m3.Blocked {
		t.Fatalf("unblock did not take effect: %v %+v", err, m3)
	}
}

func TestSetMachineBlockedUnknownMachine(t *testing.T) {
	st := testStore(t)
	// ok=false is how a caller knows to answer 404 instead of reporting a
	// success for a machine that does not exist.
	ok, err := st.SetMachineBlocked("bcross-nope", true)
	if err != nil {
		t.Fatalf("block unknown: %v", err)
	}
	if ok {
		t.Fatal("blocking an unknown machine reported success")
	}
}

// Block and revoke are independent axes. Blocking a revoked machine (or
// clearing a block on one) must never change whether it is revoked: revoke is a
// permanent tombstone, block is a reversible freeze.
func TestSetMachineBlockedDoesNotTouchRevoked(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.RevokeMachine("bcross-a"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := st.SetMachineBlocked("bcross-a", true); err != nil {
		t.Fatalf("block: %v", err)
	}
	m, _ := st.MachineByName("bcross-a")
	if m == nil || !m.Revoked || !m.Blocked {
		t.Fatalf("expected revoked and blocked together: %+v", m)
	}
	if _, err := st.SetMachineBlocked("bcross-a", false); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	m, _ = st.MachineByName("bcross-a")
	if m == nil || !m.Revoked {
		t.Fatalf("unblocking cleared revoked: %+v", m)
	}
}

// A database that predates machines.blocked must fail loudly at startup rather
// than at the first query with a raw driver error. CREATE TABLE IF NOT EXISTS
// cannot add a column, so this check is the only thing standing between an
// operator and a confusing "no such column" in production.
func TestVerifySchemaRejectsDatabaseWithoutBlocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Drop the column to reconstruct a pre-block database. SQLite has supported
	// DROP COLUMN since 3.35; modernc.org/sqlite is far past that.
	if _, err := st.db.Exec(`ALTER TABLE machines DROP COLUMN blocked`); err != nil {
		st.Close()
		t.Skipf("this driver cannot DROP COLUMN (%v); the check is still exercised by fresh opens", err)
	}
	st.Close()

	st2, err := Open(path)
	if err == nil {
		st2.Close()
		t.Fatal("opened a database missing machines.blocked; want a refusal")
	}
	if !strings.Contains(err.Error(), "machines.blocked") {
		t.Fatalf("refusal does not name the missing column: %v", err)
	}
	// The message has to tell the operator how to keep an existing fleet.
	if !strings.Contains(err.Error(), "ALTER TABLE") {
		t.Fatalf("refusal does not name the remedy: %v", err)
	}
}

// The pop had a SELECT-then-DELETE gap that was only safe while it had one
// caller. Delivering a held update on unblock is a second caller, so two
// concurrent pops would hand out the same signed manifest twice.
//
// This half pins the observable contract: once popped, the update is gone and a
// later pop reports "nothing queued" rather than replaying it. It does NOT pin
// the race — that is what TestPopPendingUpdateIsSingleDeliveryUnderRace is for,
// and the sequential case passes against the old two-statement implementation.
func TestPopPendingUpdateIsSingleDelivery(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.QueueUpdate("bcross-a", "1.2.3", "sha", "url", "data", "sig"); err != nil {
		t.Fatalf("queue: %v", err)
	}
	v, sha, url, data, sig, ok, err := st.PopPendingUpdate("bcross-a")
	if err != nil || !ok {
		t.Fatalf("first pop: ok=%v err=%v", ok, err)
	}
	if v != "1.2.3" || sha != "sha" || url != "url" || data != "data" || sig != "sig" {
		t.Fatalf("pop returned the wrong manifest: %q %q %q %q %q", v, sha, url, data, sig)
	}
	// The second pop is the whole point: the row is gone, so this must report
	// "nothing queued" rather than replaying the same manifest.
	if _, _, _, _, _, ok, err := st.PopPendingUpdate("bcross-a"); err != nil || ok {
		t.Fatalf("second pop delivered the update again: ok=%v err=%v", ok, err)
	}
}

// The race the single-statement pop exists to close: several callers popping the
// same machine at once must produce exactly ONE delivery.
//
// This is reachable even on SQLite, whose pool is capped at one connection:
// queryRow and exec acquire and release the connection separately, so two
// callers can interleave *between* the SELECT and the DELETE of the old
// implementation. Postgres (25 connections) makes the same window wider.
//
// Verified by reverting PopPendingUpdate to its two-statement form: this test
// fails there and passes with the single DELETE ... RETURNING.
func TestPopPendingUpdateIsSingleDeliveryUnderRace(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	const (
		callers    = 8
		iterations = 60
	)
	double := 0
	for i := 0; i < iterations; i++ {
		if err := st.QueueUpdate("bcross-a", "1.2.3", "sha", "url", "data", "sig"); err != nil {
			t.Fatalf("queue: %v", err)
		}
		start := make(chan struct{})
		var (
			wg    sync.WaitGroup
			mu    sync.Mutex
			got   int
			fails []error
		)
		for c := 0; c < callers; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // line them all up, then release together
				_, _, _, _, _, ok, err := st.PopPendingUpdate("bcross-a")
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					fails = append(fails, err)
				}
				if ok {
					got++
				}
			}()
		}
		close(start)
		wg.Wait()
		if len(fails) > 0 {
			t.Fatalf("pop errored: %v", fails[0])
		}
		if got != 1 {
			double++
		}
	}
	if double > 0 {
		t.Fatalf("%d of %d rounds delivered the queued update to more (or fewer) than one caller; "+
			"the pop is not a single statement", double, iterations)
	}
}

func TestHasPendingUpdateDoesNotConsume(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if has, err := st.HasPendingUpdate("bcross-a"); err != nil || has {
		t.Fatalf("empty queue reports pending: has=%v err=%v", has, err)
	}
	if err := st.QueueUpdate("bcross-a", "1.2.3", "sha", "url", "data", "sig"); err != nil {
		t.Fatalf("queue: %v", err)
	}
	// Read twice, then pop: observing the queue must not drain it.
	for i := 0; i < 2; i++ {
		if has, err := st.HasPendingUpdate("bcross-a"); err != nil || !has {
			t.Fatalf("probe %d reports no queued update: has=%v err=%v", i, has, err)
		}
	}
	if _, _, _, _, _, ok, err := st.PopPendingUpdate("bcross-a"); err != nil || !ok {
		t.Fatalf("pop after probes: ok=%v err=%v", ok, err)
	}
}

// Delete is the recovery path revocation cannot express, and the web UI depends
// on exactly these semantics: the row goes, the queued update goes, the audit
// trail stays, and both the name and the agent key become reusable.
func TestDeleteMachineFreesNameAndKeyKeepsAudit(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.QueueUpdate("bcross-a", "1.2.3", "sha", "url", "data", "sig"); err != nil {
		t.Fatalf("queue: %v", err)
	}
	if err := st.AuditInsert("2026-01-01T00:00:00Z", "bcross-a", "echo hi", "console:x",
		sql.NullInt64{Int64: 0, Valid: true}, "hi", ""); err != nil {
		t.Fatalf("audit: %v", err)
	}

	if err := st.DeleteMachine("bcross-a"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if m, err := st.MachineByName("bcross-a"); err != nil || m != nil {
		t.Fatalf("machine row survived delete: %v %+v", err, m)
	}
	if m, err := st.MachineByPubKey("pub-a"); err != nil || m != nil {
		t.Fatalf("agent key survived delete: %v %+v", err, m)
	}
	if has, err := st.HasPendingUpdate("bcross-a"); err != nil || has {
		t.Fatalf("queued update survived delete: has=%v err=%v", has, err)
	}
	// Audit is a record about the fleet, not a property of the machine row.
	entries, err := st.AuditList("bcross-a", 50)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("delete purged the audit trail: %d entries", len(entries))
	}

	// The whole point: the same name AND the same key material may enroll again.
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", ""); err != nil {
		t.Fatalf("re-enroll with the freed name and key: %v", err)
	}
	m, err := st.MachineByName("bcross-a")
	if err != nil || m == nil {
		t.Fatalf("re-enrolled machine missing: %v %+v", err, m)
	}
	// The re-enrolled row is not born blocked.
	if m.Blocked || m.Revoked {
		t.Fatalf("re-enrolled machine inherited state: %+v", m)
	}
}
