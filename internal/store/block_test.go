package store

// Tests for the operator's soft block, the non-reserving delete, and the
// single-delivery guarantee on the queued-update pop. These back the control
// plane's web UI, where a missed or mis-ordered statement is a security hole
// rather than a cosmetic bug.

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetMachineBlockedRoundTripAndSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", "", false, "bcross"); err != nil {
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
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", "", false, "bcross"); err != nil {
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

// Delete is the recovery path revocation cannot express, and the web UI depends
// on exactly these semantics: the row goes, the audit trail stays, and both the
// name and the agent key become reusable.
func TestDeleteMachineFreesNameAndKeyKeepsAudit(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", "", false, "bcross"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.AuditInsert("2026-01-01T00:00:00Z", "bcross", "bcross-a", "echo hi", "console:x",
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
	// Audit is a record about the fleet, not a property of the machine row.
	entries, err := st.AuditList("bcross", "bcross-a", 50)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("delete purged the audit trail: %d entries", len(entries))
	}

	// The whole point: the same name AND the same key material may enroll again.
	if err := st.CreateMachine("bcross-a", "pub-a", "host", "linux", "arm64", "v", "", false, "bcross"); err != nil {
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
