package store

// Tests for the command-approval store: the pending → approved/denied
// transitions and their guard, the normalized-key lookups that make two
// spellings of one command share a record, the once-only consumption, the
// session wipe, and the TTL cleanup.

import (
	"errors"
	"testing"
	"time"
)

func TestCommandApprovalCreateAndPendingLookup(t *testing.T) {
	st := testStore(t)
	id, err := st.CreateCommandApproval("bcross-web", "echo hello  world", "echo hello world", ApprovalScopeOnce, "console:ops")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id <= 0 {
		t.Fatalf("id = %d, want a row id", id)
	}
	p, err := st.PendingCommandApproval("bcross-web", "echo hello world")
	if err != nil || p == nil {
		t.Fatalf("pending lookup: %v %+v", err, p)
	}
	if p.ID != id || p.Status != "pending" || p.Command != "echo hello  world" {
		t.Fatalf("pending row = %+v, want the created row with its display text", p)
	}
	if p.CreatedAt == "" || p.ExpiresAt != "" {
		t.Fatalf("pending row timestamps = %q / %q, want created_at set and expires_at empty", p.CreatedAt, p.ExpiresAt)
	}
	// A different normalized key (or machine) is a different record.
	if p, err := st.PendingCommandApproval("bcross-web", "echo other"); err != nil || p != nil {
		t.Fatalf("pending lookup for another command = %+v %v, want none", p, err)
	}
	if p, err := st.PendingCommandApproval("bcross-db", "echo hello world"); err != nil || p != nil {
		t.Fatalf("pending lookup for another machine = %+v %v, want none", p, err)
	}
}

func TestCommandApprovalApproveAndDeny(t *testing.T) {
	st := testStore(t)
	approvedID, _ := st.CreateCommandApproval("bcross-web", "echo a", "echo a", ApprovalScopeOnce, "console:ops")
	deniedID, _ := st.CreateCommandApproval("bcross-web", "echo b", "echo b", ApprovalScopeOnce, "console:ops")

	if err := st.ApproveCommandApproval(approvedID, ApprovalScopeOnce); err != nil {
		t.Fatalf("approve: %v", err)
	}
	a, err := st.CommandApprovalByID(approvedID)
	if err != nil || a == nil {
		t.Fatalf("by id: %v %+v", err, a)
	}
	if a.Status != "approved" || a.Scope != ApprovalScopeOnce {
		t.Fatalf("approved row = %+v, want status approved and scope once", a)
	}

	if err := st.DenyCommandApproval(deniedID); err != nil {
		t.Fatalf("deny: %v", err)
	}
	d, _ := st.CommandApprovalByID(deniedID)
	if d == nil || d.Status != "denied" {
		t.Fatalf("denied row = %+v, want status denied", d)
	}

	// The approved lookup now finds the approved record for its normalized key.
	if a, err := st.ApprovedCommandApproval("bcross-web", "echo a"); err != nil || a == nil || a.ID != approvedID {
		t.Fatalf("approved lookup = %+v %v, want the approved row", a, err)
	}
	// And a denied row is never served as approved.
	if a, err := st.ApprovedCommandApproval("bcross-web", "echo b"); err != nil || a != nil {
		t.Fatalf("approved lookup for a denied command = %+v %v, want none", a, err)
	}
}

func TestCommandApprovalScopeUpgrade(t *testing.T) {
	st := testStore(t)
	id, _ := st.CreateCommandApproval("bcross-web", "echo a", "echo a", ApprovalScopeOnce, "console:ops")
	if err := st.ApproveCommandApproval(id, ApprovalScopeSession); err != nil {
		t.Fatalf("approve as session: %v", err)
	}
	a, _ := st.CommandApprovalByID(id)
	if a.Scope != ApprovalScopeSession {
		t.Fatalf("scope = %q, want the upgrade to session", a.Scope)
	}
	// A session approval belongs to its machine, so the wipe can find it.
	if a.Session != "bcross-web" {
		t.Fatalf("session = %q, want the machine name", a.Session)
	}
	// An 'once' approval carries no session.
	onceID, _ := st.CreateCommandApproval("bcross-web", "echo b", "echo b", ApprovalScopeOnce, "console:ops")
	if err := st.ApproveCommandApproval(onceID, ApprovalScopeOnce); err != nil {
		t.Fatalf("approve as once: %v", err)
	}
	a, _ = st.CommandApprovalByID(onceID)
	if a.Session != "" {
		t.Fatalf("an once approval recorded session %q, want empty", a.Session)
	}
}

func TestCommandApprovalFinalizedGuard(t *testing.T) {
	st := testStore(t)
	id, _ := st.CreateCommandApproval("bcross-web", "echo a", "echo a", ApprovalScopeOnce, "console:ops")
	if err := st.DenyCommandApproval(id); err != nil {
		t.Fatalf("deny: %v", err)
	}
	// Approve after deny: the denial stands and the caller is told.
	if err := st.ApproveCommandApproval(id, ApprovalScopeOnce); !errors.Is(err, ErrApprovalFinalized) {
		t.Fatalf("approve after deny = %v, want ErrApprovalFinalized", err)
	}
	d, _ := st.CommandApprovalByID(id)
	if d == nil || d.Status != "denied" {
		t.Fatalf("row after the refused approve = %+v, want it left denied", d)
	}
	// And deny after deny is the same answer, not a second write.
	if err := st.DenyCommandApproval(id); !errors.Is(err, ErrApprovalFinalized) {
		t.Fatalf("deny after deny = %v, want ErrApprovalFinalized", err)
	}
	// An unknown scope is refused rather than stored.
	id2, _ := st.CreateCommandApproval("bcross-web", "echo b", "echo b", ApprovalScopeOnce, "console:ops")
	if err := st.ApproveCommandApproval(id2, "forever"); err == nil {
		t.Fatal("approved with an unknown scope")
	}
}

func TestCommandApprovalListByStatus(t *testing.T) {
	st := testStore(t)
	a1, _ := st.CreateCommandApproval("bcross-web", "echo 1", "echo 1", ApprovalScopeOnce, "console:ops")
	a2, _ := st.CreateCommandApproval("bcross-web", "echo 2", "echo 2", ApprovalScopeOnce, "console:ops")
	a3, _ := st.CreateCommandApproval("bcross-web", "echo 3", "echo 3", ApprovalScopeOnce, "console:ops")
	// Approve in an order different from creation, so "newest first" is
	// observable rather than coincidental with insertion order.
	if err := st.ApproveCommandApproval(a2, ApprovalScopeOnce); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := st.DenyCommandApproval(a3); err != nil {
		t.Fatalf("deny: %v", err)
	}

	all, err := st.ListCommandApprovals("", 10)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 || all[0].ID != a3 || all[1].ID != a2 || all[2].ID != a1 {
		t.Fatalf("list all = %v, want newest first", ids(all))
	}
	approved, _ := st.ListCommandApprovals("approved", 10)
	if len(approved) != 1 || approved[0].ID != a2 {
		t.Fatalf("list approved = %v, want just %d", ids(approved), a2)
	}
	pending, _ := st.ListCommandApprovals("pending", 10)
	if len(pending) != 1 || pending[0].ID != a1 {
		t.Fatalf("list pending = %v, want just %d", ids(pending), a1)
	}
	denied, _ := st.ListCommandApprovals("denied", 10)
	if len(denied) != 1 || denied[0].ID != a3 {
		t.Fatalf("list denied = %v, want just %d", ids(denied), a3)
	}
	// "all" is the same as empty.
	got, _ := st.ListCommandApprovals("all", 10)
	if len(got) != 3 {
		t.Fatalf("list all = %v, want 3 rows", ids(got))
	}
	// And the limit is honoured.
	limited, _ := st.ListCommandApprovals("", 1)
	if len(limited) != 1 || limited[0].ID != a3 {
		t.Fatalf("limited list = %v, want only the newest", ids(limited))
	}
}

func ids(as []CommandApproval) []int64 {
	out := make([]int64, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}

func TestCommandApprovalConsumeIsOnce(t *testing.T) {
	st := testStore(t)
	id, _ := st.CreateCommandApproval("bcross-web", "echo a", "echo a", ApprovalScopeOnce, "console:ops")
	if err := st.ApproveCommandApproval(id, ApprovalScopeOnce); err != nil {
		t.Fatalf("approve: %v", err)
	}
	first, err := st.ConsumeCommandApproval(id)
	if err != nil || !first {
		t.Fatalf("first consume = %v %v, want true", first, err)
	}
	second, err := st.ConsumeCommandApproval(id)
	if err != nil || second {
		t.Fatalf("second consume = %v %v, want false: one approval is one command", second, err)
	}
	// Spent, not deleted: the decision an operator made and the run it allowed
	// stay in the record. The row must be out of every state that lets a
	// command through, though — 'spent' lets nothing through.
	if a, err := st.CommandApprovalByID(id); err != nil || a == nil || a.Status != "spent" {
		t.Fatalf("row after consumption = %+v %v, want the row kept as 'spent'", a, err)
	}
	// And a spent row is invisible to the approved lookup: a second retry of
	// the same command cannot ride it.
	if ap, err := st.ApprovedCommandApproval("bcross-web", "echo a"); err != nil || ap != nil {
		t.Fatalf("approved lookup after consumption = %+v %v, want none", ap, err)
	}
}

func TestApprovalsForSessionWipe(t *testing.T) {
	st := testStore(t)
	s1, _ := st.CreateCommandApproval("bcross-web", "echo a", "echo a", ApprovalScopeOnce, "console:ops")
	s2, _ := st.CreateCommandApproval("bcross-web", "echo b", "echo b", ApprovalScopeOnce, "console:ops")
	other, _ := st.CreateCommandApproval("bcross-db", "echo c", "echo c", ApprovalScopeOnce, "console:ops")
	if err := st.ApproveCommandApproval(s1, ApprovalScopeSession); err != nil {
		t.Fatalf("approve session: %v", err)
	}
	if err := st.ApproveCommandApproval(s2, ApprovalScopeSession); err != nil {
		t.Fatalf("approve session: %v", err)
	}
	if err := st.ApproveCommandApproval(other, ApprovalScopeSession); err != nil {
		t.Fatalf("approve session (other machine): %v", err)
	}
	// A pending 'once' row on the same machine is not session-scoped and stays.
	pending, _ := st.CreateCommandApproval("bcross-web", "echo d", "echo d", ApprovalScopeOnce, "console:ops")

	n, err := st.ApprovalsForSession("bcross-web")
	if err != nil || n != 2 {
		t.Fatalf("wipe = %d %v, want 2", n, err)
	}
	if a, _ := st.CommandApprovalByID(s1); a != nil {
		t.Fatalf("session approval survived the wipe: %+v", a)
	}
	if a, _ := st.CommandApprovalByID(other); a == nil {
		t.Fatal("another machine's session approval was wiped")
	}
	if a, _ := st.CommandApprovalByID(pending); a == nil {
		t.Fatal("a pending (not session-scoped) row was wiped")
	}
	if n, _ := st.ApprovalsForSession("bcross-web"); n != 0 {
		t.Fatalf("second wipe = %d, want 0", n)
	}
}

func TestCleanupCommandApprovals(t *testing.T) {
	st := testStore(t)
	old1, _ := st.CreateCommandApproval("bcross-web", "echo old-1", "echo old-1", ApprovalScopeOnce, "console:ops")
	old2, _ := st.CreateCommandApproval("bcross-web", "echo old-2", "echo old-2", ApprovalScopeOnce, "console:ops")
	fresh, _ := st.CreateCommandApproval("bcross-web", "echo fresh", "echo fresh", ApprovalScopeOnce, "console:ops")
	if err := st.DenyCommandApproval(old1); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if err := st.ApproveCommandApproval(old2, ApprovalScopeOnce); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Age exactly the rows the cutoff would sweep, then create a fresh pending
	// row that must survive it: the cutoff is created_at, not "when this test
	// started". Aged per row rather than with a table-wide UPDATE, so the
	// survivor is not swept by the same stroke that ages the others.
	if err := ageApproval(st, old1, 25*time.Hour); err != nil {
		t.Fatalf("age old1: %v", err)
	}
	if err := ageApproval(st, old2, 25*time.Hour); err != nil {
		t.Fatalf("age old2: %v", err)
	}
	aged, _ := st.CreateCommandApproval("bcross-web", "echo aged-pending", "echo aged-pending", ApprovalScopeOnce, "console:ops")
	if err := ageApproval(st, aged, 25*time.Hour); err != nil {
		t.Fatalf("age aged: %v", err)
	}

	n, err := st.CleanupCommandApprovals(24 * time.Hour)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	// old1 (denied), old2 (approved) and the aged pending row go; the fresh
	// pending row stays — pending rows are swept by age too, so a refused
	// command nobody ever judged does not pile up forever.
	if n != 3 {
		t.Fatalf("cleanup removed %d, want 3", n)
	}
	if a, _ := st.CommandApprovalByID(fresh); a == nil {
		t.Fatal("the fresh pending row was swept")
	}
	if a, _ := st.CommandApprovalByID(old1); a != nil {
		t.Fatal("the denied row survived its TTL")
	}
}

// ageApproval rewrites one row's created_at, the way only a test may.
func ageApproval(st *Store, id int64, back time.Duration) error {
	past := time.Now().UTC().Add(-back).Format(time.RFC3339)
	_, err := st.exec(`UPDATE command_approvals SET created_at=? WHERE id=?`, past, id)
	return err
}
