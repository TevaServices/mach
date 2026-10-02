package store

// Command approvals: the record behind the control plane's answer to a
// fleet-policy refusal. When the global exec policy refuses a plaintext
// command, the server writes one of these rows instead of dispatching, and an
// operator grants or refuses it — after which the console re-runs the command
// and the approved record (never the policy) is what lets it through.
//
// The `command` column keeps the text as the console sent it, because that is
// what an audit trail and an approving operator need to see. Matching happens
// on `norm_key`, the normalized rendering the policy grammar itself matches
// against, so two invocations the block list judges identically share one
// approval record. Scope is 'once' (consumed by one dispatch) or 'session'
// (held until the machine's enrollment ends); see ApprovalsForSession.

import (
	"database/sql"
	"errors"
	"time"
)

// ErrApprovalFinalized is returned when an approval that already reached a
// terminal state (approved or denied) is approved or denied again. Callers map
// it to a 409: the operator is looking at a stale view of a decision someone
// else already made.
var ErrApprovalFinalized = errors.New("command approval already resolved")

// Approval scopes. 'once' is consumed by the first dispatch it covers;
// 'session' holds until the machine's enrollment ends (revoke, delete, block,
// or a temporary session's own retirement).
const (
	ApprovalScopeOnce    = "once"
	ApprovalScopeSession = "session"
)

type CommandApproval struct {
	ID          int64
	Machine     string
	Command     string
	Scope       string
	Session     string
	RequestedBy string
	CreatedAt   string
	Status      string
	ExpiresAt   string
}

const approvalCols = `id, machine, command, scope, session, requested_by, created_at, status, expires_at`

// scanApproval follows the store's scan contract: (nil, nil) means no row, so
// callers answer "not found" rather than mistaking a miss for an error.
func scanApproval(row interface{ Scan(...any) error }) (*CommandApproval, error) {
	a := &CommandApproval{}
	if err := row.Scan(&a.ID, &a.Machine, &a.Command, &a.Scope, &a.Session, &a.RequestedBy, &a.CreatedAt, &a.Status, &a.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return a, nil
}

// CreateCommandApproval records a pending approval for one refused command and
// returns its id. Status starts 'pending' and expires_at stays empty: the
// prompt window is a server-side timeout on the in-memory waiter, not a
// timestamp — a pending row that was never decided simply never dispatches,
// and CleanupCommandApprovals sweeps it.
func (s *Store) CreateCommandApproval(machine, command, normKey, scope, requestedBy string) (int64, error) {
	var id int64
	// RETURNING, not LastInsertId: Postgres does not implement the latter, and
	// the id is what the caller registers its waiter under.
	err := s.queryRow(`INSERT INTO command_approvals
		(machine, command, norm_key, scope, session, requested_by, created_at, status, expires_at)
		VALUES (?,?,?,?,?,?,?,'pending','') RETURNING id`,
		machine, command, normKey, scope, "", requestedBy, now()).Scan(&id)
	return id, err
}

// ApproveCommandApproval transitions a pending approval to 'approved' with the
// given scope, so a caller may upgrade a 'once' request to 'session' in the
// same write. A row already approved or denied is left alone and reported —
// approve and deny race, and deny must win.
//
// A session-scoped approval is bound to the machine the row belongs to, which
// is how ApprovalsForSession finds it later.
func (s *Store) ApproveCommandApproval(id int64, scope string) error {
	if scope != ApprovalScopeOnce && scope != ApprovalScopeSession {
		return errors.New("approval scope must be once or session")
	}
	res, err := s.exec(`UPDATE command_approvals
		SET status='approved', scope=?, session=CASE WHEN ?='session' THEN machine ELSE '' END
		WHERE id=? AND status='pending'`, scope, scope, id)
	if err != nil {
		return err
	}
	return finalizedOrOK(res)
}

// DenyCommandApproval transitions a pending approval to 'denied'. The row
// stays: the record of a refused command is as much the point of this table as
// the record of a granted one.
func (s *Store) DenyCommandApproval(id int64) error {
	res, err := s.exec(`UPDATE command_approvals SET status='denied' WHERE id=? AND status='pending'`, id)
	if err != nil {
		return err
	}
	return finalizedOrOK(res)
}

// finalizedOrOK turns "no row matched a pending transition" into the sentinel
// the callers share, keeping the driver's affected-row reporting out of the
// handlers.
func finalizedOrOK(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrApprovalFinalized
	}
	return nil
}

// PendingCommandApproval returns the newest pending approval for this machine
// and normalized command, or nil when there is none. The caller passes the
// normalized key; no further normalization happens here.
func (s *Store) PendingCommandApproval(machine, normKey string) (*CommandApproval, error) {
	return scanApproval(s.queryRow(`SELECT `+approvalCols+` FROM command_approvals
		WHERE machine=? AND norm_key=? AND status='pending' ORDER BY id DESC LIMIT 1`, machine, normKey))
}

// ApprovedCommandApproval returns the newest approved approval for this
// machine and normalized command, or nil when there is none. This is the
// lookup that lets an approved command through the policy gate.
func (s *Store) ApprovedCommandApproval(machine, normKey string) (*CommandApproval, error) {
	return scanApproval(s.queryRow(`SELECT `+approvalCols+` FROM command_approvals
		WHERE machine=? AND norm_key=? AND status='approved' ORDER BY id DESC LIMIT 1`, machine, normKey))
}

// CommandApprovalByID returns one approval, or nil when there is no such row.
func (s *Store) CommandApprovalByID(id int64) (*CommandApproval, error) {
	return scanApproval(s.queryRow(`SELECT `+approvalCols+` FROM command_approvals WHERE id=?`, id))
}

// ConsumeCommandApproval spends an approved 'once' approval, reporting whether
// this caller was the one that spent it. The update is conditional on the
// status so two concurrent retries of the same command cannot both spend one
// approval: exactly one of them dispatches. The row is kept, marked 'spent' —
// the record of an approval an operator granted and a run used is part of the
// audit trail, and deleting it would erase the very decision that allowed the
// command to run.
func (s *Store) ConsumeCommandApproval(id int64) (bool, error) {
	res, err := s.exec(`UPDATE command_approvals SET status='spent'
		WHERE id=? AND status='approved' AND scope='once'`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ListCommandApprovals returns approvals newest first. status selects one
// state ('pending', 'approved', 'denied', 'spent'); empty or 'all' means
// every row. A 'spent' row is an approval that was granted and used by the
// one dispatch it allowed — kept for the record, not for letting anything
// through.
func (s *Store) ListCommandApprovals(status string, limit int) ([]CommandApproval, error) {
	q := `SELECT ` + approvalCols + ` FROM command_approvals`
	var args []any
	if status != "" && status != "all" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommandApproval
	for rows.Next() {
		var a CommandApproval
		if err := rows.Scan(&a.ID, &a.Machine, &a.Command, &a.Scope, &a.Session, &a.RequestedBy, &a.CreatedAt, &a.Status, &a.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ApprovalsForSession deletes the session-scoped approvals for a machine and
// reports how many went. Called when the thing they were granted for ends:
// revocation, deletion, an operator block, or a temporary session retiring
// itself. A session approval that outlives the session it was granted on
// would be an approval nobody can account for.
func (s *Store) ApprovalsForSession(machine string) (int64, error) {
	res, err := s.exec(`DELETE FROM command_approvals WHERE scope='session' AND session=?`, machine)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CleanupCommandApprovals deletes rows created more than maxAge ago.
//
// It sweeps both terminal rows (forensics retention, the same 24h the pairing
// cleanup keeps) and pending rows: a pending record whose prompt window closed
// can never dispatch — silence is not consent — so leaving it would grow the
// table without bound for every refused command nobody ever judged.
func (s *Store) CleanupCommandApprovals(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339)
	res, err := s.exec(`DELETE FROM command_approvals WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
