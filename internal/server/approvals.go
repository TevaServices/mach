package server

// Command approvals: what happens when the control plane's GLOBAL exec policy
// refuses a plaintext command and an operator would rather decide than be
// refused.
//
// The flow, in one paragraph: the policy check in handleExec (and in the
// streaming relay's exec_stream) computes a refusal reason as before, but
// instead of a final refusal the server records a PENDING approval row,
// audits the attempt, and tells the console an approval is pending — 202 with
// a body on the one-shot path, a typed frame plus an ExitApprovalPending
// stream_end on the relay. Nothing is dispatched. An operator approves (an
// exec:* key through the admin API, or the web UI), and the console re-runs
// the same command; the approved record — never the policy — is what lets that
// one command through, and the dispatch carries FleetApproved so the mirrored
// copy of the same ruleset on the machine stands down for it.
//
// What this deliberately does not touch:
//
//   - Sealed exec. There is no plaintext to match, so there is nothing to
//     approve and nothing to hold: the fleet check stays skipped for a sealed
//     request (see handleExec), and approvals apply to the plaintext paths
//     only.
//   - The machine's own policy (MACH_POLICY). No approval overrides it; the
//     mirrored fleet ruleset is the only layer an approval excepts, because
//     the control plane is that ruleset's author.
//   - The operator's soft block. dispatchRefusal still runs after this gate,
//     and a blocked machine refuses an approved command like any other.
//
// "Silence is not consent": a pending record nobody decides never dispatches.
// The prompt window is a server-side timeout on the in-memory waiter; the row
// itself is swept by the hourly cleanup.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TevaServices/mach/internal/policy"
	"github.com/TevaServices/mach/internal/protocol"
	"github.com/TevaServices/mach/internal/store"
)

// approvalPromptTimeout is how long a pending approval is worth waiting on:
// the window a console retry may join, and the window an operator's decision
// can still reach a waiting console. After it, the attempt is over — the row
// stays pending until the TTL sweep, and the console re-runs the command to
// ask again.
const approvalPromptTimeout = 60 * time.Second

// approvalDecision is what an operator's action tells a waiting console.
type approvalDecision struct {
	Approved bool
	Scope    string
}

// approvalWaiter is the in-memory rendezvous for one pending approval row,
// keyed by the row's id. The console that first asked does not wait — it was
// answered 202 and gone — so the waiter exists for the retries that JOIN the
// pending approval and for the approve/deny endpoints to wake them. The DB row
// is the authority; the channel is only the alarm that fires when someone
// decides.
type approvalWaiter struct {
	id      int64
	machine string
	command string // the normalized key the row matches on
	display string // as typed, for logs
	source  string
	ch      chan approvalDecision // buffered: a decision is never lost to a slow receiver
	created time.Time
}

// registerApprovalWaiter records the rendezvous for a freshly created pending
// approval.
func (s *Server) registerApprovalWaiter(id int64, machine, normKey, display, source string) {
	s.apprMu.Lock()
	s.apprWaiters[id] = &approvalWaiter{
		id: id, machine: machine, command: normKey, display: display, source: source,
		ch:      make(chan approvalDecision, 1),
		created: time.Now(),
	}
	s.apprMu.Unlock()
}

// waitForApproval blocks until the approval is decided or its window runs out,
// and drops the waiter either way — a decision that arrives after the wait
// ended must not linger in the map. A waiter that is already gone (the window
// expired with nobody waiting) is simply not found.
func (s *Server) waitForApproval(id int64, timeout time.Duration) approvalDecision {
	if timeout <= 0 {
		return approvalDecision{}
	}
	s.apprMu.Lock()
	w := s.apprWaiters[id]
	s.apprMu.Unlock()
	if w == nil {
		return approvalDecision{}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case d := <-w.ch:
		return d
	case <-timer.C:
		s.apprMu.Lock()
		if s.apprWaiters[id] == w {
			delete(s.apprWaiters, id)
		}
		s.apprMu.Unlock()
		return approvalDecision{}
	}
}

// resolveApproval wakes whoever is waiting on an approval with a decision and
// retires the waiter, so exactly one decision is ever delivered per row.
// Reports whether a waiter was found.
func (s *Server) resolveApproval(id int64, d approvalDecision) bool {
	s.apprMu.Lock()
	w := s.apprWaiters[id]
	if w != nil {
		delete(s.apprWaiters, id)
	}
	s.apprMu.Unlock()
	if w == nil {
		return false
	}
	select {
	case w.ch <- d:
	default:
	}
	return true
}

// sweepApprovalWaiters drops waiters whose window has passed and nobody
// resolved. The hourly cleanup calls it so a pending approval that was never
// decided cannot hold its rendezvous forever.
func (s *Server) sweepApprovalWaiters() {
	cutoff := time.Now().Add(-2 * approvalPromptTimeout)
	s.apprMu.Lock()
	defer s.apprMu.Unlock()
	for id, w := range s.apprWaiters {
		if w.created.Before(cutoff) {
			delete(s.apprWaiters, id)
		}
	}
}

// approvalWaiterCount reports how many waiters are registered; for tests.
func (s *Server) approvalWaiterCount() int {
	s.apprMu.Lock()
	defer s.apprMu.Unlock()
	return len(s.apprWaiters)
}

// normalizedCommandKey renders a request's command into the canonical form the
// approval lookups match on: the same normalization the policy grammar itself
// matches against, so `echo  hi`, `echo hi` and their quoted spellings share
// one approval record. Argv mode joins the vector first — that is what the
// block list sees — because an argument list is one command and nothing
// re-parses it.
func normalizedCommandKey(command string, argv []string) string {
	if len(argv) > 0 {
		return policy.Normalize(strings.Join(argv, " "))
	}
	return policy.Normalize(command)
}

// tryApprovedApproval reports whether an APPROVED record lets this exact
// command through, consuming a 'once' grant. The consume is conditional on the
// status in the SQL itself, so two concurrent retries of the same command
// cannot both spend one approval: exactly one of them dispatches and the other
// asks again.
func (s *Server) tryApprovedApproval(machine, normKey string) bool {
	ap, err := s.st.ApprovedCommandApproval(machine, normKey)
	if err != nil || ap == nil {
		return false
	}
	if ap.Scope == store.ApprovalScopeSession {
		return true // held until the session it belongs to ends
	}
	consumed, err := s.st.ConsumeCommandApproval(ap.ID)
	return err == nil && consumed
}

// approvalPendingResponse is the 202 body for a command that was refused by
// the fleet-wide exec policy and is waiting for an operator's approval.
type approvalPendingResponse struct {
	Status     string `json:"status"` // "pending_approval"
	ApprovalID int64  `json:"approval_id"`
	Machine    string `json:"machine"`
	Command    string `json:"command"`
	Reason     string `json:"reason"`
	Timeout    int    `json:"timeout"` // seconds
}

// execPolicyGate handles a fleet-policy refusal on the one-shot path, in three
// steps: an approval already granted, a pending approval to join, or a fresh
// pending record to create. It reports whether the caller may proceed to
// dispatch (and whether the dispatch is an approved exception to the mirrored
// fleet ruleset); when it returns false, the response is already written.
func (s *Server) execPolicyGate(w http.ResponseWriter, req *protocol.ExecRequest, display, keyName, reason string) (dispatch, fleetApproved bool) {
	machine := req.Machine
	normKey := normalizedCommandKey(req.Command, req.Argv)
	source := "console:" + keyName

	// 1. An approval the operator already granted for this exact normalized
	// command. 'once' is consumed by this dispatch; 'session' stays until the
	// session ends. Either way the command is dispatched as an approved
	// exception, not silently past the policy.
	if s.tryApprovedApproval(machine, normKey) {
		return true, true
	}

	// 2. A pending record someone already asked about: join it rather than
	// pile up duplicates. The first asker was already answered 202 and gone;
	// a waiter exists only for a decision that lands while THIS request is
	// in flight — an operator approving out of band wakes it early, and the
	// wait can never outlast the row's own window. The DB row is the
	// authority, the channel only the alarm: after the wait (decision,
	// denial, or timeout) the gate re-reads what is approved and dispatches
	// on that.
	if p, err := s.st.PendingCommandApproval(machine, normKey); err == nil && p != nil {
		remaining := approvalPromptTimeout
		if created, perr := time.Parse(time.RFC3339, p.CreatedAt); perr == nil {
			remaining = approvalPromptTimeout - time.Since(created)
		}
		// The wait is capped at the one-shot timeout so the console's own
		// machinery (its request timeout, the user staring at a spinner) is
		// not stretched by the full approval window: it gets the decision or
		// the same 202/403 shape immediately after.
		wait := remaining
		if wait > 5*time.Second {
			wait = 5 * time.Second
		}
		if d := s.waitForApproval(p.ID, wait); d.Approved {
			s.grantApproval(p, d.Scope, source, "command approval granted (waiter joined)")
			if s.tryApprovedApproval(machine, normKey) {
				return true, true
			}
		}
		if s.tryApprovedApproval(machine, normKey) {
			return true, true
		}
		// Still held: nobody decided, or the grant was spent by a concurrent
		// retry. The console gets the SAME 202 with the SAME id — the pending
		// approval is still open and the operator can still decide — rather
		// than a refusal that pretends the window closed.
		writeJSON(w, http.StatusAccepted, approvalPendingResponse{
			Status: "pending_approval", ApprovalID: p.ID, Machine: machine,
			Command: display, Reason: reason, Timeout: int(approvalPromptTimeout / time.Second),
		})
		return false, false
	}

	// 3. First ask. Record the pending approval, audit the attempt (invariant
	// 16: a command the policy refused is in the record, with the reason) and
	// answer 202. The request does NOT wait: the console reports the pending
	// approval and stops, an operator decides out of band, and the console
	// re-runs the command — at which point step 1 dispatches it.
	id, err := s.st.CreateCommandApproval(machine, display, normKey, store.ApprovalScopeOnce, source)
	if err != nil {
		// Fail closed: without a record there is nothing an operator could
		// approve, so this stays a plain policy refusal.
		s.auditRow(machine, display, source, sqlNullInt(execRefused), "", reason)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "blocked by the server's global exec policy: " + reason})
		return false, false
	}
	s.registerApprovalWaiter(id, machine, normKey, display, source)
	s.auditRow(machine, display, source, sqlNullInt(execRefused), "", "awaiting operator approval: "+reason)
	writeJSON(w, http.StatusAccepted, approvalPendingResponse{
		Status: "pending_approval", ApprovalID: id, Machine: machine,
		Command: display, Reason: reason, Timeout: int(approvalPromptTimeout / time.Second),
	})
	return false, false
}

// streamExecPolicyGate is execPolicyGate for the streaming relay. The relay
// cannot block a live session on a decision — its read loop serves every frame
// the console sends, kill included — so it never joins or waits: it records the
// pending approval (or finds the existing one), audits the attempt, sends the
// typed approval_needed frame plus an ExitApprovalPending stream_end, and ends
// this command. The console decides what to do; a re-sent exec_stream is a new
// command and reaches step 1 above like any other attempt.
func (s *Server) streamExecPolicyGate(consoleConn *protocol.WSConn, machine, display, source string, start *protocol.StreamStart, reason string) (dispatch, fleetApproved bool) {
	normKey := normalizedCommandKey(start.Command, start.Argv)
	if s.tryApprovedApproval(machine, normKey) {
		return true, true
	}
	// An existing pending record is reused rather than duplicated: the console
	// is told the SAME id it may already be showing.
	if p, err := s.st.PendingCommandApproval(machine, normKey); err == nil && p != nil {
		s.sendStreamApprovalNeeded(consoleConn, machine, display, source, p.ID, reason)
		return false, false
	}
	id, err := s.st.CreateCommandApproval(machine, display, normKey, store.ApprovalScopeOnce, source)
	if err != nil {
		s.auditRow(machine, display, source, sqlNullInt(execRefused), "", reason)
		s.streamRefuse(consoleConn, machine, "blocked by the server's global exec policy: "+reason)
		return false, false
	}
	s.registerApprovalWaiter(id, machine, normKey, display, source)
	s.sendStreamApprovalNeeded(consoleConn, machine, display, source, id, reason)
	return false, false
}

// sendStreamApprovalNeeded tells the console a fleet-refused command has an
// approval pending: the typed frame carries the id to approve, and the
// terminal record ends the command with the approval-pending status so a
// script sees a distinct exit rather than a silent nothing.
func (s *Server) sendStreamApprovalNeeded(consoleConn *protocol.WSConn, machine, display, source string, id int64, reason string) {
	s.auditRow(machine, display, source, sqlNullInt(execRefused), "", "awaiting operator approval: "+reason)
	payload, _ := json.Marshal(protocol.StreamApprovalNeeded{
		ApprovalID: id, Command: display, Reason: reason,
		Timeout: int(approvalPromptTimeout / time.Second),
	})
	_ = consoleConn.WriteEnvelope(protocol.Envelope{Type: "approval_needed", Payload: payload})
	_ = consoleConn.WriteEnvelope(protocol.Envelope{
		Type: "stream_end",
		Payload: mustJSON(protocol.StreamEnd{
			ExitCode: protocol.ExitApprovalPending,
			Error: "command blocked by the server's global exec policy; approval requested (id=" +
				strconv.FormatInt(id, 10) + "): approve via the admin API or UI, then re-run",
		}),
	})
}

// clearSessionApprovals wipes the session-scoped approvals for a machine — the
// housekeeping that keeps a session approval from outliving the session it was
// granted on. Defense in depth on the block path (a block is a hard stop on
// its own, invariant 19) and correctness on revoke/delete/retire, where the
// session genuinely no longer exists.
func (s *Server) clearSessionApprovals(machine string) {
	n, err := s.st.ApprovalsForSession(machine)
	if err != nil {
		s.logf("command approvals: session wipe for %q failed: %v", machine, err)
		return
	}
	if n > 0 {
		s.logf("command approvals: session wipe for %q removed %d approval(s)", machine, n)
	}
}

// ---- console API: GET /v1/admin/approvals, POST .../approve, POST .../deny ----

// approvalScopeFromBody parses an approve request's scope, defaulting to
// 'once' when the body is absent or omits it.
func approvalScopeFromBody(r *http.Request) (string, error) {
	var req struct {
		Scope string `json:"scope"`
	}
	if err := readJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if req.Scope == "" {
		return store.ApprovalScopeOnce, nil
	}
	if req.Scope != store.ApprovalScopeOnce && req.Scope != store.ApprovalScopeSession {
		return "", errors.New("scope must be once or session")
	}
	return req.Scope, nil
}

// approvalIDFromPath parses the {id} path value of the admin approval routes.
func approvalIDFromPath(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// handleListApprovals serves the approval queue an operator acts on.
func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	if !adminScopeOK(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks approval scope"})
		return
	}
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}
	switch status {
	case "pending", "approved", "denied", "spent", "all":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be pending, approved, denied, spent or all"})
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	rows, err := s.st.ListCommandApprovals(status, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	// The listing is the operator's view of what is waiting; it deliberately
	// carries no requested_by beyond what it shows and no norm_key — the
	// normalized key is an implementation detail of matching, not something an
	// approving human needs.
	type approvalJSON struct {
		ID        int64  `json:"id"`
		Machine   string `json:"machine"`
		Command   string `json:"command"`
		Scope     string `json:"scope"`
		Session   string `json:"session"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
	}
	out := make([]approvalJSON, 0, len(rows))
	for _, a := range rows {
		out = append(out, approvalJSON{
			ID: a.ID, Machine: a.Machine, Command: a.Command, Scope: a.Scope,
			Session: a.Session, Status: a.Status, CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
}

// handleApproveApproval grants a pending approval. The scope may upgrade a
// 'once' request to 'session' in the same decision.
func (s *Server) handleApproveApproval(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	if !adminScopeOK(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks approval scope"})
		return
	}
	scope, err := approvalScopeFromBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id, ok := approvalIDFromPath(r)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown approval"})
		return
	}
	ap, err := s.st.CommandApprovalByID(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	if ap == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown approval"})
		return
	}
	if err := s.st.ApproveCommandApproval(id, scope); err != nil {
		if errors.Is(err, store.ErrApprovalFinalized) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "approval already resolved"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	s.grantApproval(ap, scope, "admin:"+keyName, "command approval granted ("+scope+")")
	writeJSON(w, http.StatusOK, map[string]any{"ok": "approved", "approval_id": id, "scope": scope})
}

// handleDenyApproval refuses a pending approval. The row stays as the record;
// a console waiting on it is woken and told, and future attempts of the same
// command go through the policy refusal path again.
func (s *Server) handleDenyApproval(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	if !adminScopeOK(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks approval scope"})
		return
	}
	id, ok := approvalIDFromPath(r)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown approval"})
		return
	}
	ap, err := s.st.CommandApprovalByID(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	if ap == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown approval"})
		return
	}
	if err := s.st.DenyCommandApproval(id); err != nil {
		if errors.Is(err, store.ErrApprovalFinalized) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "approval already resolved"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	// Wake any console joined to this approval. The DB row said denied; the
	// re-read in the gate is what actually decides, so an empty decision is
	// enough to end the wait promptly.
	s.resolveApproval(id, approvalDecision{})
	s.auditRow(ap.Machine, ap.Command, "admin:"+keyName, sqlNullInt(0), "", "command approval denied")
	s.logf("command approval %d denied for %q (by %s)", id, ap.Machine, "admin:"+keyName)
	writeJSON(w, http.StatusOK, map[string]any{"ok": "denied", "approval_id": id})
}

// grantApproval finishes a decision the caller has already written to the
// store: wake any console waiting on it and record who decided. Shared by the
// admin API and the web UI so the two cannot drift — the store write happens
// before this runs, so a woken console re-reads the row and finds it approved.
func (s *Server) grantApproval(ap *store.CommandApproval, scope, source, detail string) {
	s.resolveApproval(ap.ID, approvalDecision{Approved: true, Scope: scope})
	s.auditRow(ap.Machine, ap.Command, source, sqlNullInt(0), "", detail)
	s.logf("command approval %d granted (%s) for %q (by %s)", ap.ID, scope, ap.Machine, source)
}

// ---- web UI ----

// handleUIApprovals renders the pending-approvals fragment on its own, for the
// no-JS path and for anything that wants the panel without the fleet table.
func (s *Server) handleUIApprovals(w http.ResponseWriter, r *http.Request, sess uiSession) {
	rows, err := s.pendingApprovalRows()
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	s.renderFragment(w, sess, uiTmpl, "approvals", approvalsData{Approvals: rows, CSRF: sess.CSRF})
}

// handleUIApprove grants a pending approval from the fleet page's approvals
// panel — the same server methods the admin API runs, so the audit trail
// cannot differ by which surface was used.
func (s *Server) handleUIApprove(w http.ResponseWriter, r *http.Request, sess uiSession) {
	s.uiApprovalDecision(w, r, sess, true)
}

func (s *Server) handleUIDeny(w http.ResponseWriter, r *http.Request, sess uiSession) {
	s.uiApprovalDecision(w, r, sess, false)
}

func (s *Server) uiApprovalDecision(w http.ResponseWriter, r *http.Request, sess uiSession, approve bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		s.uiFail(w, r, http.StatusNotFound, "No approval by that id.")
		return
	}
	ap, err := s.st.CommandApprovalByID(id)
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	if ap == nil {
		s.uiFail(w, r, http.StatusNotFound, "No approval by that id.")
		return
	}
	action := "approval-deny"
	if approve {
		action = "approval-allow-once"
	}
	if approve {
		scope := r.PostFormValue("scope")
		if scope == "" {
			scope = store.ApprovalScopeOnce
		}
		if scope != store.ApprovalScopeOnce && scope != store.ApprovalScopeSession {
			s.uiFail(w, r, http.StatusBadRequest, "Scope must be once or session.")
			return
		}
		if scope == store.ApprovalScopeSession {
			action = "approval-allow-session"
		}
		if err := s.st.ApproveCommandApproval(id, scope); err != nil {
			s.uiApprovalFailure(w, r, err)
			return
		}
		s.grantApproval(ap, scope, "ui:"+sess.Ident.Subject, "command approval granted ("+scope+") via the web UI")
		s.logf("ui: command approval %d granted (%s) for %q (by %q)", id, scope, ap.Machine, sess.Ident.Subject)
		notice := "approvalgranted"
		if scope == store.ApprovalScopeSession {
			notice = "approvalgrantedsession"
		}
		s.approvalRefresh(w, r, sess, notice)
		return
	}
	if err := s.st.DenyCommandApproval(id); err != nil {
		s.uiApprovalFailure(w, r, err)
		return
	}
	s.resolveApproval(id, approvalDecision{})
	s.auditUIAction(ap.Machine, action, sess.Ident, "command approval denied via the web UI")
	s.logf("ui: command approval %d denied for %q (by %q)", id, ap.Machine, sess.Ident.Subject)
	s.approvalRefresh(w, r, sess, "approvaldenied")
}

// approvalRefresh is refreshOrRedirect for the approvals panel: the action's
// response replaces #approvals (the panel's own container), not #fleet — the
// table's polled region and this panel are siblings, and one target keeps the
// decision's refresh from reaching into the other's slot. Same shapes as
// refreshOrRedirect otherwise: htmx gets the fragment with the notice OOB,
// no-JS gets the redirect.
func (s *Server) approvalRefresh(w http.ResponseWriter, r *http.Request, sess uiSession, noticeCode string) {
	if r.Header.Get("HX-Request") != "" {
		rows, err := s.pendingApprovalRows()
		if err != nil {
			s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
			return
		}
		s.renderFragment(w, sess, uiTmpl, "approvalsaction", approvalsData{
			Approvals: rows, CSRF: sess.CSRF, Notice: uiNoticeText(noticeCode),
		})
		return
	}
	http.Redirect(w, r, "/ui?n="+noticeCode, http.StatusSeeOther)
}

// uiApprovalFailure maps a store refusal to the UI's own answer shape: an
// already-decided approval is a 409 naming what happened, not a silent no-op.
func (s *Server) uiApprovalFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrApprovalFinalized) {
		s.uiFail(w, r, http.StatusConflict, "That approval was already decided.")
		return
	}
	s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
}

// pendingApprovalRows loads the pending queue for the fleet page's approvals
// panel. Bounded the same way the API listing is: a page is not a place to
// render an unbounded table.
func (s *Server) pendingApprovalRows() ([]store.CommandApproval, error) {
	return s.st.ListCommandApprovals("pending", 50)
}

// approvalsData is the panel's view model: the pending queue, the per-session
// values its forms need, and — on an action's response — the notice the action
// renders out of band (the same field fleetData carries for the same reason).
type approvalsData struct {
	Approvals []store.CommandApproval
	CSRF      string
	Notice    string
}

var _ = sql.NullInt64{} // keep database/sql linked for the audit helpers' types
