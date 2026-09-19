package server

// Machine lifecycle actions an operator can take against a machine, shared by
// the console API and the web UI so the two can never drift apart.
//
// Three axes, deliberately distinct:
//
//   - block  — soft and reversible. The agent stays connected and keeps
//     answering keepalives; the control plane simply stops dispatching to it,
//     and any live console session is ended. Stored in the database, so it
//     outlives the broker and the process.
//   - revoke — sticky. The row stays as a tombstone, so the name and the agent
//     key remain reserved and every reconnect is refused. Invariant #10.
//   - delete — removal. The row and the key go, the name is freed, and the agent
//     is told to retire if it is connected.
//
// None of the three writes another's field. In particular blocking a revoked
// machine — or clearing a block on one — must never change whether it is revoked.

import (
	"errors"
	"net/http"

	"github.com/TevaServices/mach/internal/protocol"
	"github.com/TevaServices/mach/internal/version"
)

// errNoSuchMachine distinguishes "that machine does not exist" from a store
// failure, so callers can answer 404 rather than 500.
var errNoSuchMachine = errors.New("no such machine")

// refusal is why a dispatch was declined, as an HTTP status and a message the
// console prints verbatim.
type refusal struct {
	status int
	msg    string
}

// adminScopeOK reports whether a key may perform a fleet-wide destructive admin
// action. Revocation, deletion and blocking are all fleet-wide: they are gated
// on the unrestricted exec:* key. Enroll-scoped keys live in provisioning
// pipelines and must never reach any of them.
func adminScopeOK(scopes string) bool {
	return hasScope(scopes, "exec") && keyCanExecOn(scopes, "*")
}

// dispatchRefusal reports why a command may not be dispatched to this machine,
// or nil when it may.
//
// This is the single place the operator's soft block is enforced for
// server→agent *commands*. Every dispatch site must go through it — exec and the
// streaming relay today, and any future command frame — because a block that one
// path forgets is not a block.
//
// It reads the store on every call rather than caching: the block is operator-set
// state that has to survive a restart, and a cached copy is exactly how it would
// fail to. A store read that fails refuses the dispatch (500) rather than
// allowing it — the block is a control, and a control that fails open when its
// backing store is unreadable is not one.
//
// An unknown machine is NOT a refusal here: the callers already answer that case
// with "offline or unknown", and duplicating it would change those responses for
// no gain.
func (s *Server) dispatchRefusal(name string) *refusal {
	m, err := s.st.MachineByName(name)
	if err != nil {
		return &refusal{http.StatusInternalServerError, "cannot read machine state"}
	}
	if m == nil {
		return nil
	}
	if m.Blocked {
		return &refusal{
			http.StatusForbidden,
			"machine is blocked by the operator: " + name + " — unblock it to run commands",
		}
	}
	// Revocation is checked here too, and that closes the dispatch half of a
	// documented gap. A revoked machine is meant to be out of the fleet: it is
	// told to retire and its key can never re-enroll. But revocation is written
	// by `mach-server revoke-machine` in a *separate process*, which cannot
	// close this control plane's socket — so the connection stays open and,
	// with nothing reading the flag on the dispatch path, the machine keeps
	// accepting exec, exec_stream, stream_stdin and stream_kill until it
	// happens to reconnect. The HTTP and UI paths terminate the socket, so this
	// was only reachable from the CLI, which is exactly the case an operator
	// would not think to check.
	//
	// This does not touch the reconnect design: an agent that dials with a
	// revoked key is still answered the same way it always was (see
	// handleAgentWS), so the endpoint stays free of a name-enumeration oracle.
	if m.Revoked {
		return &refusal{
			http.StatusForbidden,
			"machine is revoked: " + name + " — re-enroll it to run commands again",
		}
	}
	return nil
}

// revokeMachine applies sticky revocation and terminates the live connection.
//
// The store write comes first, as it does on every path that touches a live
// agent: the database is the authority, and a socket left open after a failed
// write is a machine that is still reachable while the operator believes it is
// not.
func (s *Server) revokeMachine(name string, purgeAudit bool) error {
	if err := s.st.RevokeMachine(name); err != nil {
		return err
	}
	if ac := s.br.Get(name); ac != nil {
		_ = ac.Conn.WriteEnvelope(protocol.Envelope{Type: "revoked"})
		ac.Conn.Close()
	}
	if purgeAudit {
		return s.st.RemoveMachineAudit(name)
	}
	return nil
}

// deleteMachine removes a machine outright — the row and the agent key — frees
// its name for re-enrollment, and tells a connected agent to retire.
//
// Order: the row goes first, then the notice, then the close. The alternative is
// a real hazard, not a stylistic choice: dispatch resolves its target through the
// broker, which returns a live connection WITHOUT consulting the database. In a
// notify-first design, a subsequent delete failure would therefore leave a live,
// fully-authenticated socket for a machine whose row is gone — and that socket
// would still accept dispatch. Deleting first makes that impossible, and puts any
// partial failure on the visible side: the row is gone, the operator retries, and
// gets a clear 404.
//
// The notice is best-effort by construction (the agent may be offline) and never
// gates the delete. The close is unconditional.
//
// It is only ever sent on a connection that has already completed hello. An
// *unknown* name is answered elsewhere by upgrading and closing with no frame at
// all, deliberately, so the unauthenticated agent endpoint cannot be used to
// enumerate names — and a deleted machine is exactly an unknown name there.
func (s *Server) deleteMachine(name string) error {
	if err := s.st.DeleteMachine(name); err != nil {
		return err
	}
	if ac := s.br.Get(name); ac != nil {
		_ = ac.Conn.WriteEnvelope(protocol.Envelope{Type: "deleted"})
		ac.Conn.Close()
	}
	return nil
}

// blockMachine sets or clears the soft block. Blocking also ends any live console
// session for the machine; unblocking delivers an update that was held back while
// it was blocked.
func (s *Server) blockMachine(name string, blocked bool) error {
	ok, err := s.st.SetMachineBlocked(name, blocked)
	if err != nil {
		return err
	}
	if !ok {
		return errNoSuchMachine
	}
	if blocked {
		// A session opened before the block would otherwise keep feeding stdin —
		// or killing the running command — for as long as its console stayed
		// connected, which is the opposite of what blocking a machine means.
		if n := s.killStreamsForMachine(name, "machine blocked by the operator"); n > 0 {
			s.logf("machine blocked: %q, ended %d live console session(s)", name, n)
		}
		return nil
	}
	// An update held while the machine was blocked is delivered now rather than
	// waiting for a reconnect that may not come. This is the second caller of
	// PopPendingUpdate, which is why that pop is a single statement.
	if ac := s.br.Get(name); ac != nil {
		s.pushQueuedUpdate(ac.Conn, name)
	}
	return nil
}

// ---- console API: POST /v1/admin/block, POST /v1/admin/delete ----

// handleBlockMachine sets or clears a machine's soft block.
func (s *Server) handleBlockMachine(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	var req struct {
		Machine string `json:"machine"`
		// A pointer so an omitted field is a 400 rather than silently meaning
		// "false": a malformed request must never unblock a machine.
		Blocked *bool `json:"blocked"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if !adminScopeOK(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks block scope"})
		return
	}
	if req.Machine == "" || req.Blocked == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "machine and blocked are required"})
		return
	}
	if err := s.blockMachine(req.Machine, *req.Blocked); err != nil {
		if errors.Is(err, errNoSuchMachine) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	// %q: both values reach the log from outside, and a name containing newlines
	// could otherwise forge log lines.
	s.logf("machine %s: %q (by %q)", blockVerb(*req.Blocked), req.Machine, keyName)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": blockVerb(*req.Blocked), "machine": req.Machine, "blocked": *req.Blocked,
	})
}

func blockVerb(blocked bool) string {
	if blocked {
		return "blocked"
	}
	return "unblocked"
}

// handleDeleteMachine removes a machine and its key, freeing the name.
func (s *Server) handleDeleteMachine(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	var req struct {
		Machine string `json:"machine"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if !adminScopeOK(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks delete scope"})
		return
	}
	if req.Machine == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "machine is required"})
		return
	}
	m, err := s.st.MachineByName(req.Machine)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	if m == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
		return
	}
	if err := s.deleteMachine(req.Machine); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	s.logf("machine deleted: %q (by %q) — name and key are free to re-enroll", req.Machine, keyName)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "deleted", "machine": req.Machine})
}

// fleetRow is one machine as the web UI renders it. Revoked machines are
// included: delete is the only way to free a revoked machine's name, so a
// listing that hid them would make the recovery path unreachable.
type fleetRow struct {
	Name     string
	Hostname string
	OS       string
	Arch     string
	AgentVer string
	// AgentSkew marks a machine whose agent reports a version other than this
	// control plane's own. It is a hint, not a fault: a machine mid-update, or an
	// agent binary baked into an older image, is meant to differ for a while —
	// which is why the template styles it neutrally. Only set for a reported
	// version: a machine that enrolled but has never sent a hello has nothing to
	// compare, and flagging it would be an assertion about a value we do not have.
	AgentSkew bool
	Online    bool
	Blocked   bool
	Revoked   bool
	// Temporary marks an enrollment that belongs to a session rather than to a
	// machine (plain `mach` on a target). Shown so an operator can tell a
	// throwaway row from a real one, and so a session that never got to retire
	// itself is not mistaken for a machine that stopped working.
	Temporary bool
}

// fleetRows assembles the fleet listing for the UI, including revoked machines.
func (s *Server) fleetRows() ([]fleetRow, error) {
	machines, err := s.st.ListMachines()
	if err != nil {
		return nil, err
	}
	online := s.br.OnlineNames()
	rows := make([]fleetRow, 0, len(machines))
	for _, m := range machines {
		rows = append(rows, fleetRow{
			Name: m.Name, Hostname: m.Hostname, OS: m.OS, Arch: m.Arch,
			AgentVer:  m.AgentVer,
			AgentSkew: m.AgentVer != "" && m.AgentVer != version.Version,
			Online:    online[m.Name],
			Blocked:   m.Blocked, Revoked: m.Revoked, Temporary: m.Temporary,
		})
	}
	return rows, nil
}
