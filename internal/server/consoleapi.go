package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/bcross/mach/internal/store"
)

// authConsole requires a valid API key (Bearer) and rate-limits failures.
// Only FAILED attempts count toward the limit — successful requests from a
// busy CI box must never trip the limiter.
func (s *Server) authConsole(next func(w http.ResponseWriter, r *http.Request, keyName, scopes string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
			s.authFail(w, "missing bearer key")
			return
		}
		ip := s.clientIP(r)
		if s.authFails.blocked(ip) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed auth attempts"})
			return
		}
		ok, name, scopes, err := s.st.APIKeyExists(auth[len(prefix):])
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
			return
		}
		if !ok {
			s.authFails.record(ip)
			s.authFail(w, "invalid api key")
			return
		}
		next(w, r, name, scopes)
	}
}

func (s *Server) authFail(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": msg})
}

// ---- GET /v1/machines (readonly, or exec keys — allowlist-filtered) ----

func (s *Server) handleMachines(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	if !canRead(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks machine-list scope"})
		return
	}
	allowed, all := readScope(scopes)
	machines, err := s.st.ListMachines()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	online := s.br.OnlineNames()
	resp := protocol.MachinesResponse{Machines: []protocol.MachineInfo{}}
	for _, m := range machines {
		if m.Revoked {
			continue
		}
		if !all && !containsExact(allowed, m.Name) {
			continue
		}
		// The E2E signal rides each machine, not the listing: the setting is
		// per org, and a client holding a machine name can decide without
		// having to work out which org it belongs to.
		e2eState := s.e2eStateFor(m.Name)
		resp.Machines = append(resp.Machines, protocol.MachineInfo{
			Name: m.Name, Hostname: m.Hostname, OS: m.OS, Arch: m.Arch,
			Online: online[m.Name], AgentVer: m.AgentVer, CreatedAt: m.CreatedAt,
			E2E: e2eState.Mode, E2EReason: e2eState.Reason,
			Blocked: m.Blocked, Temporary: m.Temporary,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// containsExact reports whether a machine name is on an allowlist. Exact, for
// the reason spelled out on execAllowlist: the store's name matching is
// case-sensitive, so folding here would let a scoped key read the fleet listing
// and audit trail of a machine it cannot exec on — or, worse, of one that merely
// differs in case.
func containsExact(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// canRead reports whether a key may read the fleet (machine list, audit).
// Enroll keys cannot: they are handed to provisioning pipelines, which have no
// business reading another machine's command history.
func canRead(scopes string) bool {
	return hasScope(scopes, "readonly") || hasScope(scopes, "exec")
}

// readScope resolves the machine allowlist for a read-only surface.
//
// A readonly key is fleet-wide by definition ("read machines + audit, execute
// nothing"). An exec key is restricted to its allowlist. Calling
// execAllowlist for both was a bug: a readonly key has no exec: entry, so it
// came back with an empty allowlist and every machine was filtered out —
// readonly keys saw an empty fleet and an empty audit log.
func readScope(scopes string) (allowed []string, all bool) {
	if hasScope(scopes, "readonly") {
		return nil, true
	}
	return execAllowlist(scopes)
}

// ---- POST /v1/exec (exec scope; allowlist-checked per machine) ----

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	var req protocol.ExecRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if req.Machine == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "machine is required"})
		return
	}
	// Two modes: plaintext (command/argv) or E2E (sealed + e2e_pub). In E2E
	// mode the server relays an opaque blob and audits a placeholder.
	if req.Sealed == "" && req.Command == "" && len(req.Argv) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "machine and (command or argv or sealed) are required"})
		return
	}
	if req.Command != "" && len(req.Argv) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide command or argv, not both"})
		return
	}
	if (req.Sealed != "") != (req.E2EPub != "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sealed and e2e_pub must be provided together"})
		return
	}
	if !keyCanExecOn(scopes, req.Machine) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + req.Machine})
		return
	}
	display := commandForDisplay(req.Command, req.Argv)
	// Sealed (E2E) exec is the control plane's call, not the client's: it is the
	// party that cannot read ciphertext, and the one an operator points at when
	// they want a fleet that can (or cannot) be inspected. With E2E off the
	// command is refused here — before dispatch, so nothing reaches the machine
	// — and the client is told in the response why, rather than being left to
	// discover it from a console that silently ran in plaintext.
	//
	// Note what the flag does NOT do: the fleet-wide block list keeps checking
	// every plaintext command, on both paths, whether E2E is on or off. Turning
	// it off is how an operator restores that check over the one-shot path too
	// (a sealed command has no text to match); it is not a way to switch the
	// block list off.
	if req.Sealed != "" && !s.e2eStateFor(req.Machine).Enabled {
		state := s.e2eStateFor(req.Machine)
		s.st.AuditInsert(nowRFC3339(), req.Machine, auditSealedLabel, "console:"+keyName,
			sqlNullInt(execRefused), "", "sealed exec refused: E2E is off for this machine's org")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "sealed exec is disabled on this control plane: " + state.Reason})
		return
	}
	// The fleet-wide block list, checked here — after the caller is
	// authorized, before anything is dispatched — so every key, every scope
	// and every machine is subject to it. The refusal is a plain HTTP error
	// (no stream has started) and is audited like any other attempt, so a
	// blocked command shows up in the record rather than vanishing.
	//
	// A sealed request is skipped, because there is no text here to match: the
	// control plane holds ciphertext and nothing else. Running the rules against
	// the empty command that remains is not a stricter check, it is a wrong one —
	// under `allowonly` an empty command fails closed, so EVERY sealed command
	// was refused with "allowlist mode: empty command" and a deployment that
	// paired an allow-list with the default E2E posture had no sealed path at
	// all. The rules are not skipped, they are applied where the plaintext is:
	// the same ruleset is mirrored onto every agent (see pushFleetPolicy) and
	// evaluated there, at the point the sealed command is decrypted. That is the
	// whole reason the mirror exists, and why a refusal on this path is audited
	// as the sealed placeholder with exit 126 — the control plane can see that
	// something was refused, but not which rule did it.
	if req.Sealed == "" {
		if reason := s.execPolicyCheck(req.Command, req.Argv); reason != "" {
			s.auditExec(&pendingExec{machine: req.Machine, command: display, source: "console:" + keyName},
				execRefused, "", reason)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "blocked by the server's global exec policy: " + reason})
			return
		}
	}
	// The operator's soft block, checked after authorization and before anything
	// is dispatched, for the same reason the policy check sits here: it has to
	// hold for every key, every scope and every machine.
	//
	// Audited like a policy refusal — a block that silently swallowed commands
	// would be indistinguishable, in the record, from a machine that was simply
	// idle. This also replaces what used to be a 15s wait for the agent followed
	// by "machine offline": a blocked machine is online, and saying so
	// immediately is the truthful answer.
	if ref := s.dispatchRefusal(req.Machine); ref != nil {
		s.auditExec(&pendingExec{machine: req.Machine, command: display, source: "console:" + keyName},
			execRefused, "", ref.msg)
		writeJSON(w, ref.status, map[string]string{"error": ref.msg})
		return
	}
	if req.Timeout <= 0 {
		req.Timeout = 30
	}
	if req.Timeout > 600 {
		req.Timeout = 600
	}

	ac := s.br.WaitOnline(req.Machine, 15*time.Second)
	if ac == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "machine offline or unknown: " + req.Machine})
		return
	}

	reqID := store.RandToken(8)
	pe := &pendingExec{
		ch:      make(chan execReply, 1),
		machine: req.Machine,
		command: display,
		source:  "console:" + keyName,
	}
	s.pendMu.Lock()
	s.pending[reqID] = pe
	s.pendMu.Unlock()
	defer func() {
		s.pendMu.Lock()
		delete(s.pending, reqID)
		s.pendMu.Unlock()
	}()

	var cmdPayload []byte
	if req.Sealed != "" {
		// E2E: relay the sealed blob to the agent verbatim, carrying the
		// console's reply key. The server never sees the command.
		cmdPayload, _ = json.Marshal(protocol.SealedExecCommand{
			SealedB64: req.Sealed,
			ReplyPub:  strings.TrimSpace(req.E2EPub),
			Timeout:   req.Timeout,
		})
	} else {
		cmdPayload, _ = json.Marshal(protocol.ExecCommand{Command: req.Command, Argv: req.Argv, Timeout: req.Timeout})
	}
	if err := ac.Conn.WriteEnvelope(protocol.Envelope{Type: "exec", ReqID: reqID, Payload: cmdPayload}); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent connection lost"})
		return
	}

	grace := time.Duration(req.Timeout)*time.Second + 10*time.Second
	select {
	case reply := <-pe.ch:
		if reply.Sealed != "" {
			// E2E: audit metadata only (never plaintext). The exit status is the
			// one fact the control plane is documented to learn about a sealed
			// command, and it rides beside the ciphertext rather than inside it —
			// the previous code read it out of the (empty) plaintext result and so
			// recorded 0 for every sealed command, however it actually ended.
			// When the agent did not report one, the row carries NULL instead of
			// a number it would be making up.
			auditExit := sql.NullInt64{}
			if reply.SealedExit != nil {
				auditExit = sqlNullInt(*reply.SealedExit)
			}
			s.st.AuditInsert(nowRFC3339(), pe.machine, auditSealedLabel, pe.source,
				auditExit, "", "")
			writeJSON(w, http.StatusOK, execReplyWire{ExitCode: reply.SealedExit, SealedB64: reply.Sealed})
			return
		}
		s.auditExec(pe, reply.Result.ExitCode, reply.Result.Stdout, reply.Result.Stderr)
		writeJSON(w, http.StatusOK, reply.Result)
	case <-time.After(grace):
		res := protocol.ExecResult{Error: "timed out waiting for agent result"}
		s.auditExec(pe, -1, "", res.Error)
		writeJSON(w, http.StatusGatewayTimeout, res)
	}
}

const auditSealedLabel = "[E2E sealed command]"

// e2ePubResponse is the control signal a console reads before it decides how to
// send a command: whether this control plane accepts sealed exec at all, and
// the key to seal to when it does.
//
// The two facts are separate fields on purpose. "The server will not accept
// ciphertext" and "this machine never registered a key" are different problems
// with different fixes, and a client that had to tell them apart from an error
// string would get it wrong eventually. With E2E off no key is advertised at
// all, so an obeying client never seals to a key the server would refuse.
type e2ePubResponse struct {
	E2EState
	Machine string `json:"machine"`
	PubE2E  string `json:"pub_e2e,omitempty"`
	// Note explains an absent key when E2E is on.
	Note string `json:"note,omitempty"`
}

// handleE2EPub serves the target machine's X25519 public key so a console
// can seal exec commands to it, plus what this control plane accepts. Scoped
// like exec: a key that may run commands on the machine may fetch its E2E key.
func (s *Server) handleE2EPub(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	name := r.PathValue("name")
	// Exec scope only, with no readonly carve-out. The key this hands out is the
	// one used to seal commands, so a key that may not run commands has no use for
	// it — and the control table's promise is that a read-only key sees the fleet
	// and the audit trail "and nothing else". A readonly key can be refused here
	// sooner and more legibly than at the exec it would attempt next.
	if !keyCanExecOn(scopes, name) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + name})
		return
	}
	m, err := s.st.MachineByName(name)
	if err != nil || m == nil || m.Revoked {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
		return
	}
	resp := e2ePubResponse{E2EState: s.e2eStateFor(m.Name), Machine: m.Name}
	switch {
	case !resp.Enabled:
		// Nothing else to say: the reason is in E2EState.
	case m.PubE2E == "":
		// Older agents enrolled before E2E: no key registered. Not an error —
		// the client is told the server accepts sealing but this machine has no
		// key, which is a different sentence from "E2E is off".
		resp.Note = "machine has no E2E key — re-enroll to enable E2E"
	default:
		resp.PubE2E = m.PubE2E
	}
	writeJSON(w, http.StatusOK, resp)
}

// execReply is what the agent pump hands back: either plaintext or sealed.
type execReply struct {
	Result protocol.ExecResult
	Sealed string // base64 sealed ExecResult (E2E mode); empty for plaintext
	// SealedExit is the exit status the agent reported in the clear alongside a
	// sealed result. nil when it reported none (an agent older than the field),
	// which is audited as "no status" rather than as 0.
	SealedExit *int
}

// execReplyWire is the HTTP response in E2E mode. ExitCode is omitted when the
// agent did not report one, so a client is never handed a 0 it might read as
// "the command succeeded".
type execReplyWire struct {
	ExitCode  *int   `json:"exit_code,omitempty"`
	SealedB64 string `json:"sealed_b64"`
}

func (s *Server) auditExec(pe *pendingExec, exitCode int, stdout, stderr string) {
	s.st.AuditInsert(nowRFC3339(), pe.machine, pe.command, pe.source,
		sql.NullInt64{Int64: int64(exitCode), Valid: true}, stdout, stderr)
}

// ---- GET /v1/audit (readonly, or exec keys — allowlist-filtered) ----

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	// Audit entries carry command output: restrict to readonly (full) or
	// exec keys (allowlist keys see only their machines). Enroll keys get
	// nothing — they are distributed into provisioning pipelines.
	if !canRead(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks audit scope"})
		return
	}
	allowed, all := readScope(scopes)
	machine := r.URL.Query().Get("machine")
	if !all && machine != "" && machine != "*" && !containsExact(allowed, machine) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + machine})
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	entries, err := s.st.AuditList(machine, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	type auditRow struct {
		TS         string `json:"ts"`
		Machine    string `json:"machine"`
		Command    string `json:"command"`
		Source     string `json:"source"`
		ExitCode   *int64 `json:"exit_code"`
		StdoutSnip string `json:"stdout_snip,omitempty"`
		StderrSnip string `json:"stderr_snip,omitempty"`
	}
	rows := make([]auditRow, 0, len(entries))
	for _, e := range entries {
		if !all && !containsExact(allowed, e.Machine) {
			continue
		}
		var ec *int64
		if e.ExitCode.Valid {
			v := e.ExitCode.Int64
			ec = &v
		}
		rows = append(rows, auditRow{TS: e.TS, Machine: e.Machine, Command: e.Command, Source: e.Source, ExitCode: ec, StdoutSnip: e.StdoutSnip, StderrSnip: e.StderrSnip})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": rows})
}

// ---- POST /v1/admin/revoke (exec:* keys only) ----

func (s *Server) handleRevokeMachine(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	var req struct {
		Machine    string `json:"machine"`
		PurgeAudit bool   `json:"purge_audit"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	// Revocation (and especially audit purging) is a destructive,
	// fleet-wide admin action: require the unrestricted exec:* key.
	// Enroll-scoped keys live in provisioning pipelines and must never
	// revoke — or worse, erase another machine's audit trail.
	if !adminScopeOK(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks revoke scope"})
		return
	}
	m, err := s.st.MachineByName(req.Machine)
	if err != nil || m == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
		return
	}
	if err := s.revokeMachine(req.Machine, req.PurgeAudit); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	// %q, not %s: both values reach the log from outside, and a machine name
	// or key name containing newlines could forge log lines.
	s.logf("machine revoked: %q (by %q)", req.Machine, keyName)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "revoked", "machine": req.Machine})
}

// sqlNullInt is an audit exit status (or a NULL when there is none to report).
func sqlNullInt(code int) sql.NullInt64 {
	return sql.NullInt64{Int64: int64(code), Valid: true}
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
