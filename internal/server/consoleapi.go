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
	if scopes != "readonly" && !hasScope(scopes, "exec") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks machine-list scope"})
		return
	}
	allowed, all := execAllowlist(scopes)
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
		if !all && !containsFold(allowed, m.Name) {
			continue
		}
		resp.Machines = append(resp.Machines, protocol.MachineInfo{
			Name: m.Name, Hostname: m.Hostname, OS: m.OS, Arch: m.Arch,
			Online: online[m.Name], AgentVer: m.AgentVer, CreatedAt: m.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
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
		command: req.Command,
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
			// E2E: audit metadata only (never plaintext).
			s.st.AuditInsert(nowRFC3339(), pe.machine, auditSealedLabel, pe.source,
				sql.NullInt64{Int64: int64(reply.Result.ExitCode), Valid: true}, "", "")
			writeJSON(w, http.StatusOK, execReplyWire{ExitCode: reply.Result.ExitCode, SealedB64: reply.Sealed})
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

// handleE2EPub serves the target machine's X25519 public key so a console
// can seal exec commands to it. Scoped like exec: a key that may run
// commands on the machine may fetch its E2E key.
func (s *Server) handleE2EPub(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	name := r.PathValue("name")
	if !keyCanExecOn(scopes, name) && scopes != "readonly" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + name})
		return
	}
	m, err := s.st.MachineByName(name)
	if err != nil || m == nil || m.Revoked {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
		return
	}
	if m.PubE2E == "" {
		// Older agents enrolled before E2E: no key registered.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "machine has no E2E key — re-enroll to enable E2E"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"machine": m.Name, "pub_e2e": m.PubE2E})
}

// execReply is what the agent pump hands back: either plaintext or sealed.
type execReply struct {
	Result protocol.ExecResult
	Sealed string // base64 sealed ExecResult (E2E mode); empty for plaintext
}

// execReplyWire is the HTTP response in E2E mode.
type execReplyWire struct {
	ExitCode  int    `json:"exit_code"`
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
	if scopes != "readonly" && !hasScope(scopes, "exec") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks audit scope"})
		return
	}
	allowed, all := execAllowlist(scopes)
	machine := r.URL.Query().Get("machine")
	if !all && machine != "" && machine != "*" && !containsFold(allowed, machine) {
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
		if !all && !containsFold(allowed, e.Machine) {
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
	if !hasScope(scopes, "exec") || !keyCanExecOn(scopes, "*") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks revoke scope"})
		return
	}
	m, err := s.st.MachineByName(req.Machine)
	if err != nil || m == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
		return
	}
	if err := s.st.RevokeMachine(req.Machine); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	if ac := s.br.Get(req.Machine); ac != nil {
		_ = ac.Conn.WriteEnvelope(protocol.Envelope{Type: "revoked"})
		ac.Conn.Close()
	}
	if req.PurgeAudit {
		_ = s.st.RemoveMachineAudit(req.Machine)
	}
	s.logf("machine revoked: %s (by %s)", req.Machine, keyName)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "revoked", "machine": req.Machine})
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
