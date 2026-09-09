package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/bcross/mach/internal/store"
)

// authConsole requires a valid API key (Bearer) and rate-limits failures.
func (s *Server) authConsole(next func(w http.ResponseWriter, r *http.Request, keyName, scopes string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
			s.authFail(w, "missing bearer key")
			return
		}
		ip := s.clientIP(r)
		if s.authFails.tooMany(ip) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed auth attempts"})
			return
		}
		ok, name, scopes, err := s.st.APIKeyExists(auth[len(prefix):])
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
			return
		}
		if !ok {
			s.authFail(w, "invalid api key")
			return
		}
		next(w, r, name, scopes)
	}
}

func (s *Server) authFail(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": msg})
}

// ---- GET /v1/machines (readonly or exec scope) ----

func (s *Server) handleMachines(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	if scopes != "readonly" && !hasScope(scopes, "exec") && !hasScope(scopes, "enroll") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks machine-list scope"})
		return
	}
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
		resp.Machines = append(resp.Machines, protocol.MachineInfo{
			Name: m.Name, Hostname: m.Hostname, OS: m.OS, Arch: m.Arch,
			Online: online[m.Name], AgentVer: m.AgentVer, CreatedAt: m.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- POST /v1/exec (exec scope; allowlist-checked per machine) ----

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	var req protocol.ExecRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if req.Machine == "" || (req.Command == "" && len(req.Argv) == 0) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "machine and (command or argv) are required"})
		return
	}
	if req.Command != "" && len(req.Argv) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide command or argv, not both"})
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
		ch:      make(chan protocol.ExecResult, 1),
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

	cmdPayload, _ := json.Marshal(protocol.ExecCommand{Command: req.Command, Argv: req.Argv, Timeout: req.Timeout})
	if err := ac.Conn.WriteEnvelope(protocol.Envelope{Type: "exec", ReqID: reqID, Payload: cmdPayload}); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent connection lost"})
		return
	}

	grace := time.Duration(req.Timeout)*time.Second + 10*time.Second
	select {
	case res := <-pe.ch:
		s.auditExec(pe, res.ExitCode, res.Stdout, res.Stderr)
		writeJSON(w, http.StatusOK, res)
	case <-time.After(grace):
		res := protocol.ExecResult{Error: "timed out waiting for agent result"}
		s.auditExec(pe, -1, "", res.Error)
		writeJSON(w, http.StatusGatewayTimeout, res)
	}
}

func (s *Server) auditExec(pe *pendingExec, exitCode int, stdout, stderr string) {
	s.st.AuditInsert(nowRFC3339(), pe.machine, pe.command, pe.source,
		sql.NullInt64{Int64: int64(exitCode), Valid: true}, stdout, stderr)
}

// ---- GET /v1/audit (readonly or exec scope) ----

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	machine := r.URL.Query().Get("machine")
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
		var ec *int64
		if e.ExitCode.Valid {
			v := e.ExitCode.Int64
			ec = &v
		}
		rows = append(rows, auditRow{TS: e.TS, Machine: e.Machine, Command: e.Command, Source: e.Source, ExitCode: ec, StdoutSnip: e.StdoutSnip, StderrSnip: e.StderrSnip})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": rows})
}

// ---- POST /v1/admin/revoke (enroll-scoped or exec:* keys) ----

func (s *Server) handleRevokeMachine(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	var req struct {
		Machine    string `json:"machine"`
		PurgeAudit bool   `json:"purge_audit"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if !hasScope(scopes, "enroll") && scopes != "exec:*" {
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