package server

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
	"github.com/TevaServices/mach/internal/store"
)

// authConsole requires a valid API key (Bearer) and rate-limits failures.
// Only FAILED attempts count toward the limit — successful requests from a
// busy CI box must never trip the limiter.
//
// The key's org binding travels with the request into every handler: it is
// the tenant the key belongs to, and every machine name the handler sees is
// resolved within it. The binding lives in the api_keys row, so a key cannot
// present an org it does not hold.
func (s *Server) authConsole(next func(w http.ResponseWriter, r *http.Request, keyName, scopes, keyOrg string)) http.HandlerFunc {
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
		ok, name, scopes, keyOrg, err := s.st.APIKeyExists(auth[len(prefix):])
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
			return
		}
		if !ok {
			s.authFails.record(ip)
			s.authFail(w, "invalid api key")
			return
		}
		if keyOrg == "" {
			// A key minted before orgs were bindings, on a store the startup
			// backfill never reached. It behaves as keys always did; the log
			// line is so the operator can see the transitional state rather
			// than inherit it silently.
			s.logf("api key %q has no org binding (pre-tenancy key on a store the backfill has not run on) — treating as fleet-wide", name)
		}
		next(w, r, name, scopes, keyOrg)
	}
}

func (s *Server) authFail(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": msg})
}

// ---- GET /v1/machines (readonly, or exec keys — allowlist-filtered) ----

func (s *Server) handleMachines(w http.ResponseWriter, r *http.Request, keyName, scopes, keyOrg string) {
	if !canRead(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks machine-list scope"})
		return
	}
	allowed, all := readScope(scopes)
	// The listing is org-scoped in the store, not filtered here: a tenant
	// key's fleet is its org's machines, full stop. Machines with no org
	// (rows the backfill never resolved) belong to no tenant and are listed
	// only to the unbound caller.
	machines, err := s.st.ListMachinesByOrg(keyOrg)
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
		if !all && !containsExact(allowed, m.Name) && !containsExact(allowed, m.LocalName()) {
			continue
		}
		// The E2E signal rides each machine, not the listing: the setting is
		// per org, and a client holding a machine name can decide without
		// having to work out which org it belongs to.
		e2eState := s.e2eStateForMachineRow(&m)
		resp.Machines = append(resp.Machines, protocol.MachineInfo{
			Name: m.Name, Hostname: m.Hostname, OS: m.OS, Arch: m.Arch,
			Online: online[m.Name], AgentVer: m.AgentVer, CreatedAt: m.CreatedAt,
			Org: m.Org, LocalName: m.LocalName(),
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

// unknownMachineHint names the machines the caller's own org has enrolled,
// with their live state, appended to an "offline or unknown" refusal. An
// LLM caller that guessed a name (observed 2026-10-09: an invented
// "teven-teva-ent-docker01" for teva's "teva-ent-docker01") can self-correct
// in one round trip instead of calling machines_list blind. Tenancy holds:
// the list is the key's org only — the same set machines_list shows — so a
// cross-org guess learns nothing it could not already list.
func (s *Server) unknownMachineHint(keyOrg string) string {
	machines, err := s.st.ListMachinesByOrg(keyOrg)
	if err != nil || len(machines) == 0 {
		return ""
	}
	online := s.br.OnlineNames()
	const max = 12
	names := make([]string, 0, len(machines))
	for _, m := range machines {
		if m.Revoked {
			continue // what machines_list shows: a revoked enrollment is not a machine
		}
		if len(names) == max {
			names = append(names, "…")
			break
		}
		state := "offline"
		if online[m.Name] {
			state = "online"
		}
		names = append(names, m.Name+" ("+state+")")
	}
	if len(names) == 0 {
		return ""
	}
	return " — machines enrolled in this org: " + strings.Join(names, ", ")
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request, keyName, scopes, keyOrg string) {
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
	// Sealed and plaintext are two ways to say the same thing, and a request
	// carrying both is refused rather than resolved. Execution was never
	// smuggleable — the dispatch payload is built from the sealed fields only —
	// but the audit trail was: the plaintext `command` a sealed request happened
	// to carry was what the refusal and timeout rows recorded, so a key holder
	// could choose the text of a row describing a command the control plane
	// cannot read. Nothing legitimate sends both, and a client that does is
	// telling us its two halves disagree.
	if req.Sealed != "" && (req.Command != "" || len(req.Argv) > 0) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide sealed or command/argv, not both"})
		return
	}
	if (req.Sealed != "") != (req.E2EPub != "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sealed and e2e_pub must be provided together"})
		return
	}
	// Tenancy: the machine a tenant key names is resolved within its own org —
	// a bare local name composes with the key's org, a canonical name is taken
	// as typed. The composed name is what every later check and the dispatch
	// use, so a tenant key cannot address another org's machine no matter how
	// it spells the request.
	machine := canonicalMachineName(keyOrg, req.Machine)
	if !keyAllowsMachine(scopes, keyOrg, machine) {
		// Recorded, because the record is the point: an exec-scoped key asking
		// for a machine outside its allowlist is either a mistake worth seeing
		// or a stolen key being used to find out what else it can reach, and
		// this was the one refusal on the path that left no trace.
		s.auditNotScoped(machine, keyName, keyOrg)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + req.Machine})
		return
	}
	target, err := s.st.MachineByName(machine)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	// The display form is what every audit row for this request carries — the
	// refusals and the timeout as well as the reply — so for a sealed request it
	// is the placeholder and nothing else. Deriving it from `command`/`argv`
	// would leave a sealed refusal audited as an empty command (meaningless in
	// the record) and, before the validation above, as whatever text the caller
	// chose to attach to a command the control plane cannot read. One home for
	// the decision is what keeps every path saying the same thing.
	display := commandForDisplay(req.Command, req.Argv)
	if req.Sealed != "" {
		display = auditSealedLabel
	}
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
	//
	// The org the setting is read for is the machine row's own — a stored fact,
	// not a prefix guess against a mutable org list.
	if req.Sealed != "" && target != nil && !s.e2eStateForMachineRow(target).Enabled {
		state := s.e2eStateForMachineRow(target)
		s.auditRow(s.auditOrgFor(machine, keyOrg), machine, auditSealedLabel, "console:"+keyName,
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
	// fleetApproved rides the dispatch: an approved command reaches the agent
	// with FleetApproved, so the mirrored copy of the same ruleset on the
	// machine stands down for this one command (never for the machine's own
	// policy). Sealed requests never set it — there is no plaintext there to
	// judge or to approve; the mirror handles them on the machine.
	// The exec-time secrets guard, plaintext paths only: an injection name
	// must be registered to this machine's org before dispatch. A sealed
	// request's names are inside the seal — the machine judges them there,
	// like the fleet rules (see the comment below on why the policy check is
	// skipped for sealed commands; the same reasoning applies verbatim).
	if req.Sealed == "" && len(req.InjectEnv) > 0 {
		injOrg := s.auditOrgFor(machine, keyOrg)
		if reason := s.injectRefusal(injOrg, machine, req.InjectEnv); reason != "" {
			s.auditRow(injOrg, machine, display, "console:"+keyName, sqlNullInt(execRefused), "", reason)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
			return
		}
	}
	fleetApproved := false
	if req.Sealed == "" {
		if reason := s.execPolicyCheck(req.Command, req.Argv); reason != "" {
			// The refusal is not final: an operator may approve this exact
			// command (internal/server/approvals.go). The gate records or joins
			// a pending approval, audits the attempt, and answers the caller —
			// 202 with the approval id on the first ask, a plain refusal when
			// nobody approves in time, or fall-through when an approved record
			// covers this command.
			var dispatch bool
			dispatch, fleetApproved = s.execPolicyGate(w, &req, display, keyName, keyOrg, reason)
			if !dispatch {
				return
			}
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
	if ref := s.dispatchRefusal(machine); ref != nil {
		s.auditExec(&pendingExec{org: s.auditOrgFor(machine, keyOrg), machine: machine, command: display, source: "console:" + keyName},
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

	ac := s.br.WaitOnline(machine, 15*time.Second)
	if ac == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "machine offline or unknown: " + req.Machine + s.unknownMachineHint(keyOrg)})
		return
	}
	// Re-checked after the wait, because that wait is up to fifteen seconds and
	// the check above is now that old. A block (or a revocation) set in the
	// window would otherwise be dispatched anyway — the operator's "stop
	// sending this machine commands" arriving one command too late, which is
	// precisely the command they were trying to prevent. The streaming path
	// re-checks per frame and never had this window; this is the same pattern
	// on the path that did.
	if ref := s.dispatchRefusal(machine); ref != nil {
		s.auditExec(&pendingExec{org: s.auditOrgFor(machine, keyOrg), machine: machine, command: display, source: "console:" + keyName},
			execRefused, "", ref.msg)
		writeJSON(w, ref.status, map[string]string{"error": ref.msg})
		return
	}

	reqID := store.RandToken(8)
	pe := &pendingExec{
		ch:      make(chan execReply, 1),
		org:     s.auditOrgFor(machine, keyOrg),
		machine: machine,
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
		// Plaintext: the command text is already visible to the control
		// plane, so the inject NAMES ride beside it — they are in the
		// request and have already passed the injectRefusal gate above.
		// The agent resolves them against its local store and scrubs every
		// output byte. Dropping the names here silently ran every plaintext
		// exec (the MCP exec tool's only path) with empty variables while
		// the sealed path injected fine.
		cmdPayload, _ = json.Marshal(protocol.ExecCommand{Command: req.Command, Argv: req.Argv, InjectEnv: req.InjectEnv, Timeout: req.Timeout, FleetApproved: fleetApproved})
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
			s.auditRow(pe.org, pe.machine, auditSealedLabel, pe.source, auditExit, "", "")
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

// auditNotScopedLabel is the command column of a row that records a refusal
// which happened before any command existed: a key asking for a machine it is
// not scoped for.
//
// That row is the most valuable thing a fleet's audit trail can hold — someone
// probing with a stolen or misused key across machine names — and it was
// invisible in the record, because the scope check returned before anything was
// written. A marker says plainly that no command was involved, where an empty
// column would read as a missing field.
const auditNotScopedLabel = "[refused: key not scoped for this machine]"

// auditRow writes one audit row and reports a failure rather than discarding
// it. "Every dispatched command is audited" is invariant 16, and a discarded
// error made that claim unfalsifiable: a full disk or a locked database left
// commands dispatching with no row and no complaint, so the process kept saying
// it recorded things it did not record. The insert still does not block the
// dispatch — by the time most of these run the command has been dispatched or
// has already finished, and refusing then would invent a new failure mode
// rather than recover the record — but the operator hears about it.
// auditRow writes one audit row and reports a failure rather than discarding
// it. "Every dispatched command is audited" is invariant 16, and a discarded
// error made that claim unfalsifiable: a full disk or a locked database left
// commands dispatching with no row and no complaint, so the process kept saying
// it recorded things it did not record. The insert still does not block the
// dispatch — by the time most of these run the command has been dispatched or
// has already finished, and refusing then would invent a new failure mode
// rather than recover the record — but the operator hears about it.
//
// org scopes the row to the machine's tenant, so an org-bound read filters in
// the store. An org that cannot be resolved is stored empty rather than
// guessed: an empty org is readable by no tenant, which fails closed.
func (s *Server) auditRow(org, machine, command, source string, exit sql.NullInt64, stdout, stderr string) {
	if err := s.st.AuditInsert(nowRFC3339(), org, machine, command, source, exit, stdout, stderr); err != nil {
		log.Printf("server: AUDIT INSERT FAILED for machine %q (command %q): %v — the audit trail is "+
			"no longer complete; every dispatched command is supposed to be recorded", machine, command, err)
	}
}

// auditNotScoped records an attempt on a machine the key is not scoped for.
func (s *Server) auditNotScoped(machine, keyName, keyOrg string) {
	s.auditRow(s.auditOrgFor(machine, keyOrg), machine, auditNotScopedLabel, "console:"+keyName, sqlNullInt(execRefused), "",
		"refused: this key is not scoped for machine "+machine)
}

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
func (s *Server) handleE2EPub(w http.ResponseWriter, r *http.Request, keyName, scopes, keyOrg string) {
	name := canonicalMachineName(keyOrg, r.PathValue("name"))
	// Exec scope only, with no readonly carve-out. The key this hands out is the
	// one used to seal commands, so a key that may not run commands has no use for
	// it — and the control table's promise is that a read-only key sees the fleet
	// and the audit trail "and nothing else". A readonly key can be refused here
	// sooner and more legibly than at the exec it would attempt next.
	if !keyAllowsMachine(scopes, keyOrg, name) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + name})
		return
	}
	m, err := s.st.MachineByName(name)
	if err != nil || m == nil || m.Revoked {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
		return
	}
	resp := e2ePubResponse{E2EState: s.e2eStateForMachineRow(m), Machine: m.Name}
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
	s.auditRow(pe.org, pe.machine, pe.command, pe.source,
		sql.NullInt64{Int64: int64(exitCode), Valid: true}, stdout, stderr)
}

// ---- GET /v1/audit (readonly, or exec keys — allowlist-filtered) ----

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, keyName, scopes, keyOrg string) {
	// Audit entries carry command output: restrict to readonly (full) or
	// exec keys (allowlist keys see only their machines). Enroll keys get
	// nothing — they are distributed into provisioning pipelines.
	if !canRead(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks audit scope"})
		return
	}
	_, all := readScope(scopes)
	machine := r.URL.Query().Get("machine")
	// Tenancy: the org filter is applied in the store — the same statement
	// that would otherwise have returned another tenant's rows filters them
	// out, so the boundary does not depend on this handler's loop. A tenant
	// key's audit trail is its org's trail.
	if machine != "" && machine != "*" {
		machine = canonicalMachineName(keyOrg, machine)
		if !all && !keyAllowsMachine(scopes, keyOrg, machine) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + machine})
			return
		}
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	entries, err := s.st.AuditList(keyOrg, machine, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	type auditRow struct {
		TS         string `json:"ts"`
		Machine    string `json:"machine"`
		Org        string `json:"org,omitempty"`
		Command    string `json:"command"`
		Source     string `json:"source"`
		ExitCode   *int64 `json:"exit_code"`
		StdoutSnip string `json:"stdout_snip,omitempty"`
		StderrSnip string `json:"stderr_snip,omitempty"`
	}
	rows := make([]auditRow, 0, len(entries))
	for _, e := range entries {
		if !all && !keyAllowsMachine(scopes, keyOrg, e.Machine) {
			continue
		}
		var ec *int64
		if e.ExitCode.Valid {
			v := e.ExitCode.Int64
			ec = &v
		}
		// The row carries the machine's canonical name — the identifier the
		// whole dispatch path keys on, and unambiguous in a log — plus the
		// org as its own field for tenant-scoped readers.
		rows = append(rows, auditRow{TS: e.TS, Machine: e.Machine, Org: e.Org, Command: e.Command, Source: e.Source, ExitCode: ec, StdoutSnip: e.StdoutSnip, StderrSnip: e.StderrSnip})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": rows})
}

// ---- POST /v1/admin/revoke (exec:* keys only) ----

func (s *Server) handleRevokeMachine(w http.ResponseWriter, r *http.Request, keyName, scopes, keyOrg string) {
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
	// Tenancy: the machine is resolved inside the key's org. A machine of
	// another org is answered "unknown machine" — the same response an
	// absent name gets — so a scoped key cannot even learn that the row
	// exists, let alone retire it.
	machine := canonicalMachineName(keyOrg, req.Machine)
	m, err := s.st.MachineByName(machine)
	if err != nil || m == nil || (keyOrg != "" && m.Org != keyOrg) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
		return
	}
	if err := s.revokeMachine(machine, req.PurgeAudit); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	// %q, not %s: both values reach the log from outside, and a machine name
	// or key name containing newlines could forge log lines.
	s.logf("machine revoked: %q (by %q)", machine, keyName)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "revoked", "machine": machine})
}

// sqlNullInt is an audit exit status (or a NULL when there is none to report).
func sqlNullInt(code int) sql.NullInt64 {
	return sql.NullInt64{Int64: int64(code), Valid: true}
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
