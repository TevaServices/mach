package server

// Secrets, control-plane side: a registry of NAMES, two org guards, and the
// relay for sealed pushes.
//
// The value never passes through here. A push arrives from a console already
// sealed to the target machine's E2E key (the same trust shape as a sealed
// exec: the control plane relays an opaque blob and learns only metadata),
// and everything else this file touches — announcements, listings, the
// injection guard — works on names alone. The registry table has no value
// column, which is the strongest form of that statement the schema can make.
//
// The two guards mirror the two policy layers, and for the same reason:
//
//  1. At push time (here): the secret's org must be the target machine's
//     org, and the org's E2E setting must be ON — the push is the one path
//     where a value crosses the wire, and with sealing off there is no
//     honest way to send one.
//  2. At exec time: an injection name must be registered to the machine's
//     org before dispatch (plaintext paths — one-shot and the relay's
//     exec_stream, which reads the command by design). A SEALED command's
//     names travel inside the seal, so the server cannot judge them; the
//     machine does, exactly as it judges the sealed command text against
//     the mirrored fleet rules, and an unknown name refuses the exec there
//     (fail-closed, 126-class).
//
// The registry is metadata, not authority: a row for a name a machine does
// not hold fails at the machine ("unknown name"), never runs with an empty
// value. That is why a registry mismatch is an operational nuisance rather
// than a hole.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
	"github.com/TevaServices/mach/internal/store"
)

// secretPushLabel is the audit command for a push: "secret push NAME",
// deliberately NOT "secrets: NAME" — the audit redactor masks
// keyword-colon-value shapes, and the label would redact itself into
// uselessness (the name is not a secret; the row should show it).
func secretPushLabel(name string) string { return "secret push " + name }

// secretRelayTimeout bounds how long the control plane waits for the agent
// to answer a secret_push or secret_list. A push is interactive (the
// operator is watching a CLI), a list likewise; beyond this the answer is
// reported as the machine not answering, never as success.
const secretRelayTimeout = 10 * time.Second

// maxInjectEnv bounds one request's injection list. It is a resource bound
// (each name is an indexed probe) rather than a policy decision; a command
// needing more than 64 secrets is a script gone wrong.
const maxInjectEnv = 64

// pushWaiter is one in-flight sealed push or live list, keyed by the ReqID
// the frame was sent under and bound to the machine it was sent to — the
// same binding completeExec enforces, so only the machine a frame was
// dispatched to may complete it.
type pushWaiter struct {
	machine string
	push    chan protocol.SecretPushResult
	list    chan protocol.SecretListResult
}

func (s *Server) registerPushWaiter(reqID, machine string) *pushWaiter {
	w := &pushWaiter{
		machine: machine,
		push:    make(chan protocol.SecretPushResult, 1),
		list:    make(chan protocol.SecretListResult, 1),
	}
	s.pushMu.Lock()
	s.pendingPushes[reqID] = w
	s.pushMu.Unlock()
	return w
}

func (s *Server) completePushWaiter(reqID, fromMachine string, push *protocol.SecretPushResult, list *protocol.SecretListResult) {
	s.pushMu.Lock()
	w, ok := s.pendingPushes[reqID]
	if ok && w.machine != fromMachine {
		ok = false // only the machine the frame was sent to may answer it
	}
	if ok {
		delete(s.pendingPushes, reqID)
	}
	s.pushMu.Unlock()
	if !ok {
		return
	}
	switch {
	case push != nil:
		select {
		case w.push <- *push:
		default:
		}
	case list != nil:
		select {
		case w.list <- *list:
		default:
		}
	}
}

// handleSecretsAnnounce records the names a machine announced, stamped with
// the ORG THE MACHINE ROW SAYS it belongs to — never the org the frame
// self-reports. The announce is the one place an agent tells the control
// plane what it holds, and a hostile or confused agent must not be able to
// write rows into another tenant's registry: the connection already proved
// which machine it is, and the machine row already says which org that is.
func (s *Server) handleSecretsAnnounce(machine string, env protocol.Envelope, conn *protocol.WSConn) {
	var ann protocol.SecretsAnnounce
	if err := json.Unmarshal(env.Payload, &ann); err != nil {
		s.logf("agent %q sent a malformed secrets_announce", machine)
		return
	}
	m, err := s.st.MachineByName(machine)
	if err != nil || m == nil {
		return
	}
	if m.Org == "" {
		// A machine of no org holds no registry names: nothing to record,
		// and an ack of zero rather than silence, so the agent does not
		// retry an announce the server will never accept.
		_ = conn.WriteEnvelope(protocol.Envelope{Type: "secrets_announce_ack",
			Payload: mustJSON(protocol.SecretsAnnounceAck{Count: 0})})
		return
	}
	recorded := 0
	for _, n := range ann.Names {
		if err := protocol.ValidSecretName(n); err != nil {
			s.logf("agent %q announced an invalid secret name: %v", machine, err)
			continue
		}
		if err := s.st.UpsertSecret(m.Org, n, "agent"); err != nil {
			s.logf("agent %q: secrets registry write failed: %v", machine, err)
			continue
		}
		recorded++
	}
	_ = conn.WriteEnvelope(protocol.Envelope{Type: "secrets_announce_ack",
		Payload: mustJSON(protocol.SecretsAnnounceAck{Count: recorded})})
}

// injectRefusal is the exec-time org guard: every injection name must be
// registered to this machine's org before the command is dispatched. The
// registry read failing refuses too — a guard that fails open when its
// backing store is unreadable is not a guard.
func (s *Server) injectRefusal(org, machine string, names []string) string {
	if len(names) == 0 {
		return ""
	}
	if len(names) > maxInjectEnv {
		return "refused: too many injected secret names (max " + strconv.Itoa(maxInjectEnv) + ")"
	}
	for _, n := range names {
		if err := protocol.ValidSecretName(n); err != nil {
			return "refused: " + err.Error()
		}
		known, err := s.st.SecretKnown(org, n)
		if err != nil {
			s.logf("secrets: registry read failed for %q on %q: %v", n, machine, err)
			return "refused: the secrets registry could not be read"
		}
		if !known {
			return "refused: secret \"" + n + "\" is not registered for this machine's org — push it first"
		}
	}
	return ""
}

// ---- console API: POST /v1/secrets/push, GET /v1/secrets ----

// handleSecretPush relays a sealed secret to a machine and records the
// NAME in the registry on success.
//
// Request: {machine, name, sealed} — sealed is the console's e2e.Seal of a
// protocol.SecretPayload to the machine's public E2E key. The server checks
// the caller's scope and org, the target's org, and that the org's E2E
// setting is ON (the value crosses the wire exactly once on this path, so
// sealing is not optional), then relays the blob blind and reports the
// agent's verdict. The registry learns the name, the acting key, and
// nothing else.
func (s *Server) handleSecretPush(w http.ResponseWriter, r *http.Request, keyName, scopes, keyOrg string) {
	var req struct {
		Machine string `json:"machine"`
		Name    string `json:"name"`
		Sealed  string `json:"sealed"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if req.Machine == "" || req.Name == "" || req.Sealed == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "machine, name and sealed are required"})
		return
	}
	if !keyAllowsMachine(scopes, keyOrg, canonicalMachineName(keyOrg, req.Machine)) {
		s.auditNotScoped(canonicalMachineName(keyOrg, req.Machine), keyName, keyOrg)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + req.Machine})
		return
	}
	machine := canonicalMachineName(keyOrg, req.Machine)
	m, err := s.st.MachineByName(machine)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	if m == nil || m.Revoked || (keyOrg != "" && m.Org != keyOrg) {
		// Same answer for absent, revoked, and another tenant's machine.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
		return
	}
	if err := protocol.ValidSecretName(req.Name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Guard 1: E2E must be ON for this org. A sealed push is the only way a
	// value crosses the wire, and the setting is the single decision point
	// for whether this control plane accepts ciphertext at all.
	if state := s.e2eStateForMachineRow(m); !state.Enabled {
		org := m.Org
		s.auditRow(org, machine, secretPushLabel(req.Name), "console:"+keyName,
			sqlNullInt(execRefused), "", "secret push refused: E2E is off for this machine's org")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "secret push is disabled on this control plane: " + state.Reason})
		return
	}
	// The operator's soft block before the key-presence check: a blocked
	// machine is refused for being blocked, not for an unrelated defect.
	if ref := s.dispatchRefusal(machine); ref != nil {
		s.auditRow(m.Org, machine, secretPushLabel(req.Name), "console:"+keyName,
			sqlNullInt(execRefused), "", ref.msg)
		writeJSON(w, ref.status, map[string]string{"error": ref.msg})
		return
	}
	if m.PubE2E == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "machine has no E2E key — re-enroll to enable secret push"})
		return
	}

	reqID := store.RandToken(8)
	waiter := s.registerPushWaiter(reqID, machine)
	defer s.dropPushWaiter(reqID)
	payload, _ := json.Marshal(protocol.SealedSecretPush{SealedB64: req.Sealed})
	ac := s.br.Get(machine)
	if ac == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "machine offline or unknown: " + req.Machine})
		return
	}
	if err := ac.Conn.WriteEnvelope(protocol.Envelope{Type: "secret_push", ReqID: reqID, Payload: payload}); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent connection lost"})
		return
	}
	var res protocol.SecretPushResult
	select {
	case res = <-waiter.push:
	case <-time.After(secretRelayTimeout):
		s.auditRow(m.Org, machine, secretPushLabel(req.Name), "console:"+keyName,
			sqlNullInt(-1), "", "secret push timed out waiting for the machine")
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "the machine did not answer the secret push"})
		return
	}
	if !res.OK {
		// The machine refused — org tag mismatch, invalid name, full store.
		// The error is agent-authored but value-free by construction; audit
		// it as a refusal so the attempt is in the record.
		s.auditRow(m.Org, machine, secretPushLabel(req.Name), "console:"+keyName,
			sqlNullInt(execRefused), "", "secret push refused by the machine: "+res.Error)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "the machine refused the secret push: " + res.Error})
		return
	}
	if err := s.st.UpsertSecret(m.Org, req.Name, "console:"+keyName); err != nil {
		// The value is already on the machine; a registry write failing is
		// logged loudly rather than turned into a false "refused" — the push
		// happened.
		s.logf("secrets: registry write failed after push to %q: %v", machine, err)
	}
	s.auditRow(m.Org, machine, secretPushLabel(req.Name), "console:"+keyName,
		sqlNullInt(0), "", "secret pushed (value sealed; the control plane cannot read it)")
	s.logf("secret %q pushed to %q (by %q)", req.Name, machine, keyName)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "pushed", "machine": machine, "name": req.Name})
}

func (s *Server) dropPushWaiter(reqID string) {
	s.pushMu.Lock()
	delete(s.pendingPushes, reqID)
	s.pushMu.Unlock()
}

// handleSecretsList answers "what secrets does this org (or machine) hold".
// Without a machine: the registry, filtered to the key's org. With one: the
// names are asked of the machine itself over a live relayed secret_list —
// the freshest truth — and the registry's last_seen is refreshed from it.
// Both forms carry names only; the response shape has no value field.
func (s *Server) handleSecretsList(w http.ResponseWriter, r *http.Request, keyName, scopes, keyOrg string) {
	if !canRead(scopes) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key lacks secrets-list scope"})
		return
	}
	machineParam := r.URL.Query().Get("machine")
	if machineParam == "" || machineParam == "*" {
		rows, err := s.st.ListSecrets(keyOrg)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
			return
		}
		type secretRow struct {
			Name       string `json:"name"`
			Org        string `json:"org,omitempty"`
			CreatedAt  string `json:"created_at"`
			CreatedBy  string `json:"created_by,omitempty"`
			LastSeenAt string `json:"last_seen_at,omitempty"`
		}
		out := make([]secretRow, 0, len(rows))
		for _, si := range rows {
			name := si.Name
			org := si.Org
			if keyOrg != "" {
				// A tenant key sees its own org's rows; the org column is
				// redundant for it, and the name is already local.
				org = ""
			}
			out = append(out, secretRow{Name: name, Org: org, CreatedAt: si.CreatedAt, CreatedBy: si.CreatedBy, LastSeenAt: si.LastSeenAt})
		}
		writeJSON(w, http.StatusOK, map[string]any{"secrets": out})
		return
	}

	machine := canonicalMachineName(keyOrg, machineParam)
	_, all := readScope(scopes)
	if !all && !keyAllowsMachine(scopes, keyOrg, machine) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + machineParam})
		return
	}
	m, err := s.st.MachineByName(machine)
	if err != nil || m == nil || m.Revoked || (keyOrg != "" && m.Org != keyOrg) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown machine"})
		return
	}
	ac := s.br.Get(machine)
	if ac == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "machine offline or unknown: " + machineParam})
		return
	}
	reqID := store.RandToken(8)
	waiter := s.registerPushWaiter(reqID, machine)
	defer s.dropPushWaiter(reqID)
	if err := ac.Conn.WriteEnvelope(protocol.Envelope{Type: "secret_list", ReqID: reqID}); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent connection lost"})
		return
	}
	var res protocol.SecretListResult
	select {
	case res = <-waiter.list:
	case <-time.After(secretRelayTimeout):
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "the machine did not answer the secrets list"})
		return
	}
	// The machine's own answer is the freshest evidence; refresh what the
	// registry already knows. Missing rows are NOT invented here: only a
	// push (or the machine's own announce) creates one, so the registry's
	// created_by stays honest about who provisioned what.
	for _, n := range res.Names {
		_ = s.st.TouchSecret(m.Org, n)
	}
	writeJSON(w, http.StatusOK, map[string]any{"machine": machine, "org": m.Org, "names": res.Names})
}
