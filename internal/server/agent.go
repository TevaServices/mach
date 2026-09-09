package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bcross/mach/internal/broker"
	"github.com/bcross/mach/internal/protocol"
	"github.com/bcross/mach/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(v)
}

// ---- POST /v1/pair/start  (agent, unauthenticated but ungranted) ----

func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request) {
	if s.tooManyPairStarts(clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many pairing attempts; try later"})
		return
	}
	var req protocol.PairStartReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if err := validPubKey(req.PubKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if existing, _ := s.st.MachineByPubKey(req.PubKey); existing != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "this agent key is already enrolled as " + existing.Name})
		return
	}
	code := store.NewPairingCode()
	id, token, err := s.st.CreatePairing(req.PubKey, req.Hostname, req.OS, req.Arch, req.AgentVer, code, "", s.pairingTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	s.logf("pair start: id=%s host=%q code=%s", id, req.Hostname, code)
	writeJSON(w, http.StatusOK, protocol.PairStartResponse{
		PairID:  id,
		Token:   token,
		Code:    code,
		Expires: time.Now().UTC().Add(s.pairingTTL).Format(time.RFC3339),
	})
}

func validPubKey(pk string) error {
	if len(pk) != 64 {
		return errors.New("pub_key must be 64 hex chars (ed25519)")
	}
	_, err := hex.DecodeString(pk)
	return err
}

// ---- POST /v1/pair/status  (agent polls while waiting for approval) ----

func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	var req protocol.PairStatusReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	p, err := s.st.PairingByToken(req.Token)
	if err != nil || p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown pairing"})
		return
	}
	resp := protocol.PairStatusResponse{State: s.st.PairingState(p)}
	if resp.State == "approved" && p.Name != "" {
		resp.Machine = p.Name
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- POST /v1/register/apikey  (headless enrollment) ----

func (s *Server) handleRegisterAPIKey(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterAPIKeyReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	ok, _, err := s.st.APIKeyExists(strings.TrimSpace(req.APIKey))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid api key"})
		return
	}
	if err := validPubKey(req.PubKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if !validMachineName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be 1-63 chars: letters, digits, '-'"})
		return
	}
	if existing, _ := s.st.MachineByPubKey(req.PubKey); existing != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already enrolled as " + existing.Name})
		return
	}
	if existing, _ := s.st.MachineByName(name); existing != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "machine name already taken"})
		return
	}
	if err := s.st.CreateMachine(name, req.PubKey, req.Hostname, req.OS, req.Arch, req.AgentVer); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	s.logf("api-key enrollment: machine=%s host=%q", name, req.Hostname)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "enrolled", "machine": name})
}

func validMachineName(name string) bool {
	if len(name) < 1 || len(name) > 63 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ---- GET /v1/agent/ws  (agent main connection; identity via ed25519) ----

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	machine, err := s.st.MachineByName(name)
	if err != nil || machine == nil {
		http.Error(w, "unknown machine", http.StatusUnauthorized)
		return
	}
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn := protocol.NewWSConn(ws)
	defer conn.Close()

	// Handshake: server sends hello-required, agent replies with signed hello.
	if err := conn.WriteEnvelope(protocol.Envelope{Type: "hello"}); err != nil {
		return
	}
	env, err := conn.ReadEnvelope()
	if err != nil || env.Type != "hello" {
		_ = conn.WriteEnvelope(protocol.Envelope{Type: "hello_result", Payload: mustJSON(protocol.HelloResponse{OK: false, Error: "expected hello"})})
		return
	}
	var hr protocol.HelloRequest
	if err := json.Unmarshal(env.Payload, &hr); err != nil || hr.PubKey != machine.PubKey || verifyAgentHello(machine.PubKey, hr) != nil {
		_ = conn.WriteEnvelope(protocol.Envelope{Type: "hello_result", Payload: mustJSON(protocol.HelloResponse{OK: false, Error: "bad signature or key"})})
		return
	}
	_ = conn.WriteEnvelope(protocol.Envelope{Type: "hello_result", Payload: mustJSON(protocol.HelloResponse{OK: true})})

	ac := &broker.AgentConn{Name: machine.Name, Conn: conn, LastSeen: time.Now(), Hostname: hr.Hostname, OS: hr.OS, Arch: hr.Arch, AgentVer: hr.AgentVer}
	s.br.Add(ac)
	defer s.br.Remove(ac)

	// Best-effort runtime metadata refresh.
	_ = s.st.UpdateMachineMeta(machine.ID, hr.Hostname, hr.OS, hr.Arch, hr.AgentVer)

	// Pump: read envelopes from the agent until it disconnects.
	for {
		_ = ws.SetReadDeadline(time.Now().Add(90 * time.Second))
		env, err := conn.ReadEnvelope()
		if err != nil {
			return
		}
		switch env.Type {
		case "exec_result":
			s.completeExec(env)
		case "ping":
			_ = conn.WriteEnvelope(protocol.Envelope{Type: "pong"})
		default:
			s.logf("agent %s sent unknown frame %q", machine.Name, env.Type)
		}
	}
}

// verifyAgentHello checks the ed25519 signature over (name || "|" || timestamp).
func verifyAgentHello(pubHex string, hr protocol.HelloRequest) error {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("bad key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hr.Auth, "v1 "))
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(helloMessage(hr.Name, hr.Timestamp)), sig) {
		return errors.New("signature mismatch")
	}
	ts, err := time.Parse(time.RFC3339, hr.Timestamp)
	if err != nil {
		return errors.New("bad timestamp")
	}
	if d := time.Since(ts); d > 5*time.Minute || d < -5*time.Minute {
		return errors.New("stale hello")
	}
	return nil
}

func helloMessage(name, timestamp string) string { return name + "|" + timestamp }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ---- exec completion (called from the agent pump above) ----

func (s *Server) completeExec(env protocol.Envelope) {
	var res protocol.ExecResult
	if err := json.Unmarshal(env.Payload, &res); err != nil {
		res = protocol.ExecResult{Error: "bad exec_result payload"}
	}
	s.pendMu.Lock()
	pe, ok := s.pending[env.ReqID]
	if ok {
		delete(s.pending, env.ReqID)
	}
	s.pendMu.Unlock()
	if ok {
		pe.ch <- res
	}
}

// ---- POST /v1/pair/claim  (agent completes enrollment after phone approval) ----

func (s *Server) handlePairClaim(w http.ResponseWriter, r *http.Request) {
	var req protocol.PairClaimRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	p, err := s.st.PairingByToken(req.Token)
	if err != nil || p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown pairing"})
		return
	}
	if p.PubKey != req.PubKey {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key does not match pairing"})
		return
	}
	state := s.st.PairingState(p)
	if state != "approved" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "pairing not approved (state: " + state + ")"})
		return
	}
	if existing, _ := s.st.MachineByPubKey(p.PubKey); existing != nil {
		// Idempotent: enrolled between approve and claim.
		writeJSON(w, http.StatusOK, map[string]string{"ok": "enrolled", "machine": existing.Name})
		return
	}
	ok, err := s.st.ConsumePairing(p)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "pairing already claimed"})
		return
	}
	s.logf("pair claimed: machine=%s", p.Name)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "enrolled", "machine": p.Name})
}