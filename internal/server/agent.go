package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
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
	if s.tooManyPairStarts(s.clientIP(r)) {
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
		if existing.Revoked {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "this agent key is revoked; ask the operator to delete it first"})
			return
		}
		writeJSON(w, http.StatusConflict, map[string]string{"error": "this agent key is already enrolled as " + existing.Name})
		return
	}
	id, token, code, err := s.st.CreatePairing(req.PubKey, req.Hostname, req.OS, req.Arch, req.AgentVer, s.pairingTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	s.logf("pair start: id=%s host=%q", id, req.Hostname)
	// code goes ONLY to the agent console (never into the QR); the phone
	// must type it blind — that's the anti-QR-theft property.
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

// ---- POST /v1/register/apikey  (headless enrollment; requires an enroll-scoped key) ----

func (s *Server) handleRegisterAPIKey(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterAPIKeyReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	ok, _, scopes, err := s.st.APIKeyExists(strings.TrimSpace(req.APIKey))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	if !ok || !hasScope(scopes, "enroll") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid api key"})
		return
	}
	if err := validPubKey(req.PubKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if existing, _ := s.st.MachineByPubKey(req.PubKey); existing != nil {
		if existing.Revoked {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "this agent key is revoked"})
			return
		}
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already enrolled as " + existing.Name})
		return
	}
	if !store.ValidOrgName(s.org, name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be org-prefixed (<org>-<machine>, letters/digits/hyphen, machine part 1-48 chars)"})
		return
	}
	if existing, _ := s.st.MachineByName(name); existing != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "machine name already taken — pick a new name (e.g. " + name + "-2)"})
		return
	}
	if err := s.st.CreateMachine(name, req.PubKey, req.Hostname, req.OS, req.Arch, req.AgentVer); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	s.logf("api-key enrollment: machine=%s host=%q", name, req.Hostname)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "enrolled", "machine": name, "server_key": s.serverKeyHex})
}

// ---- GET /v1/agent/ws  (agent main connection; identity via ed25519) ----

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	machine, err := s.st.MachineByName(name)
	if err != nil || machine == nil {
		http.Error(w, "unknown machine", http.StatusUnauthorized)
		return
	}
	if machine.Revoked {
		ws2, err2 := s.upgrader.Upgrade(w, r, nil)
		if err2 == nil {
			conn0 := protocol.NewWSConn(ws2)
			_ = conn0.WriteEnvelope(protocol.Envelope{Type: "revoked"})
			conn0.Close()
		}
		return
	}
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn := protocol.NewWSConn(ws)
	defer conn.Close()

	// Replay-proof hello: server sends a random challenge; the agent signs
	// name|challenge. Captured hellos are worthless on other connections.
	nonce := store.RandToken(32)
	if err := conn.WriteEnvelope(protocol.Envelope{Type: "hello", ReqID: nonce}); err != nil {
		return
	}
	env, err := conn.ReadEnvelope()
	if err != nil || env.Type != "hello" {
		_ = conn.WriteEnvelope(protocol.Envelope{Type: "hello_result", Payload: mustJSON(protocol.HelloResponse{OK: false, Error: "expected hello"})})
		return
	}
	var hr protocol.HelloRequest
	if err := json.Unmarshal(env.Payload, &hr); err != nil || hr.PubKey != machine.PubKey || verifyAgentHello(machine.PubKey, hr, nonce) != nil {
		_ = conn.WriteEnvelope(protocol.Envelope{Type: "hello_result", Payload: mustJSON(protocol.HelloResponse{OK: false, Error: "bad signature or key"})})
		return
	}
	_ = conn.WriteEnvelope(protocol.Envelope{Type: "hello_result", Payload: mustJSON(protocol.HelloResponse{OK: true})})

	ac := &broker.AgentConn{Name: machine.Name, Conn: conn, LastSeen: time.Now(), Hostname: hr.Hostname, OS: hr.OS, Arch: hr.Arch, AgentVer: hr.AgentVer}
	s.br.Add(ac)
	defer s.br.Remove(ac)

	_ = s.st.UpdateMachineMeta(machine.ID, hr.Hostname, hr.OS, hr.Arch, hr.AgentVer)

	// Deliver any queued, signed update before the command loop.
	if version, sha256Hex, url, dataB64, sigB64, ok, err := s.st.PopPendingUpdate(machine.Name); err == nil && ok {
		manifest, _ := json.Marshal(protocol.UpdateCommand{
			URL: url, DataB64: dataB64, Sha256: sha256Hex, Version: version, SigB64: sigB64,
		})
		if err := conn.WriteEnvelope(protocol.Envelope{Type: "update", Payload: manifest}); err != nil {
			// Re-queue on failure so it isn't lost.
			_ = s.st.QueueUpdate(machine.Name, version, sha256Hex, url, dataB64, sigB64)
		} else {
			s.logf("update pushed to %s (v%s)", machine.Name, version)
		}
	}

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

// verifyAgentHello checks the ed25519 signature over (name|nonce). The
// nonce is unique per connection, so captured hellos can't be replayed.
func verifyAgentHello(pubHex string, hr protocol.HelloRequest, nonce string) error {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("bad key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hr.Auth, "v1 "))
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(helloMessage(hr.Name, nonce)), sig) {
		return errors.New("signature mismatch")
	}
	return nil
}

func helloMessage(name, nonce string) string { return name + "|" + nonce }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
		writeJSON(w, http.StatusOK, map[string]string{"ok": "enrolled", "machine": existing.Name, "server_key": s.serverKeyHex})
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
	writeJSON(w, http.StatusOK, map[string]string{"ok": "enrolled", "machine": p.Name, "server_key": s.serverKeyHex})
}

// ---- exec completion (called from the agent pump above) ----

type pendingExec struct {
	ch      chan protocol.ExecResult
	machine string
	command string
	source  string
}

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
		select {
		case pe.ch <- res:
		default:
		}
	}
}

// authFailures tracks failed console-auth attempts per IP for rate limiting.
type authLimiter struct {
	mu      sync.Mutex
	fails   map[string][]time.Time
}

func (a *authLimiter) tooMany(ip string) bool {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fails == nil {
		a.fails = map[string][]time.Time{}
	}
	times := a.fails[ip][:0]
	for _, t := range a.fails[ip] {
		if now.Sub(t) < 10*time.Minute {
			times = append(times, t)
		}
	}
	if len(times) >= 20 {
		a.fails[ip] = times
		return true
	}
	times = append(times, now)
	a.fails[ip] = times
	return false
}