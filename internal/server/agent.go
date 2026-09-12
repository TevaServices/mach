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
	if s.pairStarts.record(s.clientIP(r)) {
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
		// The machine name is deliberately not echoed back: this endpoint is
		// unauthenticated, so anyone holding a public key (an agent's key is
		// not a secret once it has been used anywhere) could otherwise confirm
		// which machine it belongs to. The agent already knows its own name.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "this agent key is already enrolled; delete the existing machine to re-enroll it"})
		return
	}
	id, token, code, err := s.st.CreatePairing(req.PubKey, req.Hostname, req.OS, req.Arch, req.AgentVer, s.pairingTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	s.logf("pair start: id=%q host=%q", id, req.Hostname)
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
	// Bounded per IP, and generous: real agents poll every ~2s for the whole
	// 10-minute pairing window (~300 requests), so the limit has to sit well
	// above that or legitimate enrollment starves behind its own polling.
	if s.pairLookups.record(s.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		return
	}
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
		// Upgrade-then-close instead of a 401: an HTTP-level error would be
		// an oracle for distinguishing "known machine" from "unknown" during
		// name enumeration. (Revoked machines get the explicit frame below.)
		if ws0, err0 := s.upgrader.Upgrade(w, r, nil); err0 == nil {
			ws0.SetReadLimit(64 << 10)
			_ = ws0.SetReadDeadline(time.Now().Add(10 * time.Second))
			ws0.Close()
		}
		return
	}
	if machine.Revoked {
		ws2, err2 := s.upgrader.Upgrade(w, r, nil)
		if err2 == nil {
			ws2.SetReadLimit(64 << 10)
			_ = ws2.SetReadDeadline(time.Now().Add(10 * time.Second))
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

	// Pre-auth window: bounded frames and a hard deadline to finish hello,
	// so an unauthenticated client can neither buffer an unbounded frame
	// nor hold a connection open indefinitely.
	ws.SetReadLimit(64 << 10)
	_ = ws.SetReadDeadline(time.Now().Add(15 * time.Second))

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
	if err := json.Unmarshal(env.Payload, &hr); err != nil || hr.PubKey != machine.PubKey || hr.Name != machine.Name || verifyAgentHello(machine.PubKey, hr, nonce) != nil {
		_ = conn.WriteEnvelope(protocol.Envelope{Type: "hello_result", Payload: mustJSON(protocol.HelloResponse{OK: false, Error: "bad signature or key"})})
		return
	}
	// Mutual authentication: sign the challenge with this control plane's
	// identity key. The agent verifies against the key it pinned at
	// enrollment, so a hijacked TLS layer cannot impersonate the server.
	resp := protocol.HelloResponse{OK: true, ServerAuth: "v1 " + base64.StdEncoding.EncodeToString(ed25519.Sign(s.serverPriv, []byte("server|"+nonce)))}
	_ = conn.WriteEnvelope(protocol.Envelope{Type: "hello_result", Payload: mustJSON(resp)})

	// Authenticated: an agent only ever sends hello, ping, exec_chunk and
	// exec_result. The largest of those is a chunk — one flush's worth of
	// output (8 KiB) plus at most one os/exec copy (32 KiB), base64'd to
	// ~55 KiB — so the cap sits four times above the real maximum. It used to
	// be 40 MiB, from when exec_result carried a whole command's output;
	// streaming means that no longer exists, and the cap is what bounds how
	// much a single agent connection can make this server allocate at once.
	ws.SetReadLimit(256 << 10)

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
			s.logf("update pushed to %q (v%q)", machine.Name, version)
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
		case "exec_chunk":
			s.streamChunk(env, machine.Name)
		case "exec_result":
			s.completeExec(env, machine.Name)
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
	s.logf("pair claimed: machine=%q", p.Name)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "enrolled", "machine": p.Name, "server_key": s.serverKeyHex})
}

// ---- exec streaming and completion (called from the agent pump above) ----

const (
	// execOutChanBuf bounds the chunks buffered for one exec while it waits
	// for the console to read them. Beyond it chunks are dropped and the
	// console is told, rather than blocking the agent's frame pump — which
	// serves every other exec on that machine connection too.
	execOutChanBuf = 512

	// auditHeadBytes is how much of each output stream is kept for the audit
	// row (the store trims further, to 4096 bytes, on insert).
	auditHeadBytes = 8 << 10

	// execWriteTimeout bounds one write of a stream frame to a console.
	execWriteTimeout = 60 * time.Second
)

// pendingExec is one in-flight command: the live output channel the console
// reads, and the head of that output kept for the audit row it will leave.
type pendingExec struct {
	ch      chan execOutcome        // terminal result (buffered: never blocks the pump)
	out     chan protocol.ExecChunk // live output, consumed by the HTTP handler
	machine string
	command string
	source  string

	// Owned by the agent pump, read by the HTTP handler once the terminal
	// result has been delivered (the channel send orders the two).
	mu        sync.Mutex
	stdout    []byte
	stderr    []byte
	truncated bool // output dropped here: the console was too slow
}

// execOutcome is the terminal state delivered on pendingExec.ch.
type execOutcome struct {
	res       protocol.ExecResult
	stdout    string
	stderr    string
	truncated bool
}

func (pe *pendingExec) appendOut(stream string, data []byte) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	dst := &pe.stdout
	if stream == "stderr" {
		dst = &pe.stderr
	}
	if room := auditHeadBytes - len(*dst); room > 0 {
		if len(data) > room {
			data = data[:room] // the store trims to a rune boundary on insert
		}
		*dst = append(*dst, data...)
	}
}

func (pe *pendingExec) markTruncated() {
	pe.mu.Lock()
	pe.truncated = true
	pe.mu.Unlock()
}

func (pe *pendingExec) outcome(res protocol.ExecResult) execOutcome {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	return execOutcome{res: res, stdout: string(pe.stdout), stderr: string(pe.stderr), truncated: pe.truncated}
}

// pendingFor resolves a frame from a machine to its pending exec. An exec may
// only be streamed or completed by the machine it was dispatched to: without
// that check, any other enrolled machine could inject output into (or end) a
// command it was never sent.
func (s *Server) pendingFor(reqID, fromMachine string) *pendingExec {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	pe, ok := s.pending[reqID]
	if !ok || pe.machine != fromMachine {
		return nil
	}
	return pe
}

// streamChunk relays one piece of a running command's output to the console.
// Called from the agent pump, so it must never block.
func (s *Server) streamChunk(env protocol.Envelope, fromMachine string) {
	var ch protocol.ExecChunk
	if err := json.Unmarshal(env.Payload, &ch); err != nil {
		return
	}
	if ch.Stream != "stdout" && ch.Stream != "stderr" {
		// Relay only the two streams the console knows. An agent must not be
		// able to invent a third label and have it echoed to a client.
		return
	}
	data, err := base64.StdEncoding.DecodeString(ch.DataB64)
	if err != nil {
		return
	}
	pe := s.pendingFor(env.ReqID, fromMachine)
	if pe == nil {
		return // unknown exec, or one dispatched to a different machine
	}
	pe.appendOut(ch.Stream, data)
	select {
	case pe.out <- ch:
	default:
		pe.markTruncated()
	}
}

func (s *Server) completeExec(env protocol.Envelope, fromMachine string) {
	var res protocol.ExecResult
	if err := json.Unmarshal(env.Payload, &res); err != nil {
		res = protocol.ExecResult{Error: "bad exec_result payload", ExitCode: -1}
	}
	pe := s.pendingFor(env.ReqID, fromMachine)
	if pe == nil {
		return
	}
	s.pendMu.Lock()
	delete(s.pending, env.ReqID)
	s.pendMu.Unlock()
	select {
	case pe.ch <- pe.outcome(res):
	default:
	}
}
