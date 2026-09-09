package server

// Streaming console relay (limitation #3): `mach console` opens a
// dedicated authenticated WebSocket; the control plane pairs it with the
// target machine's agent WebSocket and relays frames bidirectionally:
//
//   console → {exec_stream: {command|argv}} → agent
//   agent   → {stream_out: {stream,b64}}    → console
//   console → {stream_stdin: {b64}}         → agent
//   agent   → {stream_end: {exit_code}}     → console (then both close)
//
// Frames are small JSON envelopes (output chunked at 32 KiB by the agent);
// the relay adds no buffering beyond backpressure from the sockets. This
// is streaming, not a PTY: no echo/line discipline — TUI apps still need a
// real PTY (tracked as future work). E2E mode: sealed variants carry the
// same streams encrypted; the relay sees only opaque b64 blobs.

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/bcross/mach/internal/store"
)

// streamSessions tracks active console↔agent relay pairs by session ID.
var (
	streamMu       sync.Mutex
	streamSessions = map[string]*streamRelay{}
)

type streamRelay struct {
	ConsoleCh chan protocol.Envelope
	AgentCh   chan protocol.Envelope
	Done      chan struct{}
	machine   string
}

func newStreamRelay(machine string) *streamRelay {
	r := &streamRelay{
		ConsoleCh: make(chan protocol.Envelope, 64),
		AgentCh:   make(chan protocol.Envelope, 64),
		Done:      make(chan struct{}),
		machine:   machine,
	}
	return r
}

// handleConsoleStreamWS is the console's streaming endpoint (machine in
// query string, same bearer auth as exec).
func (s *Server) handleConsoleStreamWS(w http.ResponseWriter, r *http.Request, _, scopes string) {
	// Auth (bearer key name/scopes) validated by the authConsole wrapper.
	machine := r.URL.Query().Get("machine")
	if !keyCanExecOn(scopes, machine) && scopes != "readonly" {
		http.Error(w, "key is not scoped for machine "+machine, http.StatusForbidden)
		return
	}

	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	consoleConn := protocol.NewWSConn(ws)
	defer consoleConn.Close()

	// Ask the agent to open a matching stream session.
	ac := s.br.WaitOnline(machine, 15*time.Second)
	if ac == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "machine offline or unknown: " + machine})
		return
	}

	sessionID := store.RandToken(8)
	relay := newStreamRelay(machine)
	streamMu.Lock()
	streamSessions[sessionID] = relay
	streamMu.Unlock()
	defer func() {
		streamMu.Lock()
		delete(streamSessions, sessionID)
		streamMu.Unlock()
		close(relay.Done)
	}()

	// Bind the relay to this console and the agent pump (agent side picks
	// frames with matching SessionID out of its command loop).
	s.br.BindStream(sessionID, relay.AgentCh, machine)

	// Tell the console its session ID so errors are traceable.
	_ = consoleConn.WriteEnvelope(protocol.Envelope{Type: "stream_hello", ReqID: sessionID})

	// Pump: console → agent (exec_stream/stream_stdin) and agent → console
	// (stream_out/stream_end). Both directions ride the channels above;
	// the agent side pushes via s.br.SendToStream.
	go func() {
		for {
			select {
			case env := <-relay.ConsoleCh:
				_ = consoleConn.WriteEnvelope(env)
			case <-relay.Done:
				return
			}
		}
	}()

	for {
		_ = ws.SetReadDeadline(time.Now().Add(120 * time.Second))
		env, err := consoleConn.ReadEnvelope()
		if err != nil {
			s.br.UnbindStream(sessionID)
			return
		}
		switch env.Type {
		case "exec_stream", "stream_stdin":
			env.ReqID = sessionID // tag for the agent pump routing
			s.br.SendToStream(sessionID, env)
		case "stream_kill":
			s.br.SendToStream(sessionID, env)
		default:
			// ignore unknown frames from consoles
		}
	}
}

func stripBearer(h string) string {
	const p = "Bearer "
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return h
}

// streamOutChunkSize is the max payload bytes per stream_out chunk.
const streamOutChunkSize = 32 << 10

var _ = json.Marshal