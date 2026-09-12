package server

// Streaming console relay: `mach console` opens a dedicated authenticated
// WebSocket; the control plane pairs it with the target machine's agent
// WebSocket and relays frames in both directions:
//
//	console → {exec_stream: {command|argv}} → agent
//	agent   → {stream_out: {stream,b64}}    → console
//	console → {stream_stdin: {b64}}         → agent
//	agent   → {stream_end: {exit_code}}     → console (then the console closes)
//
// Frames are small JSON envelopes (output chunked at 32 KiB by the agent); the
// relay adds no buffering beyond backpressure from the sockets. This is
// streaming, not a PTY: no echo/line discipline — TUI apps still need a real
// PTY (tracked as future work).
//
// This path is plaintext by design, and that is not an accident: one-shot
// `mach exec` is the path that can be end-to-end sealed, while a live stream of
// many small frames cannot be sealed per-chunk without the server learning the
// frame boundaries anyway. Because the relay can read the command, it is also
// the only path where the fleet-wide exec policy can be enforced on the server
// side — see the note on sealed exec in handleExec.
//
// Every command dispatched through here is audited, exactly like the buffered
// path: the row is written when the agent reports the exit status, carrying the
// head of the output. A control plane that streams commands without recording
// them would be a hole in the audit trail.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/bcross/mach/internal/store"
)

// auditHeadBytes bounds how much of a streamed command's output the relay
// keeps for the audit row. The store truncates again on insert; this cap only
// stops a chatty command from growing the session's memory without limit while
// the console reads at its own pace.
const auditHeadBytes = 8 << 10

// consoleStreamIdle bounds a quiet console. Any frame from the console — or a
// pong answering this server's keepalive ping — refreshes it, so a long-running
// command whose console is simply not typing is never cut off; a console whose
// host has vanished is dropped.
const consoleStreamIdle = 120 * time.Second

// streamPingInterval is how often the relay pings the console to keep the idle
// deadline alive while a command runs and the user types nothing.
const streamPingInterval = 30 * time.Second

// streamSessions tracks active console↔agent relay pairs by session ID, so a
// teardown can find the relay to unbind. streamsByMachine is the same set
// indexed the other way, so an operator action can find every session for one
// machine — streamSessions carries the machine only as a field.
var (
	streamMu         sync.Mutex
	streamSessions   = map[string]*streamRelay{}
	streamsByMachine = map[string]map[string]bool{}
)

type streamRelay struct {
	machine string
	// console is the console end of this relay, retained so the session can be
	// ended from outside it. Without it a session could only be ended by the
	// console itself or by the idle deadline — and the keepalive pings below
	// keep that deadline from ever firing.
	console *protocol.WSConn
	// toConsole carries agent-originated frames to the console socket. The
	// agent pump pushes into it through the broker, which drops a frame rather
	// than stalling an agent whose console has stopped reading.
	toConsole chan protocol.Envelope
	Done      chan struct{}
	// stopOnce guards Done, which two goroutines may now want to close: the
	// handler's own teardown and an operator's block.
	stopOnce sync.Once

	// Audit bookkeeping for the command running in this session. Guarded
	// because the console pump (which captures output) and the console read
	// loop (which starts and ends commands) are different goroutines.
	mu      sync.Mutex
	command string // display form; "" when no command is running
	source  string
	out     []byte
	errOut  []byte
}

func newStreamRelay(machine string, console *protocol.WSConn) *streamRelay {
	return &streamRelay{
		machine:   machine,
		console:   console,
		toConsole: make(chan protocol.Envelope, 64),
		Done:      make(chan struct{}),
	}
}

// stop ends this session's delivery loop. Idempotent, because the handler's own
// teardown and an operator's kill can both reach it.
func (r *streamRelay) stop() { r.stopOnce.Do(func() { close(r.Done) }) }

// kill ends the session from outside its handler: the console is told why, and
// then the socket is closed.
//
// Closing is what actually ends it. The handler is parked in a read on that
// socket, so closing makes the read fail and the normal teardown runs — which
// then unregisters the session and writes the audit row for a command that
// never reported an exit status.
func (r *streamRelay) kill(reason string) {
	if r.console != nil {
		_ = r.console.WriteEnvelope(protocol.Envelope{
			Type:    "stream_end",
			Payload: mustJSON(protocol.StreamEnd{ExitCode: -1, Error: reason}),
		})
		r.console.Close()
	}
	r.stop()
}

// registerStream records a session in both indexes.
func registerStream(sessionID string, relay *streamRelay) {
	streamMu.Lock()
	streamSessions[sessionID] = relay
	if streamsByMachine[relay.machine] == nil {
		streamsByMachine[relay.machine] = map[string]bool{}
	}
	streamsByMachine[relay.machine][sessionID] = true
	streamMu.Unlock()
}

// unregisterStream drops a session from both indexes.
func unregisterStream(sessionID, machine string) {
	streamMu.Lock()
	delete(streamSessions, sessionID)
	if set := streamsByMachine[machine]; set != nil {
		delete(set, sessionID)
		if len(set) == 0 {
			delete(streamsByMachine, machine)
		}
	}
	streamMu.Unlock()
}

// killStreamsForMachine ends every live console session for a machine and
// reports how many it ended.
//
// Used when an operator blocks a machine. A soft block stops *new* commands, but
// a session opened before it would otherwise keep feeding stdin — or killing the
// running command — for as long as its console stayed connected, which is the
// opposite of what blocking a machine means.
//
// What this deliberately does NOT do is cancel the command on the machine. The
// documented behaviour is that a command keeps running when its console goes
// away, and synthesising a stream_kill here would be a new remote-kill
// capability rather than a freeze on terminal communication. The audit row
// records the session as ending without an exit status, which is what happened.
// streamCountForMachine reports how many console sessions are live for a
// machine.
//
// It exists so a test can assert the index without reaching into the map, which
// would be a read outside streamMu — a race the detector catches, and one that
// would be invisible in production because every real caller holds the lock.
func streamCountForMachine(machine string) int {
	streamMu.Lock()
	defer streamMu.Unlock()
	return len(streamsByMachine[machine])
}

func (s *Server) killStreamsForMachine(machine, reason string) int {
	streamMu.Lock()
	relays := make([]*streamRelay, 0, len(streamsByMachine[machine]))
	for id := range streamsByMachine[machine] {
		if r := streamSessions[id]; r != nil {
			relays = append(relays, r)
		}
	}
	streamMu.Unlock()
	for _, r := range relays {
		r.kill(reason)
	}
	return len(relays)
}

// beginCommand records the command a stream is about to run, for the audit row
// written when it ends.
func (r *streamRelay) beginCommand(command, source string) {
	r.mu.Lock()
	r.command, r.source = command, source
	r.out, r.errOut = nil, nil
	r.mu.Unlock()
}

// capture keeps the head of the command's output for the audit row.
func (r *streamRelay) capture(stream string, b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case stream == "stderr":
		r.errOut = appendHead(r.errOut, b, auditHeadBytes)
	default:
		r.out = appendHead(r.out, b, auditHeadBytes)
	}
}

func appendHead(dst, b []byte, max int) []byte {
	if len(dst) >= max {
		return dst
	}
	if room := max - len(dst); len(b) > room {
		return append(dst, b[:room]...)
	}
	return append(dst, b...)
}

// takeCommand returns the running command's audit fields and clears them, so a
// session that ends after a command is audited once and only once.
func (r *streamRelay) takeCommand() (command, source, stdout, stderr string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.command == "" {
		return "", "", "", "", false
	}
	command, source, ok = r.command, r.source, true
	stdout, stderr = string(r.out), string(r.errOut)
	r.command, r.source, r.out, r.errOut = "", "", nil, nil
	return command, source, stdout, stderr, ok
}

// handleConsoleStreamWS is the console's streaming endpoint (machine in the
// query string, same bearer auth as exec).
func (s *Server) handleConsoleStreamWS(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
	machine := r.URL.Query().Get("machine")
	// Exec scope, and only exec scope: a readonly key reads the fleet and the
	// audit log, it does not run commands. Accepting "readonly" here would make
	// the scope meaningless — streaming is command execution.
	if !keyCanExecOn(scopes, machine) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "key is not scoped for machine " + machine})
		return
	}
	// The operator's soft block, refused here rather than after the upgrade:
	// streaming is command execution, so a blocked machine must not open a
	// session at all, and an HTTP status is a clearer answer than a session that
	// immediately dies.
	if ref := s.dispatchRefusal(machine); ref != nil {
		writeJSON(w, ref.status, map[string]string{"error": ref.msg})
		return
	}

	// Resolve the agent before upgrading: an HTTP status is the only way to
	// tell the console "no such machine / offline", and the console's client
	// relies on the dial failing to fall back to buffered exec. After a
	// successful upgrade there is no HTTP response left to send.
	ac := s.br.WaitOnline(machine, 15*time.Second)
	if ac == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "machine offline or unknown: " + machine})
		return
	}

	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	consoleConn := protocol.NewWSConn(ws)
	defer consoleConn.Close()

	sessionID := store.RandToken(8)
	relay := newStreamRelay(machine, consoleConn)
	registerStream(sessionID, relay)
	defer func() {
		unregisterStream(sessionID, machine)
		s.br.UnbindStream(sessionID)
		relay.stop()
		// A command that never reported an exit status — the console
		// disconnected mid-stream, or the agent died — still leaves a record.
		// The command's fate on the machine is unknown; it is not cancelled by
		// the console going away, so the row says as much rather than
		// pretending it succeeded.
		if command, source, stdout, stderr, ok := relay.takeCommand(); ok {
			if stderr != "" {
				stderr += "\n"
			}
			stderr += "[mach: stream closed before the command reported an exit status]"
			s.st.AuditInsert(nowRFC3339(), machine, command, source,
				sqlNullInt(-1), stdout, stderr)
		}
	}()

	// Bind the relay to this console: the agent pump delivers frames tagged
	// with this session ID to relay.toConsole.
	s.br.BindStream(sessionID, relay.toConsole, machine)

	// Tell the console its session ID so errors are traceable.
	_ = consoleConn.WriteEnvelope(protocol.Envelope{Type: "stream_hello", ReqID: sessionID})

	// Keepalive: the console's read side is silent while a command runs, so
	// without this its idle deadline would sever a long-running command's
	// stream. The console's websocket answers pings automatically.
	pingDone := make(chan struct{})
	defer close(pingDone)
	go func() {
		t := time.NewTicker(streamPingInterval)
		defer t.Stop()
		for {
			select {
			case <-pingDone:
				return
			case <-relay.Done:
				return
			case <-t.C:
				_ = consoleConn.Ping()
			}
		}
	}()
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(consoleStreamIdle))
	})

	// Agent → console, plus the audit capture that has to see the frames go by.
	go func() {
		for {
			select {
			case env := <-relay.toConsole:
				if env.Type == "stream_out" {
					var out protocol.StreamOut
					if json.Unmarshal(env.Payload, &out) == nil {
						if b, derr := base64.StdEncoding.DecodeString(out.B64); derr == nil {
							relay.capture(out.Stream, b)
						}
					}
				}
				if err := consoleConn.WriteEnvelope(env); err != nil {
					return
				}
				if env.Type != "stream_end" {
					continue
				}
				var end protocol.StreamEnd
				_ = json.Unmarshal(env.Payload, &end)
				if command, source, stdout, stderr, ok := relay.takeCommand(); ok {
					if end.Error != "" {
						if stderr != "" {
							stderr += "\n"
						}
						stderr += "[mach: " + end.Error + "]"
					}
					s.st.AuditInsert(nowRFC3339(), machine, command, source,
						sqlNullInt(end.ExitCode), stdout, stderr)
				}
			case <-relay.Done:
				return
			}
		}
	}()

	for {
		_ = ws.SetReadDeadline(time.Now().Add(consoleStreamIdle))
		env, err := consoleConn.ReadEnvelope()
		if err != nil {
			return
		}
		switch env.Type {
		case "exec_stream":
			var start protocol.StreamStart
			if err := json.Unmarshal(env.Payload, &start); err != nil {
				s.streamRefuse(consoleConn, machine, "bad exec_stream payload")
				continue
			}
			display := commandForDisplay(start.Command, start.Argv)
			// The fleet-wide block list, checked here for the same reason the
			// buffered path checks it there: every client, every scope and
			// every machine, before anything is dispatched. The agent evaluates
			// its own policy too, but a policy that only lives on the machine
			// is not fleet-wide.
			if reason := s.execPolicyCheck(start.Command, start.Argv); reason != "" {
				s.st.AuditInsert(nowRFC3339(), machine, display, "console:"+keyName,
					sqlNullInt(execRefused), "", "blocked by the server's global exec policy: "+reason)
				s.streamRefuse(consoleConn, machine, "blocked by the server's global exec policy: "+reason)
				continue
			}
			// The operator's soft block, re-checked per command: the check at
			// connect only covers the moment the session opened, and a block set
			// while it is idle must stop the next command too.
			if ref := s.dispatchRefusal(machine); ref != nil {
				s.st.AuditInsert(nowRFC3339(), machine, display, "console:"+keyName,
					sqlNullInt(execRefused), "", ref.msg)
				s.streamRefuse(consoleConn, machine, ref.msg)
				continue
			}
			relay.beginCommand(display, "console:"+keyName)
			env.ReqID = sessionID // tag for the agent pump's routing
			s.streamToAgent(sessionID, consoleConn, env)
		case "stream_stdin", "stream_kill":
			// Also gated. Refusing only exec_stream would leave a session that
			// can still feed — or kill — a command already running, which is
			// terminal communication by any reading.
			if ref := s.dispatchRefusal(machine); ref != nil {
				s.streamRefuse(consoleConn, machine, ref.msg)
				continue
			}
			env.ReqID = sessionID
			s.streamToAgent(sessionID, consoleConn, env)
		default:
			// ignore unknown frames from consoles
		}
	}
}

// streamRefuse reports a command the relay declined to dispatch (or could not
// parse) as a stream_end record. After the upgrade there is no HTTP response
// left, so the console learns the outcome the way it learns every other stream
// outcome — from the terminal record — and the caller sees the refusal text and
// the exit status rather than an empty session.
func (s *Server) streamRefuse(consoleConn *protocol.WSConn, machine, reason string) {
	_ = consoleConn.WriteEnvelope(protocol.Envelope{
		Type:    "stream_end",
		Payload: mustJSON(protocol.StreamEnd{ExitCode: execRefused, Error: reason}),
	})
}

// streamToAgent writes a console-originated frame to the machine's live agent
// connection. The target is resolved per frame so a session survives an agent
// reconnect; when the agent is gone the console is told the stream ended rather
// than left waiting for output that cannot come.
func (s *Server) streamToAgent(sessionID string, consoleConn *protocol.WSConn, env protocol.Envelope) {
	target := s.br.StreamTarget(sessionID)
	if target == nil {
		_ = consoleConn.WriteEnvelope(protocol.Envelope{
			Type:    "stream_end",
			Payload: mustJSON(protocol.StreamEnd{ExitCode: -1, Error: "agent connection lost"}),
		})
		return
	}
	if err := target.Conn.WriteEnvelope(env); err != nil {
		_ = consoleConn.WriteEnvelope(protocol.Envelope{
			Type:    "stream_end",
			Payload: mustJSON(protocol.StreamEnd{ExitCode: -1, Error: "agent connection lost"}),
		})
	}
}
