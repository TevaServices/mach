package agent

// Live streaming session registry: stdin/kill frames arrive on the main
// daemon connection and are routed to the running session by session ID
// (the envelope ReqID).

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"sync"

	"github.com/TevaServices/mach/internal/protocol"
)

// streamInputQueue bounds how many stdin frames a session will hold for a
// command that is not reading them. Small on purpose: a person typing a line at
// a time never comes close, and the queue only fills when nobody is listening.
const streamInputQueue = 64

var (
	sessionMu    sync.Mutex
	liveSessions = map[string]*liveStream{}
)

type liveStream struct {
	stdin io.WriteCloser
	// input hands stdin bytes to the session's own writer goroutine. The frame
	// loop must never write to the command's pipe itself: that Write blocks as
	// soon as the pipe buffer fills, and a command that is not reading its stdin
	// is precisely the one a person types into by hand. Doing it inline stalled
	// the whole agent — no other frame (another session's kill, an exec, a policy
	// update, a retire) could be dispatched until the running command exited.
	input chan []byte
	// kill ends the running command. It is a function rather than a flag polled
	// elsewhere because both halves of stopping a session belong to the session
	// that owns the process: closing stdin so a command that reads it sees EOF,
	// and signalling the process group so a command that never reads stdin stops
	// at all.
	//
	// Closing stdin alone was the whole of what a kill used to do, and it made
	// the console's Ctrl-C a no-op for exactly the commands an operator most
	// wants to stop: `sleep 600`, a wedged build, a hung network client. The
	// console prints "Ctrl-C kills the remote session", and it did not.
	kill func()
}

// handleStreamInput routes stdin/kill frames to a live session.
//
// Everything it does under sessionMu is non-blocking, because it runs inline
// from the frame loop that dispatches every other frame too.
func handleStreamInput(env protocol.Envelope) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	sess := liveSessions[env.ReqID]
	if sess == nil {
		return
	}
	switch env.Type {
	case "stream_stdin":
		var in protocol.StreamStdin
		if json.Unmarshal(env.Payload, &in) != nil {
			return
		}
		if in.EOF {
			// The writer goroutine closes the pipe when it drains the queue, so
			// EOF keeps its place in the order the console sent it.
			select {
			case sess.input <- nil:
			default:
			}
			return
		}
		b, err := base64.StdEncoding.DecodeString(in.B64)
		if err != nil {
			return
		}
		// A full queue drops the frame rather than stalling the frame loop —
		// the same trade the relay makes for output frames, and for the same
		// reason: this queue is fed by the loop that serves every other command
		// on the connection. Reaching it means the command has not read 64
		// frames' worth of input, which is a command that is not reading stdin at
		// all.
		select {
		case sess.input <- b:
		default:
		}
	case "stream_kill":
		sess.kill()
	}
}

// registerLiveSession records a running stream session (called by streamexec
// when the command starts) and returns the function that retires it. kill stops
// the session's command; it is safe to call more than once and from any
// goroutine. Closing the returned function's channel stops the writer goroutine,
// so a session that ends normally does not leak one.
func registerLiveSession(sessionID string, stdin io.WriteCloser, kill func()) (input chan []byte, unregister func()) {
	input = make(chan []byte, streamInputQueue)
	sess := &liveStream{stdin: stdin, input: input, kill: kill}
	sessionMu.Lock()
	liveSessions[sessionID] = sess
	sessionMu.Unlock()
	return input, func() {
		// Close while holding the lock: every send into the channel happens under
		// it too, so closing here cannot race with one and panic.
		sessionMu.Lock()
		delete(liveSessions, sessionID)
		close(input)
		sessionMu.Unlock()
	}
}

// pumpSessionInput writes queued stdin to the command's pipe on the session's
// own goroutine, and closes the pipe at EOF or when the session ends.
func pumpSessionInput(input chan []byte, stdin io.WriteCloser) {
	for b := range input {
		if b == nil {
			_ = stdin.Close()
			continue
		}
		if _, err := stdin.Write(b); err != nil {
			return
		}
	}
	// The queue was closed: the session is over. Closing the pipe releases a
	// command still waiting on a read, so it can exit instead of waiting out the
	// session's timeout.
	_ = stdin.Close()
}
