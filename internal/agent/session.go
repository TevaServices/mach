package agent

// Live streaming session registry: stdin/kill frames arrive on the main
// daemon connection and are routed to the running session by session ID
// (the envelope ReqID).

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"sync"

	"github.com/bcross/mach/internal/protocol"
)

var (
	sessionMu    sync.Mutex
	liveSessions = map[string]*liveStream{}
)

type liveStream struct {
	stdin io.WriteCloser
	done  chan struct{}
}

// handleStreamInput routes stdin/kill frames to a live session.
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
			_ = sess.stdin.Close()
			return
		}
		if b, err := base64.StdEncoding.DecodeString(in.B64); err == nil {
			_, _ = sess.stdin.Write(b)
		}
	case "stream_kill":
		close(sess.done)
	}
}

// registerLiveSession records a running stream session (called by
// streamexec when the command starts).
func registerLiveSession(sessionID string, stdin io.WriteCloser) func() {
	sess := &liveStream{stdin: stdin, done: make(chan struct{})}
	sessionMu.Lock()
	liveSessions[sessionID] = sess
	sessionMu.Unlock()
	return func() {
		sessionMu.Lock()
		delete(liveSessions, sessionID)
		sessionMu.Unlock()
	}
}
