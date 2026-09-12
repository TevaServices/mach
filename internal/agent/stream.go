package agent

import (
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/bcross/mach/internal/protocol"
)

// Output streaming.
//
// A command's output is relayed to the control plane as it is produced rather
// than buffered until the command exits: `mach console` prints live, a long
// command is observable while it runs, and the control plane writes its audit
// row from the head of the stream instead of waiting for the whole result.
//
// Chunking exists because one WebSocket frame per write would be pure
// overhead: bytes accumulate until a size threshold, with a slow ticker so a
// trickle of output (`tail -f`) still arrives promptly.
//
// The per-stream byte cap is unchanged from the buffered implementation: past
// maxOutputBytes the process keeps running but further output is discarded and
// a truncation marker is appended, so `cat /dev/urandom` cannot OOM the agent.
// The difference is that the head of the output has already been delivered by
// then, so a runaway command is still observable rather than lost.
const (
	chunkFlushBytes    = 8 << 10
	chunkFlushInterval = 100 * time.Millisecond

	// maxOutputBytes is the per-stream cap: no single command's stdout (or
	// stderr) may exceed this much delivered output.
	maxOutputBytes = 8 << 20 // 8 MiB

	// truncationMarker is appended to a stream that hit the cap. It is what
	// tells the console that output is missing, so it must survive to the
	// client and be distinguishable from a command that printed this text
	// itself (it is prefixed like every other mach diagnostic).
	truncationMarker = "\n[mach: output truncated at cap]\n"
)

// chunkWriter sends one output stream of one command to the control plane. It
// implements io.Writer for os/exec, which writes from a single goroutine per
// stream — but a ticker also drives flushes, so all state is mutex-guarded.
type chunkWriter struct {
	conn   *protocol.WSConn
	reqID  string
	stream string
	limit  int // per-stream byte cap; maxOutputBytes in production

	mu      sync.Mutex
	buf     []byte
	taken   int  // bytes accepted from the process, including bytes past the cap
	dropped bool // cap hit; a truncation marker is still owed
	broken  bool // the control plane refused a chunk; stop trying
}

func newChunkWriter(conn *protocol.WSConn, reqID, stream string) *chunkWriter {
	return &chunkWriter{conn: conn, reqID: reqID, stream: stream, limit: maxOutputBytes}
}

// Write never reports an error: once the cap is hit the process must keep
// running (and its exit status must still be reported), so overflow is
// swallowed exactly as the buffered implementation did.
func (w *chunkWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.broken {
		return len(p), nil
	}
	room := w.limit - w.taken
	switch {
	case room <= 0:
		w.dropped = true
	case len(p) > room:
		w.buf = append(w.buf, p[:room]...)
		w.taken = w.limit
		w.dropped = true
	default:
		w.buf = append(w.buf, p...)
		w.taken += len(p)
	}
	if len(w.buf) >= chunkFlushBytes {
		w.flushLocked()
	}
	return len(p), nil
}

// Flush sends whatever is buffered. Safe to call at any time (the ticker does).
func (w *chunkWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushLocked()
}

// Close flushes the tail and, if the cap was hit, appends the truncation
// marker. Must be called before the terminal exec_result so the marker cannot
// arrive after the command has been reported finished.
func (w *chunkWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dropped && !w.broken {
		w.buf = append(w.buf, truncationMarker...)
		w.dropped = false
	}
	w.flushLocked()
}

func (w *chunkWriter) flushLocked() {
	if len(w.buf) == 0 || w.broken {
		return
	}
	payload, err := json.Marshal(protocol.ExecChunk{
		Stream:  w.stream,
		DataB64: base64.StdEncoding.EncodeToString(w.buf),
	})
	if err != nil {
		w.broken = true
		return
	}
	if err := w.conn.WriteEnvelope(protocol.Envelope{Type: "exec_chunk", ReqID: w.reqID, Payload: payload}); err != nil {
		// The control plane is gone. The command keeps running (there is no
		// way to cancel what was already launched), but stop hammering a dead
		// socket once per flush interval.
		w.broken = true
	}
	w.buf = w.buf[:0]
}
