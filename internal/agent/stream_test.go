package agent

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/gorilla/websocket"
)

// wsPair gives a writer connected to a server-side reader, and a channel of
// the envelopes that reader receives. Chunking is exercised on the wire rather
// than mocked; the reader runs in the background because a read *timeout*
// permanently poisons a gorilla connection, so "nothing was sent yet" cannot
// be tested with a short read deadline.
func wsPair(t *testing.T) (*protocol.WSConn, <-chan protocol.Envelope) {
	t.Helper()
	serverSide := make(chan *protocol.WSConn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverSide <- protocol.NewWSConn(c)
	}))
	t.Cleanup(srv.Close)

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	var server *protocol.WSConn
	select {
	case server = <-serverSide:
	case <-time.After(5 * time.Second):
		t.Fatal("server side never connected")
	}

	frames := make(chan protocol.Envelope, 16)
	go func() {
		defer close(frames)
		for {
			_ = server.SetReadDeadline(time.Now().Add(10 * time.Second))
			env, err := server.ReadEnvelope()
			if err != nil {
				return // deadline or closed: the test is over
			}
			select {
			case frames <- env:
			case <-time.After(5 * time.Second):
				return // nobody is reading; do not leak the goroutine
			}
		}
	}()
	// The writer is what the test drives; closing it here also lets the
	// reader goroutine finish.
	t.Cleanup(func() { client.Close() })
	return protocol.NewWSConn(client), frames
}

// nextChunk waits for one exec_chunk frame and returns its decoded payload.
func nextChunk(t *testing.T, frames <-chan protocol.Envelope, reqID string) []byte {
	t.Helper()
	select {
	case env, ok := <-frames:
		if !ok {
			t.Fatal("connection closed while waiting for a chunk")
		}
		if env.Type != "exec_chunk" {
			t.Fatalf("frame type = %q, want exec_chunk", env.Type)
		}
		if env.ReqID != reqID {
			t.Fatalf("req_id = %q, want %q", env.ReqID, reqID)
		}
		var ch protocol.ExecChunk
		if err := json.Unmarshal(env.Payload, &ch); err != nil {
			t.Fatalf("payload: %v", err)
		}
		data, err := base64.StdEncoding.DecodeString(ch.DataB64)
		if err != nil {
			t.Fatalf("base64: %v", err)
		}
		return data
	case <-time.After(5 * time.Second):
		t.Fatal("no chunk arrived")
		return nil
	}
}

func expectNoFrame(t *testing.T, frames <-chan protocol.Envelope, d time.Duration) {
	t.Helper()
	select {
	case env, ok := <-frames:
		if ok {
			t.Fatalf("unexpected frame: %+v", env)
		}
	case <-time.After(d):
	}
}

func TestChunkWriterHoldsSmallWritesUntilFlush(t *testing.T) {
	w, frames := wsPair(t)
	cw := newChunkWriter(w, "req1", "stdout")
	if _, err := cw.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Under the threshold nothing is on the wire: chunking must not turn one
	// small write into one frame.
	expectNoFrame(t, frames, 150*time.Millisecond)
	cw.Flush()
	if got := string(nextChunk(t, frames, "req1")); got != "hello" {
		t.Errorf("flushed %q, want %q", got, "hello")
	}
}

func TestChunkWriterFlushesAtThreshold(t *testing.T) {
	w, frames := wsPair(t)
	cw := newChunkWriter(w, "req2", "stderr")
	payload := strings.Repeat("x", chunkFlushBytes)
	if _, err := cw.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A full threshold's worth goes out without waiting for Flush or a tick.
	if got := nextChunk(t, frames, "req2"); len(got) != chunkFlushBytes {
		t.Fatalf("chunk len = %d, want %d", len(got), chunkFlushBytes)
	}
	expectNoFrame(t, frames, 100*time.Millisecond)
}

func TestChunkWriterCapsAndMarksTruncation(t *testing.T) {
	w, frames := wsPair(t)
	cw := newChunkWriter(w, "req3", "stdout")
	cw.limit = 10
	// Overflow writes are swallowed, not turned into errors: the process must
	// keep running so its exit status can still be reported.
	for i := 0; i < 3; i++ {
		n, err := cw.Write([]byte("0123456789"))
		if err != nil || n != 10 {
			t.Fatalf("write %d: n=%d err=%v", i, n, err)
		}
	}
	cw.Close()
	// One chunk: the capped head, then the marker. Everything past the cap is
	// gone, and the marker is what tells the console output was lost.
	want := "0123456789" + truncationMarker
	if got := string(nextChunk(t, frames, "req3")); got != want {
		t.Fatalf("chunk = %q, want %q", got, want)
	}
	// Exactly one chunk: the terminal exec_result is sent by the caller
	// (handleExec), after Close.
	expectNoFrame(t, frames, 150*time.Millisecond)
}

func TestChunkWriterNeverErrorsAfterBreak(t *testing.T) {
	w, _ := wsPair(t)
	cw := newChunkWriter(w, "req4", "stdout")
	// flushLocked sets broken when the control plane refuses a chunk (the peer
	// is gone); the state is set directly here so the contract is tested
	// without depending on when a TCP reset is observed.
	cw.broken = true
	for i := 0; i < 2; i++ {
		if n, err := cw.Write([]byte("more output")); n != len("more output") || err != nil {
			t.Fatalf("write %d after break: n=%d err=%v", i, n, err)
		}
	}
	cw.Flush()
	cw.Close() // must not panic nor try to send
}
