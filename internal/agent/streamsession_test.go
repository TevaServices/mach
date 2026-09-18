package agent

// A streaming session's two control paths: the kill the console sends when the
// operator presses Ctrl-C, and the stdin it can type into the running command.
//
// Both were broken in ways that only show up against a command that is not
// cooperating — which is exactly the command a person reaches for Ctrl-C on.
// Closing stdin was the whole of a kill, so `sleep 600`, a wedged build, or a
// hung network client ran to completion while the console printed "Ctrl-C kills
// the remote session"; and because the same session could be killed twice, a
// second frame panicked the agent with "close of closed channel", which nothing
// recovers and which therefore took the whole process down.

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
)

// TestStreamKillStopsACommandThatIgnoresStdin is the point of the kill path: a
// command that never reads its stdin must stop anyway. The assertion is on the
// output, not on the exit status — the failure mode being guarded is a command
// that runs to completion, and its output is the proof that it did.
func TestStreamKillStopsACommandThatIgnoresStdin(t *testing.T) {
	if runtimeGOOS() == "windows" {
		t.Skip("no portable sleep binary on windows")
	}
	globalPolicy.install("")
	conn, peer := streamPipe(t)

	payload, _ := json.Marshal(protocol.StreamStart{Command: "sleep 5; echo ran-to-completion"})
	go handleStream(conn, protocol.Envelope{Type: "exec_stream", ReqID: "sess-kill", Payload: payload},
		make(chan struct{}, 1), nil)

	time.Sleep(600 * time.Millisecond)
	handleStreamInput(protocol.Envelope{Type: "stream_kill", ReqID: "sess-kill", Payload: json.RawMessage("{}")})

	start := time.Now()
	stdout, _, end := collectStream(t, peer)
	if strings.Contains(stdout, "ran-to-completion") {
		t.Fatalf("the command outlived the kill: stdout=%q (%.1fs)", stdout, time.Since(start).Seconds())
	}
	// Killed is not timed out: the two produce the same cancelled context, and
	// reporting an operator's Ctrl-C as a timeout is a lie about who ended it.
	if end.ExitCode != 130 {
		t.Errorf("exit code = %d (error %q), want 130 for a killed session", end.ExitCode, end.Error)
	}
	if end.Error != "killed" {
		t.Errorf("terminal error = %q, want %q", end.Error, "killed")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("kill took %v; the session ran on rather than stopping", elapsed)
	}
}

// A kill must be idempotent. It used to be `close(sess.done)`, so a second
// stream_kill for one session panicked — and since handleStreamInput runs inline
// on the frame loop with no recover anywhere, a duplicate or replayed frame was
// enough to bring the agent process down.
func TestStreamKillIsIdempotent(t *testing.T) {
	if runtimeGOOS() == "windows" {
		t.Skip("no portable sleep binary on windows")
	}
	globalPolicy.install("")
	conn, peer := streamPipe(t)
	defer peer.Close()

	payload, _ := json.Marshal(protocol.StreamStart{Command: "sleep 5"})
	go handleStream(conn, protocol.Envelope{Type: "exec_stream", ReqID: "sess-twice", Payload: payload},
		make(chan struct{}, 1), nil)
	time.Sleep(400 * time.Millisecond)

	kill := protocol.Envelope{Type: "stream_kill", ReqID: "sess-twice", Payload: json.RawMessage("{}")}
	handleStreamInput(kill)
	// The second one is the test. If it panics, the process under test is gone.
	handleStreamInput(kill)
	handleStreamInput(kill)

	_, _, end := collectStream(t, peer)
	if end.ExitCode != 130 {
		t.Errorf("exit code = %d, want 130", end.ExitCode)
	}
}

// A stdin frame larger than the pipe buffer must not stall the frame loop. That
// loop dispatches every other frame too — another session's kill, an exec, a
// policy update — so blocking it on a command that is not reading stdin stops
// the whole agent, not just this session.
func TestStreamInputDoesNotBlockTheFrameLoop(t *testing.T) {
	if runtimeGOOS() == "windows" {
		t.Skip("no portable sleep binary on windows")
	}
	globalPolicy.install("")
	conn, peer := streamPipe(t)
	defer peer.Close()

	// A command that never reads stdin: its pipe buffer fills and stays full.
	payload, _ := json.Marshal(protocol.StreamStart{Command: "sleep 10"})
	go handleStream(conn, protocol.Envelope{Type: "exec_stream", ReqID: "sess-wedge", Payload: payload},
		make(chan struct{}, 1), nil)
	time.Sleep(400 * time.Millisecond)

	// Far more than one pipe buffer, and more than the queue holds: the excess
	// is dropped by design rather than queued or blocked on.
	in, _ := json.Marshal(protocol.StreamStdin{B64: stdBase64([]byte(strings.Repeat("x", 4<<20)))})
	done := make(chan struct{})
	go func() {
		handleStreamInput(protocol.Envelope{Type: "stream_stdin", ReqID: "sess-wedge", Payload: in})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleStreamInput blocked on a full pipe: the frame loop is stalled")
	}
}

// The positive control for the queue: stdin the command is waiting for must
// still arrive, and in order. A fix that dropped everything would pass the test
// above and be useless.
func TestStreamInputReachesTheCommand(t *testing.T) {
	if runtimeGOOS() == "windows" {
		t.Skip("no portable sh on windows")
	}
	globalPolicy.install("")
	conn, peer := streamPipe(t)

	payload, _ := json.Marshal(protocol.StreamStart{Command: "cat"})
	go handleStream(conn, protocol.Envelope{Type: "exec_stream", ReqID: "sess-cat", Payload: payload},
		make(chan struct{}, 1), nil)
	time.Sleep(400 * time.Millisecond)

	for _, line := range []string{"first\n", "second\n"} {
		in, _ := json.Marshal(protocol.StreamStdin{B64: stdBase64([]byte(line))})
		handleStreamInput(protocol.Envelope{Type: "stream_stdin", ReqID: "sess-cat", Payload: in})
	}
	// EOF is a queued item too, so it keeps its place after the bytes above.
	handleStreamInput(protocol.Envelope{Type: "stream_stdin", ReqID: "sess-cat",
		Payload: json.RawMessage(`{"eof":true}`)})

	stdout, _, end := collectStream(t, peer)
	if stdout != "first\nsecond\n" {
		t.Errorf("stdout = %q, want the two lines in order", stdout)
	}
	if end.ExitCode != 0 {
		t.Errorf("exit code = %d (error %q), want 0", end.ExitCode, end.Error)
	}
}

// A session that ends by itself must not leave a goroutine behind. One used to
// park on `<-sess.done` forever, and only a kill ever closed that channel — so a
// long-lived agent accumulated one leaked goroutine per console session it had
// ever served.
func TestStreamSessionLeavesNoGoroutine(t *testing.T) {
	if runtimeGOOS() == "windows" {
		t.Skip("no portable true binary on windows")
	}
	globalPolicy.install("")

	// Counted as a delta: earlier tests in this package may still be running a
	// session of their own, and what this test is about is what *its* sessions
	// leave behind.
	before := liveStreamGoroutines()

	conn, peer := streamPipe(t)
	for i := 0; i < 3; i++ {
		payload, _ := json.Marshal(protocol.StreamStart{Command: "true"})
		handleStream(conn, protocol.Envelope{Type: "exec_stream", ReqID: "sess-g", Payload: payload},
			make(chan struct{}, 1), nil)
		_, _, end := collectStream(t, peer)
		if end.ExitCode != 0 {
			t.Fatalf("session %d exited %d", i, end.ExitCode)
		}
	}
	peer.Close()

	// The session's writer goroutine is released by the deferred unregister, so
	// give it a moment to run rather than racing the count.
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := liveStreamGoroutines()
		if n <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d agent streaming goroutines parked after 3 completed sessions (was %d)", n, before)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// liveStreamGoroutines counts the agent's own streaming goroutines: one per
// session's output pumps, plus the one that drains its stdin queue.
func liveStreamGoroutines() int {
	buf := make([]byte, 1<<18)
	n := runtime.Stack(buf, true)
	count := 0
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "pumpSessionInput") || strings.Contains(g, "agent.handleStream") {
			count++
		}
	}
	return count
}
