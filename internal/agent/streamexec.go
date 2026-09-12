package agent

// Agent side of the streaming console: on "exec_stream" frames the agent
// runs the command with live pipes and pushes stream_out chunks onto the
// connection as they arrive, finishing with stream_end.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/bcross/mach/internal/protocol"
)

// handleStream runs a streaming exec session (server already verified auth
// and routed the frame by session ID). Streaming is plaintext by design:
// it serves the interactive console; one-shot exec is the E2E-able path.
func handleStream(conn *protocol.WSConn, env protocol.Envelope, sem chan struct{}, stateDir string) {
	var start protocol.StreamStart
	if err := json.Unmarshal(env.Payload, &start); err != nil {
		_ = conn.WriteEnvelope(protocol.Envelope{
			Type: "stream_end", ReqID: env.ReqID,
			Payload: mustJSONStream(protocol.StreamEnd{ExitCode: 126, Error: "bad stream payload"}),
		})
		return
	}

	if reason := checkCommand(start.Command, start.Argv); reason != "" {
		_ = conn.WriteEnvelope(protocol.Envelope{
			Type: "stream_end", ReqID: env.ReqID,
			Payload: mustJSONStream(protocol.StreamEnd{ExitCode: 126, Error: reason}),
		})
		return
	}

	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-time.After(10 * time.Second):
		_ = conn.WriteEnvelope(protocol.Envelope{
			Type: "stream_end", ReqID: env.ReqID,
			Payload: mustJSONStream(protocol.StreamEnd{ExitCode: 126, Error: "too many concurrent commands on this machine"}),
		})
		return
	}

	timeout := 15 * time.Minute // interactive sessions run long
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var c *exec.Cmd
	switch {
	case len(start.Argv) > 0:
		c = exec.CommandContext(ctx, start.Argv[0], start.Argv[1:]...)
	default:
		sh, err := resolveShell()
		if err != nil {
			_ = conn.WriteEnvelope(protocol.Envelope{
				Type: "stream_end", ReqID: env.ReqID,
				Payload: mustJSONStream(protocol.StreamEnd{ExitCode: 126, Error: err.Error()}),
			})
			return
		}
		c = exec.CommandContext(ctx, sh.path, sh.args(start.Command)...)
	}
	applyConfinement(c)
	c.Env = filteredEnv()
	stdinPipe, _ := c.StdinPipe()
	stdoutPipe, _ := c.StdoutPipe()
	stderrPipe, _ := c.StderrPipe()
	if err := c.Start(); err != nil {
		_ = conn.WriteEnvelope(protocol.Envelope{
			Type: "stream_end", ReqID: env.ReqID,
			Payload: mustJSONStream(protocol.StreamEnd{ExitCode: 126, Error: err.Error()}),
		})
		return
	}
	// Route stdin/kill frames to this session until it ends.
	unregister := registerLiveSession(env.ReqID, stdinPipe)
	defer unregister()
	// Close stdin when the session is killed remotely.
	go func() {
		sessionMu.Lock()
		sess := liveSessions[env.ReqID]
		sessionMu.Unlock()
		if sess == nil {
			return
		}
		<-sess.done
		_ = stdinPipe.Close()
	}()

	// Output pumps: chunk → stream_out frames.
	done := make(chan struct{}, 2)
	pump := func(r io.Reader, stream string) {
		buf := make([]byte, streamOutChunkSize)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				_ = conn.WriteEnvelope(protocol.Envelope{
					Type:    "stream_out",
					ReqID:   env.ReqID,
					Payload: mustJSONStream(protocol.StreamOut{Stream: stream, B64: stdBase64(buf[:n])}),
				})
			}
			if rerr != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pump(stdoutPipe, "stdout")
	go pump(stderrPipe, "stderr")

	runErr := c.Wait()

	// Drain remaining pump output briefly (pipes close after Wait on most
	// platforms; give the pumps a grace period to flush).
	//
	// The grace is per pump, not one budget shared between them: the console
	// stops reading at the terminal record, so whatever is still in flight when
	// that record is written is output nobody will ever see, and a shared timer
	// lets one pump's slow flush consume the time the other pump needed. A pump
	// that is still not at EOF after the process is gone means something else
	// holds the pipe open (a grandchild that inherited it), which is why the
	// wait is bounded at all — and why the record says the output may be cut
	// short instead of presenting a truncated stream as the whole of it.
	cut := false
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(streamDrainGrace):
			cut = true
		}
	}

	exitCode := 0
	errText := ""
	switch {
	case runErr == nil:
	case ctx.Err() != nil:
		exitCode = -1
		errText = "timed out"
	default:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 127
			errText = fmt.Sprintf("%v", runErr)
		}
	}
	errText = withDrainNote(errText, cut)
	_ = stdinPipe
	_ = conn.WriteEnvelope(protocol.Envelope{
		Type: "stream_end", ReqID: env.ReqID,
		Payload: mustJSONStream(protocol.StreamEnd{ExitCode: exitCode, Error: errText}),
	})
}

// streamDrainGrace bounds how long the terminal record waits for the output pumps
// after the process has exited.
const streamDrainGrace = 2 * time.Second

// withDrainNote reports output that may have been cut short. It is a separate
// function (and a separate sentence) from the exit-status error because it is not
// a failure of the command: the command finished, and its last bytes may simply
// not have made it, which a reader needs to know to avoid reading a truncated
// stream as the whole of it.
func withDrainNote(errText string, cut bool) string {
	if !cut {
		return errText
	}
	const note = "output may be incomplete: a process still holds the output pipe"
	if errText == "" {
		return note
	}
	return errText + "; " + note
}
