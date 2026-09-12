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

	if reason := globalPolicy.Evaluate(start.Command, start.Argv); reason != "" {
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

	// Drain remaining pump output briefly (pipes close after Wait on
	// most platforms; give pumps a grace period to flush).
	timer := time.NewTimer(2 * time.Second)
drain:
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-timer.C:
			break drain
		}
	}
	timer.Stop()

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
	_ = stdinPipe
	_ = conn.WriteEnvelope(protocol.Envelope{
		Type: "stream_end", ReqID: env.ReqID,
		Payload: mustJSONStream(protocol.StreamEnd{ExitCode: exitCode, Error: errText}),
	})
}
