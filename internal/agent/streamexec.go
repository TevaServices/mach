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
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
)

// handleStream runs a streaming exec session (server already verified auth
// and routed the frame by session ID). Streaming is plaintext by design:
// it serves the interactive console; one-shot exec is the E2E-able path.
func handleStream(conn *protocol.WSConn, env protocol.Envelope, sem chan struct{}, ctl *sessionCtl) {
	var start protocol.StreamStart
	if err := json.Unmarshal(env.Payload, &start); err != nil {
		_ = conn.WriteEnvelope(protocol.Envelope{
			Type: "stream_end", ReqID: env.ReqID,
			Payload: mustJSONStream(protocol.StreamEnd{ExitCode: 126, Error: "bad stream payload"}),
		})
		return
	}

	// One place that ends a session, so the console trace and the terminal frame
	// cannot disagree about how it ended — every early refusal below goes through
	// it too, and a temporary session's operator sees a refused command rather
	// than silence followed by nothing.
	end := func(e protocol.StreamEnd) {
		ctl.announce("console: exit %d", e.ExitCode)
		_ = conn.WriteEnvelope(protocol.Envelope{
			Type: "stream_end", ReqID: env.ReqID, Payload: mustJSONStream(e),
		})
	}

	// Secrets: the output scrubber is built from one store read before
	// anything runs, and fails closed — a store that exists but cannot be
	// read refuses the session rather than sending unscrubbed bytes.
	store := activeSecrets()
	scrub, scrRefusal := commandScrubber(store)
	if scrRefusal != "" {
		end(protocol.StreamEnd{ExitCode: 126, Error: scrRefusal})
		return
	}
	ctl.announce("console: %q", scrub.ScrubText(describeCommandText(start.Command, start.Argv)))

	if reason := checkCommand(protocol.ExecCommand{Command: start.Command, Argv: start.Argv, FleetApproved: start.FleetApproved}); reason != "" {
		end(protocol.StreamEnd{ExitCode: 126, Error: reason})
		return
	}

	// Injected secrets resolve here, before anything starts: a name the
	// store cannot supply refuses the session (126, audited as a refusal,
	// naming the missing NAME and never a value) and re-announces — the
	// store may have changed since the last announce.
	envPairs, injRefusal := resolveInjection(store, start.InjectEnv)
	if injRefusal != "" {
		announceSecrets(conn, store)
		end(protocol.StreamEnd{ExitCode: 126, Error: injRefusal})
		return
	}

	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-time.After(10 * time.Second):
		end(protocol.StreamEnd{ExitCode: 126, Error: "too many concurrent commands on this machine"})
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
			end(protocol.StreamEnd{ExitCode: 126, Error: err.Error()})
			return
		}
		c = exec.CommandContext(ctx, sh.path, sh.args(start.Command)...)
	}
	applyConfinement(c)
	// Injected secrets are appended after the agent's own environment is
	// filtered out, and win over anything already set.
	c.Env = appendEnvValues(filteredEnv(), envPairs)
	stdinPipe, _ := c.StdinPipe()
	// Output pipes are ours, not os/exec's: StdoutPipe/StderrPipe hand the read
	// end back with the promise that Wait closes it, which is exactly the loss
	// this session used to suffer. The command can exit between the last stdin
	// byte and the pump's next Read; Wait then closed the read end out from
	// under the pump, Read failed, and the bytes the command had already put in
	// the pipe buffer were dropped — silently, because the pump's write errors
	// are deliberate (an unbounded stream may outlive its reader) while its
	// read errors were treated as EOF. An owned pipe pair closes the write end
	// only after Wait returns, so every pump sees EOF only after the buffer is
	// drained, whatever the scheduling.
	stdoutR, stdoutW, perr := os.Pipe()
	stderrR, stderrW, perr2 := os.Pipe()
	if perr != nil || perr2 != nil {
		if perr == nil {
			stdoutR.Close()
			stdoutW.Close()
		}
		if perr2 == nil {
			stderrR.Close()
			stderrW.Close()
		}
		end(protocol.StreamEnd{ExitCode: 126, Error: "output pipes: " + firstErr(perr, perr2).Error()})
		return
	}
	defer stdoutW.Close()
	defer stderrW.Close()
	defer stdoutR.Close()
	defer stderrR.Close()
	c.Stdout = stdoutW
	c.Stderr = stderrW
	if err := c.Start(); err != nil {
		end(protocol.StreamEnd{ExitCode: 126, Error: err.Error()})
		return
	}
	// kill stops this session's command. It is idempotent — once() is not
	// decoration: `close(sess.done)` used to be the whole of it, so a second
	// stream_kill frame for one session panicked with "close of closed channel".
	// Nothing recovers a panic in the frame loop, so the agent process died, and
	// a duplicate (or replayed) frame was enough to do it.
	var killed atomic.Bool
	var killOnce sync.Once
	kill := func() {
		killOnce.Do(func() {
			killed.Store(true)
			// Both halves, in this order. Closing stdin is what lets a command
			// that reads it see EOF; the group signal is what stops one that does
			// not, which closing stdin never did.
			_ = stdinPipe.Close()
			killProcessTree(c)
			// CommandContext's own kill covers the platforms where
			// killProcessTree is a no-op (windows), and makes Wait return.
			cancel()
		})
	}
	// Route stdin/kill frames to this session until it ends. Writes happen on
	// this goroutine, never on the frame loop that feeds the queue — see
	// handleStreamInput.
	input, unregister := registerLiveSession(env.ReqID, stdinPipe, kill)
	defer unregister()
	go pumpSessionInput(input, stdinPipe)

	// Output pumps: chunk → stream_out frames.
	done := make(chan struct{}, 2)
	pump := func(r io.Reader, stream string) {
		buf := make([]byte, streamOutChunkSize)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				// Scrubbed before it is encoded, so the value cannot hide
				// in the base64 form the frame carries. Best-effort: a
				// value split across two chunks is not caught (each chunk
				// is scrubbed independently) — see secrets.go.
				out := scrub.Scrub(buf[:n])
				_ = conn.WriteEnvelope(protocol.Envelope{
					Type:    "stream_out",
					ReqID:   env.ReqID,
					Payload: mustJSONStream(protocol.StreamOut{Stream: stream, B64: stdBase64(out)}),
				})
			}
			if rerr != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pump(stdoutR, "stdout")
	go pump(stderrR, "stderr")

	runErr := c.Wait()

	// The command is gone; close OUR write ends so each pump's next Read is
	// EOF once the pipe buffer is drained. All read ends stay open here — the
	// pipes are ours, and Wait has nothing left to close out from under the
	// pumps.
	//
	// The grace is per pump, not one budget shared between them: the console
	// stops reading at the terminal record, so whatever is still in flight when
	// that record is written is output nobody will ever see, and a shared timer
	// lets one pump's slow flush consume the time the other pump needed. A pump
	// that is still not at EOF after the write ends are closed means something
	// else holds a write end open (a grandchild that inherited it), which is why
	// the wait is bounded at all — closed read ends unblock those pumps, and the
	// record says the output may be cut short instead of presenting a truncated
	// stream as the whole of it.
	stdoutW.Close()
	stderrW.Close()
	cut := false
	for _, r := range []*os.File{stdoutR, stderrR} {
		select {
		case <-done:
		case <-time.After(streamDrainGrace):
			cut = true
			r.Close() // unblock the parked pump; its exit drains to `done`
		}
	}

	exitCode := 0
	errText := ""
	switch {
	case runErr == nil:
	case killed.Load():
		// Deliberately killed rather than timed out: the two produce the same
		// runErr (the context was cancelled), and reporting an operator's Ctrl-C
		// as "timed out" would be a lie about who ended the session. 130 is the
		// exit status a shell reports for Ctrl-C.
		exitCode = 130
		errText = "killed"
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
	errText = scrub.ScrubText(withDrainNote(errText, cut))
	_ = stdinPipe
	end(protocol.StreamEnd{ExitCode: exitCode, Error: errText})
}

// firstErr is the non-nil of two errors, for a message naming which pipe failed.
func firstErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
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
