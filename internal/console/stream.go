package console

// Streaming console client: `mach console <machine>` opens the
// /v1/console/stream WebSocket, sends exec_stream, and streams output
// live. Line-based remote reading remains for scripts;
// this path gives humans/agents live output.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
	"github.com/gorilla/websocket"
)

// Outcomes of a streaming attempt that are not the command's own exit status.
// The distinction matters to the caller: reconnecting to a relay that was never
// reached is a retry, while re-running a command whose stream died mid-flight
// would execute it a second time on the machine.
const (
	streamDialFailed = 3 // the endpoint could not be reached at all
	streamLost       = 4 // the stream started, then ended without an exit status
)

// killGrace bounds how long the console waits for the terminal record after a
// kill. A killed process goes at once, so reaching this means the machine is not
// honouring the kill — an agent older than the frame's meaning — and waiting
// longer would just be a console with no way out.
const killGrace = 15 * time.Second

// streamConsole connects to the streaming endpoint and runs one command,
// printing output as it arrives. Returns the remote exit code.
func streamConsole(server, apiKey, machine, command string) int {
	url := wsURLFrom(server) + "/v1/console/stream?machine=" + url.QueryEscape(machine)
	h := http.Header{}
	h.Set("Authorization", "Bearer "+apiKey)
	ws, resp, err := websocket.DefaultDialer.Dial(url, h)
	if err != nil {
		if resp != nil {
			fmt.Fprintln(os.Stderr, "mach: stream dial: "+resp.Status)
		} else {
			fmt.Fprintln(os.Stderr, "mach: stream dial: "+err.Error())
		}
		return streamDialFailed
	}
	defer ws.Close()

	start, _ := json.Marshal(protocol.StreamStart{Command: command})
	if err := ws.WriteMessage(websocket.TextMessage, mustJSON(protocol.Envelope{
		Type:    "exec_stream",
		ReqID:   "console",
		Payload: start,
	})); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return streamDialFailed
	}

	// Two signals, two meanings, and conflating them broke both.
	//
	// SIGINT is the operator pressing Ctrl-C at a terminal: it belongs to the
	// remote command while one runs, because the banner promises a kill and this
	// is what delivers it. InterruptGuard stands down for the window the flag
	// below is set, so the signal lands here instead of exiting the process
	// before the kill frame is written.
	//
	// SIGTERM is somebody else deciding this process should go — a supervisor, a
	// `kill` from another shell — and means exactly that. Reading it as a request
	// to kill a command on a remote machine meant a service manager could not
	// stop an interactive console.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	defer signal.Stop(term)
	go func() {
		<-term
		os.Exit(143) // 128+15, what a shell reports for SIGTERM
	}()

	streamOwnsInterrupt.Store(true)
	defer streamOwnsInterrupt.Store(false)
	// killed records that a kill was asked for, so a stream that ends without a
	// terminal record can say which of the two things happened.
	//
	// A second Ctrl-C gives up waiting and disconnects — the honest answer for an
	// agent too old to honour a kill — and so does the grace deadline armed with
	// the kill, so an unattended console cannot wait on one forever.
	var killed atomic.Bool
	go func() {
		first := true
		for range sig {
			if !first {
				fmt.Fprintln(os.Stderr, "\nmach: disconnecting; the command may still be running on "+machine)
				os.Exit(130)
			}
			first = false
			killed.Store(true)
			fmt.Fprintln(os.Stderr, "\nmach: kill sent — press Ctrl-C again to disconnect without waiting")
			_ = ws.WriteMessage(websocket.TextMessage, mustJSON(protocol.Envelope{
				Type:    "stream_kill",
				ReqID:   "console",
				Payload: json.RawMessage("{}"),
			}))
			// Bound the wait for the terminal record. It has to be a read
			// deadline rather than a timer in this loop: a killed command is
			// usually a silent one, so the loop sits in ReadMessage and a timer
			// beside it would never fire.
			_ = ws.SetReadDeadline(time.Now().Add(killGrace))
		}
	}()

	exit := 0
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			// The relay went away without a terminal record. That is not
			// success: the command may still be running on the machine, and its
			// output was cut off. Reporting 0 here would make a broken relay
			// look like a command that ran cleanly.
			if killed.Load() {
				fmt.Fprintln(os.Stderr,
					"\nmach: the remote command did not stop after the kill — it may still be running on "+machine)
				return streamLost
			}
			fmt.Fprintln(os.Stderr,
				"mach: the stream ended without an exit status — the command may still be running on "+machine)
			return streamLost
		}
		var env protocol.Envelope
		if json.Unmarshal(raw, &env) != nil {
			continue
		}
		switch env.Type {
		case "stream_out":
			var out protocol.StreamOut
			if json.Unmarshal(env.Payload, &out) != nil {
				continue
			}
			b, derr := base64.StdEncoding.DecodeString(out.B64)
			if derr != nil {
				continue
			}
			if out.Stream == "stderr" {
				os.Stderr.Write(safeForTerminal(b, os.Stderr))
			} else {
				os.Stdout.Write(safeForTerminal(b, os.Stdout))
			}
		case "stream_end":
			var end protocol.StreamEnd
			if json.Unmarshal(env.Payload, &end) == nil {
				if end.Error != "" {
					fmt.Fprintln(os.Stderr, "mach: "+end.Error)
				}
				exit = end.ExitCode
			}
			return exit
		}
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// wsURLFrom converts an http(s) base URL to a ws(s) URL.
func wsURLFrom(server string) string {
	s := strings.TrimRight(server, "/")
	if strings.HasPrefix(s, "https://") {
		return "wss://" + strings.TrimPrefix(s, "https://")
	}
	if strings.HasPrefix(s, "http://") {
		return "ws://" + strings.TrimPrefix(s, "http://")
	}
	return "wss://" + s
}
