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
	"syscall"

	"github.com/bcross/mach/internal/protocol"
	"github.com/gorilla/websocket"
)

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
		return 3
	}
	defer ws.Close()

	start, _ := json.Marshal(protocol.StreamStart{Command: command})
	if err := ws.WriteMessage(websocket.TextMessage, mustJSON(protocol.Envelope{
		Type:    "exec_stream",
		ReqID:   "console",
		Payload: start,
	})); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}

	// Ctrl-C: tell the agent to kill the session.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		_ = ws.WriteMessage(websocket.TextMessage, mustJSON(protocol.Envelope{
			Type:    "stream_kill",
			ReqID:   "console",
			Payload: json.RawMessage("{}"),
		}))
	}()

	exit := 0
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			// Connection closed by server after stream_end (or error).
			break
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
				os.Stderr.Write(b)
			} else {
				os.Stdout.Write(b)
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
	return exit
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