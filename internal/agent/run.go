package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/gorilla/websocket"
)

// Run is the daemon main loop: dial the control plane over an outbound
// connection, sign in, execute commands as they arrive, and reconnect with
// exponential backoff on any failure. Nothing listens inbound.
func Run(stateDir string) error {
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return err
	}
	id, err := LoadOrCreate(stateDir)
	if err != nil {
		return err
	}

	backoff := 2 * time.Second
	for {
		err := dialAndServe(cfg, id)
		if errors.Is(err, errShutdown) {
			return nil
		}
		log.Printf("agent: disconnected: %v — reconnecting in %s", err, backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > 2*time.Minute {
			backoff = 2 * time.Minute
		}
		// Successful sessions reset the backoff inside dialAndServe via errReset.
		if err == errReset {
			backoff = 2 * time.Second
		}
	}
}

var (
	errReset    = errors.New("reset backoff")
	errShutdown = errors.New("shutdown")
)

func dialAndServe(cfg *Config, id *Identity) error {
	url := wsURL(cfg.Server) + "/v1/agent/ws?name=" + cfg.Name
	ws, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial %s: %s", url, resp.Status)
		}
		return fmt.Errorf("dial %s: %w", url, err)
	}
	defer ws.Close()
	conn := protocol.NewWSConn(ws)

	// Server initiates hello; respond with a signed hello.
	env, err := conn.ReadEnvelope()
	if err != nil || env.Type != "hello" {
		return fmt.Errorf("expected hello, got %v/%v", env.Type, err)
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	sig := ed25519.Sign(id.Priv, []byte(helloMessage(cfg.Name, ts)))
	hello := protocol.HelloRequest{
		Auth:      "v1 " + base64.StdEncoding.EncodeToString(sig),
		PubKey:    id.PubHex,
		Name:      cfg.Name,
		Timestamp: ts,
		AgentVer:  Version,
		Hostname:  hostname(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
	payload, _ := json.Marshal(hello)
	if err := conn.WriteEnvelope(protocol.Envelope{Type: "hello", Payload: payload}); err != nil {
		return err
	}
	env, err = conn.ReadEnvelope()
	if err != nil {
		return err
	}
	var hr protocol.HelloResponse
	if err := json.Unmarshal(env.Payload, &hr); err != nil || !hr.OK {
		msg := "rejected"
		if err == nil {
			msg = hr.Error
		}
		return fmt.Errorf("server rejected hello: %s", msg)
	}
	log.Printf("agent: connected to %s as %q", cfg.Server, cfg.Name)

	// Keepalive pinger.
	pingCtx, cancelPings := context.WithCancel(context.Background())
	defer cancelPings()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-pingCtx.Done():
				return
			case <-t.C:
				_ = conn.Ping()
			}
		}
	}()

	// Command loop.
	for {
		_ = ws.SetReadDeadline(time.Time{}) // block until frame or drop
		env, err := conn.ReadEnvelope()
		if err != nil {
			return errReset // clean disconnect → reconnect fast
		}
		switch env.Type {
		case "exec":
			go handleExec(conn, env)
		case "pong":
			// ignore
		default:
			log.Printf("agent: ignoring frame %q", env.Type)
		}
	}
}

func handleExec(conn *protocol.WSConn, env protocol.Envelope) {
	var cmd protocol.ExecCommand
	if err := json.Unmarshal(env.Payload, &cmd); err != nil {
		replyExec(conn, env.ReqID, protocol.ExecResult{Error: "bad exec payload"})
		return
	}
	timeout := time.Duration(cmd.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c := exec.CommandContext(ctx, "sh", "-c", cmd.Command)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	runErr := c.Run()

	res := protocol.ExecResult{Stdout: stdout.String(), Stderr: stderr.String()}
	switch {
	case runErr == nil:
		res.ExitCode = 0
	case ctx.Err() != nil:
		res.Error = fmt.Sprintf("timed out after %s", timeout)
		res.ExitCode = -1
	default:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			res.ExitCode = ee.ExitCode()
		} else {
			res.Error = runErr.Error() // e.g. sh not found
			res.ExitCode = 127
		}
	}
	replyExec(conn, env.ReqID, res)
}

func replyExec(conn *protocol.WSConn, reqID string, res protocol.ExecResult) {
	payload, _ := json.Marshal(res)
	if err := conn.WriteEnvelope(protocol.Envelope{Type: "exec_result", ReqID: reqID, Payload: payload}); err != nil {
		log.Printf("agent: failed to send exec_result: %v", err)
	}
}

func helloMessage(name, timestamp string) string { return name + "|" + timestamp }

func wsURL(server string) string {
	s := server
	if len(s) > 7 && s[:7] == "http://" {
		return "ws://" + s[7:]
	}
	if len(s) > 8 && s[:8] == "https://" {
		return "wss://" + s[8:]
	}
	return "wss://" + s
}