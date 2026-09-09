// Package agent implements the mach agent: enrollment (QR or API key), the
// outbound-only daemon connection, streaming command execution with output
// caps, and update push from the control plane.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/gorilla/websocket"
)

// Exec limits: no single command may produce more than this much output.
const (
	maxOutputBytes = 8 << 20 // 8 MiB per stream, then truncated with a marker
)

// cappedBuffer enforces a hard cap; the process keeps running but further
// output is discarded (and the tail is marked). Prevents OOM from
// `cat /dev/urandom` style commands.
type cappedBuffer struct {
	buf     bytes.Buffer
	max     int
	dropped bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		room := c.max - c.buf.Len()
		if room > 0 {
			c.buf.Write(p[:room])
		}
		c.dropped = true
		return len(p), nil // pretend success; runner adds the truncation marker
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) String() string {
	s := c.buf.String()
	if c.dropped {
		s += "\n[mach: output truncated at cap]"
	}
	return s
}

// Run is the daemon main loop: dial the control plane over an outbound
// connection, sign in (challenge-bound), execute commands, reconnect with
// exponential backoff on any failure. Nothing listens inbound.
func Run(stateDir string) error {
	DropPrivileges()
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
		if errors.Is(err, errRevoked) {
			// Control plane says this machine was revoked: retire quietly,
			// leaving a breadcrumb the operator can find in logs.
			log.Printf("agent: machine %q was revoked by the operator — retiring (state files kept for forensics)", cfg.Name)
			return nil
		}
		log.Printf("agent: disconnected: %v — reconnecting in %s", err, backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > 2*time.Minute {
			backoff = 2 * time.Minute
		}
		if err == errReset {
			backoff = 2 * time.Second
		}
	}
}

var (
	errReset    = errors.New("reset backoff")
	errShutdown = errors.New("shutdown")
	errRevoked  = errors.New("machine revoked")
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

	// Server initiates hello with a per-connection challenge (ReqID).
	env, err := conn.ReadEnvelope()
	if err != nil || env.Type != "hello" {
		if err == nil && env.Type == "revoked" {
			return errRevoked
		}
		return fmt.Errorf("expected hello, got %v/%v", env.Type, err)
	}
	challenge := env.ReqID
	if challenge == "" {
		return errors.New("server sent empty hello challenge")
	}
	sig := ed25519.Sign(id.Priv, []byte(helloMessage(cfg.Name, challenge)))
	hello := protocol.HelloRequest{
		Auth:      "v1 " + base64.StdEncoding.EncodeToString(sig),
		PubKey:    id.PubHex,
		Name:      cfg.Name,
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
		if msg == "revoked" {
			return errRevoked
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
		case "update":
			if err := handleUpdate(cfg, env); err != nil {
				log.Printf("agent: update failed: %v", err)
			}
		case "revoked":
			return errRevoked
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
	if reason := globalPolicy.Check(cmd.Command, cmd.Argv); reason != "" {
		replyExec(conn, env.ReqID, protocol.ExecResult{Error: reason, ExitCode: 126})
		return
	}
	timeout := time.Duration(cmd.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var c *exec.Cmd
	switch {
	case len(cmd.Argv) > 0:
		// No-shell mode: execve exactly these arguments; nothing parses,
		// splits, or re-quotes anything. Go's os/exec handles Windows
		// escaping per Win32 rules.
		c = exec.CommandContext(ctx, cmd.Argv[0], cmd.Argv[1:]...)
	default:
		// Shell mode: one parse by the OS-appropriate default shell.
		sh, err := resolveShell()
		if err != nil {
			replyExec(conn, env.ReqID, protocol.ExecResult{Error: err.Error(), ExitCode: 126})
			return
		}
		c = exec.CommandContext(ctx, sh.path, sh.args(cmd.Command)...)
	}
	var stdout, stderr cappedBuffer
	stdout.max = maxOutputBytes
	stderr.max = maxOutputBytes
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
			res.Error = runErr.Error()
			res.ExitCode = 127
		}
	}
	replyExec(conn, env.ReqID, res)
}

// handleUpdate verifies and applies a pushed update, then execs the new
// binary over this process. The manifest is signed by the pinned server
// key (sig over version|sha256), so a hijacked TLS layer or a rogue
// control plane cannot push arbitrary binaries to an enrolled agent.
func handleUpdate(cfg *Config, env protocol.Envelope) error {
	var upd protocol.UpdateCommand
	if err := json.Unmarshal(env.Payload, &upd); err != nil {
		return err
	}
	if cfg.ServerKey == "" {
		return errors.New("no pinned server key in config — refusing update")
	}
	if !ed25519.Verify(mustPub(cfg.ServerKey), []byte(upd.Version+"|"+upd.Sha256), mustSig(upd.SigB64)) {
		return errors.New("update signature verification failed — refusing")
	}
	var data []byte
	switch {
	case upd.DataB64 != "":
		d, err := base64.StdEncoding.DecodeString(upd.DataB64)
		if err != nil {
			return err
		}
		data = d
	case upd.URL != "":
		// Only ever fetched over https (or plain http when the pinned
		// control plane itself is http — dev deployments).
		if !strings.HasPrefix(upd.URL, "https://") {
			if !strings.HasPrefix(cfg.Server, "http://") || !strings.HasPrefix(upd.URL, "http://") {
				return errors.New("update URL must be https")
			}
		}
		d, err := fetchUpdate(upd.URL)
		if err != nil {
			return err
		}
		data = d
	default:
		return errors.New("update has neither url nor data")
	}
	if len(data) == 0 || len(data) > 256<<20 {
		return errors.New("update payload missing or too large")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), upd.Sha256) {
		return errors.New("update checksum mismatch — refusing")
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	// Atomic swap: write new binary next to self, rename over.
	tmp := self + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, self); err != nil {
		return err
	}
	log.Printf("agent: updated to %s — restarting", upd.Version)
	// Re-exec self, detached: the new process outlives this one and
	// reconnects (old connection dies). On unix we detach via Setsid.
	cmd := exec.Command(self, "run")
	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = detachSysProcAttr()
	}
	return cmd.Start()
}

func mustSig(b64 string) []byte {
	sig, _ := base64.StdEncoding.DecodeString(b64)
	return sig
}

func mustPub(hexKey string) ed25519.PublicKey {
	b, _ := hex.DecodeString(hexKey)
	if len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}

func helloMessage(name, nonce string) string { return name + "|" + nonce }

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

func replyExec(conn *protocol.WSConn, reqID string, res protocol.ExecResult) {
	payload, _ := json.Marshal(res)
	if err := conn.WriteEnvelope(protocol.Envelope{Type: "exec_result", ReqID: reqID, Payload: payload}); err != nil {
		log.Printf("agent: failed to send exec_result: %v", err)
	}
}

// fetchUpdate downloads an update payload, size-bounded.
func fetchUpdate(url string) ([]byte, error) {
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("update fetch: %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}