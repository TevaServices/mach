// Package agent implements the mach agent: enrollment (QR or API key), the
// outbound-only daemon connection, streaming command execution with output
// caps, and update push from the control plane.
package agent

import (
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
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/gorilla/websocket"
)

// Run is the daemon main loop: dial the control plane over an outbound
// connection, sign in (challenge-bound), execute commands, reconnect with
// exponential backoff on any failure. Nothing listens inbound.
//
// Privilege drop happens AFTER the state files are read: a root-installed
// service (no User= in the unit) would otherwise drop to an unprivileged
// user that cannot read its own config and crash-loop forever.
func Run(stateDir string) error {
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return err
	}
	id, err := LoadOrCreate(stateDir)
	if err != nil {
		return err
	}
	DropPrivileges()

	backoff := 2 * time.Second
	for {
		iterStart := time.Now()
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
		// %q: the error can embed text the control plane supplied, and a newline in
		// it must not be able to forge an agent log line.
		log.Printf("agent: disconnected: %q — reconnecting in %s", err.Error(), backoff)
		// Reset the backoff only after a genuinely long-lived session; a
		// fast-failing error (bad frame, rejected hello) must not hard-reset
		// the loop to 2s forever.
		if time.Since(iterStart) > 2*time.Minute {
			backoff = 2 * time.Second
		}
		// Jitter ±25% so a fleet restart doesn't reconnect in lockstep.
		jittered := backoff - backoff/4 + time.Duration(mrand.Int63n(int64(backoff/2)+1))
		time.Sleep(jittered)
		backoff *= 2
		if backoff > 2*time.Minute {
			backoff = 2 * time.Minute
		}
	}
}

var (
	errShutdown = errors.New("shutdown")
	errRevoked  = errors.New("machine revoked")
)

func dialAndServe(cfg *Config, id *Identity) error {
	url := wsURL(cfg.Server) + "/v1/agent/ws?name=" + urlQueryEscape(cfg.Name)
	ws, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		if resp != nil {
			resp.Body.Close() // gorilla hands back the response on non-101
			return fmt.Errorf("dial %s: %s", url, resp.Status)
		}
		return fmt.Errorf("dial %s: %w", url, err)
	}
	defer ws.Close()
	conn := protocol.NewWSConn(ws)

	// Keepalive: the pinger sends pings; the pong handler (and any data
	// frame) refreshes the read deadline. A dead server fails the read
	// within pongWait; a server that stops answering pongs is detected the
	// same way. Every write carries its own deadline (protocol.WSConn).
	const pongWait = 90 * time.Second
	conn.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

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
		Auth:     "v1 " + base64.StdEncoding.EncodeToString(sig),
		PubKey:   id.PubHex,
		Name:     cfg.Name,
		AgentVer: Version,
		Hostname: hostname(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
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
	// Mutual authentication: the server signs the challenge with the key
	// this machine pinned at enrollment. TLS alone does not prove server
	// identity — the pin does.
	if cfg.ServerKey == "" {
		log.Printf("agent: WARNING: no server key pinned — skipping control-plane identity verification (re-enroll to pin it)")
	} else {
		pub, ok := parsePubKey(cfg.ServerKey)
		if !ok {
			return errors.New("corrupt server_key in config — refusing to connect without a valid pin; re-enroll")
		}
		serverSig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hr.ServerAuth, "v1 "))
		if err != nil || !ed25519.Verify(pub, []byte("server|"+challenge), serverSig) {
			return fmt.Errorf("control plane identity verification FAILED (missing or bad server signature) — refusing connection")
		}
	}
	log.Printf("agent: connected to %s as %q (control plane identity verified)", cfg.Server, cfg.Name)

	// Keepalive pinger: sends pings; pong (or any data frame) refreshes the
	// read deadline, so a black-holed connection tears down within pongWait.
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

	// Concurrency cap on command execution: a buggy or hijacked control
	// plane must not be able to spawn unbounded processes on this machine.
	execSem := make(chan struct{}, maxConcurrentExec)

	// Command loop.
	for {
		_ = ws.SetReadDeadline(time.Now().Add(pongWait))
		env, err := conn.ReadEnvelope()
		if err != nil {
			return err // deadline, clean disconnect, or protocol error
		}
		switch env.Type {
		case "exec":
			go handleExec(conn, env, execSem)
		case "update":
			if err := handleUpdate(cfg, env); err != nil {
				log.Printf("agent: update failed: %v", err)
			}
		case "revoked":
			return errRevoked
		case "pong":
			// keepalive ack; the pong handler already refreshed deadlines
		default:
			log.Printf("agent: ignoring frame %q", env.Type)
		}
	}
}

// maxConcurrentExec bounds simultaneously running remote commands.
const maxConcurrentExec = 8

func handleExec(conn *protocol.WSConn, env protocol.Envelope, sem chan struct{}) {
	var cmd protocol.ExecCommand
	if err := json.Unmarshal(env.Payload, &cmd); err != nil {
		replyExec(conn, env.ReqID, protocol.ExecResult{Error: "bad exec payload"})
		return
	}
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-time.After(10 * time.Second):
		replyExec(conn, env.ReqID, protocol.ExecResult{Error: "too many concurrent commands on this machine", ExitCode: 126})
		return
	}
	if reason := globalPolicy.Evaluate(cmd.Command, cmd.Argv); reason != "" {
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
	// Output is streamed to the control plane as it is produced; see
	// stream.go for the chunking and per-stream cap.
	//
	// What the command prints is data and stays data: it is copied to the
	// control plane and nowhere else. Nothing in this function — and nothing
	// in the agent — reads output back to decide what to run next. The only
	// things the agent acts on are frames from the control plane, and a frame
	// is only accepted after the pinned-key check in dialAndServe. A command
	// whose output mimics a protocol frame, a mach message, or a new command
	// is a command that printed text.
	stdout := newChunkWriter(conn, env.ReqID, "stdout")
	stderr := newChunkWriter(conn, env.ReqID, "stderr")
	c.Stdout = stdout
	c.Stderr = stderr
	// Stdout/stderr are writers (not files), so os/exec copies through a
	// pipe: if a command backgrounds a grandchild that inherits the pipe,
	// the copy goroutine outlives the direct child. WaitDelay bounds that
	// wait — without it, `sleep 3600 &` style commands hang Wait() forever
	// past the timeout, leaking the goroutine and losing the result.
	c.WaitDelay = 10 * time.Second
	// Do not leak the agent's own environment (MACH_USER, MACH_POLICY, ...)
	// into every command the control plane runs.
	c.Env = filteredEnv()

	// Flush ticks so the last of a trickle of output is not held until the
	// command exits. Stopped and drained before the writers are closed, so no
	// chunk can be sent after the terminal exec_result.
	flushDone := make(chan struct{})
	flusherStopped := make(chan struct{})
	go func() {
		defer close(flusherStopped)
		t := time.NewTicker(chunkFlushInterval)
		defer t.Stop()
		for {
			select {
			case <-flushDone:
				return
			case <-t.C:
				stdout.Flush()
				stderr.Flush()
			}
		}
	}()

	runErr := c.Run()
	close(flushDone)
	<-flusherStopped
	stdout.Close()
	stderr.Close()

	res := protocol.ExecResult{}
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
	pub, ok := parsePubKey(cfg.ServerKey)
	if !ok {
		// A wrong-length key would make ed25519.Verify panic; refuse instead.
		return errors.New("corrupt server_key in config (not a 32-byte hex key) — refusing update")
	}
	if !ed25519.Verify(pub, []byte(upd.Version+"|"+upd.Sha256), mustSig(upd.SigB64)) {
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
	// Atomic swap: write new binary next to self, rename over. Windows
	// cannot rename over a running executable image, so move self aside
	// first (the .old copy is replaced on the next update).
	tmp := self + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, self); err != nil {
		old := self + ".old"
		_ = os.Remove(old)
		if err2 := os.Rename(self, old); err2 != nil {
			return fmt.Errorf("replacing binary %s: %v (initial rename: %v)", self, err2, err)
		}
		if err3 := os.Rename(tmp, self); err3 != nil {
			return err3
		}
	}
	log.Printf("agent: updated to %s — restarting", upd.Version)
	// Re-exec self, detached: the new process outlives this one and
	// reconnects (old connection dies). On unix we detach via Setsid.
	cmd := exec.Command(self, "run")
	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = detachSysProcAttr()
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// This process must NOT re-enter the reconnect loop: two live agents
	// with one identity would fight over the broker connection forever.
	// errShutdown stops Run() and lets the new process take over.
	return errShutdown
}

func mustSig(b64 string) []byte {
	sig, _ := base64.StdEncoding.DecodeString(b64)
	return sig
}

// parsePubKey hex-decodes an ed25519 public key, rejecting wrong-length
// input (ed25519.Verify panics on anything that is not 32 bytes).
func parsePubKey(hexKey string) (ed25519.PublicKey, bool) {
	b, err := hex.DecodeString(hexKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(b), true
}

// filteredEnv strips this agent's own MACH_* control variables from the
// environment every executed command inherits.
func filteredEnv() []string {
	out := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "MACH_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
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
