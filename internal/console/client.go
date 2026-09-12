// Package console is the mach CLI client: it dials the control plane's
// console API with a bearer API key. This is the interface the Hermes
// troubleshooter (and humans) drive the fleet through.
package console

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bcross/mach/internal/protocol"
)

// Config is the console client's local config (~/.mach/console.json).
type Config struct {
	Server string `json:"server"`
	APIKey string `json:"api_key"`
}

// StateDirDefault is where console config lives (same state dir as the agent).
func StateDirDefault() string {
	if v := os.Getenv("MACH_STATE_DIR"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".mach"
	}
	return filepath.Join(home, ".mach")
}

func LoadConfig() (*Config, error) {
	dir := StateDirDefault()
	path := filepath.Join(dir, "console.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errNotConfigured{dir: dir}
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.Server == "" || c.APIKey == "" {
		return nil, fmt.Errorf("console.json needs \"server\" and \"api_key\"")
	}
	// A config holding a bearer key must never be group/world-readable
	// (e.g. restored from an archive with different perms).
	if st, serr := os.Stat(path); serr == nil && st.Mode().Perm() != 0o600 {
		fmt.Fprintf(os.Stderr, "mach: warning: %s had permissions %v; tightening to 0600\n", path, st.Mode().Perm())
		_ = os.Chmod(path, 0o600)
	}
	return &c, nil
}

type errNotConfigured struct{ dir string }

// NotConfiguredError is returned when no console config exists yet.
type NotConfiguredError = errNotConfigured

func (e errNotConfigured) Error() string {
	return "not configured yet — run plain `mach` for one-time setup (or create " + e.dir + "/console.json)"
}

// DefaultClient builds a client from the saved console config.
func DefaultClient() (*client, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	return New(cfg), nil
}

type client struct {
	cfg  *Config
	http *http.Client
}

func New(cfg *Config) *client {
	return &client{cfg: cfg, http: &http.Client{Timeout: 12 * time.Minute}}
}

func (c *client) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.Server, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	const maxResp = 8 << 20
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResp))
	if len(data) == maxResp {
		// Failing open here would surface as a confusing JSON unmarshal
		// error; say what actually happened.
		return fmt.Errorf("server response exceeded %d MiB", maxResp>>20)
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

type MachineInfo struct {
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Online    bool   `json:"online"`
	AgentVer  string `json:"agent_version"`
	CreatedAt string `json:"created_at"`
}

type auditEntry struct {
	TS       string `json:"ts"`
	Machine  string `json:"machine"`
	Command  string `json:"command"`
	Source   string `json:"source"`
	ExitCode *int64 `json:"exit_code"`
}

func (c *client) Machines() ([]MachineInfo, error) {
	var resp struct {
		Machines []MachineInfo `json:"machines"`
	}
	err := c.do("GET", "/v1/machines", nil, &resp)
	return resp.Machines, err
}

// runExec is the shared one-shot path; exactly one of command/argv is set.
//
// The response is streamed, not buffered: the control plane relays the
// command's output as the agent produces it, so output appears live and a
// long-running command is watchable. The stream ends with an exit record.
//
// When asJSON is set, the frames are re-emitted on stdout verbatim instead of
// being decoded into this process's output streams. See Exec for why.
func (c *client) runExec(machine, command string, argv []string, timeout int, asJSON bool) int {
	body := map[string]any{"machine": machine}
	if command != "" {
		body["command"] = command
	} else {
		body["argv"] = argv
	}
	if timeout > 0 {
		body["timeout"] = timeout
	}
	raw, err := json.Marshal(body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	req, err := http.NewRequest("POST", strings.TrimRight(c.cfg.Server, "/")+"/v1/exec", bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/x-ndjson")
	resp, err := c.http.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Failures before the command was dispatched are still plain HTTP
		// errors with a JSON body (bad request, not scoped, blocked by
		// policy, machine offline) — only the stream itself is NDJSON.
		return reportHTTPError(resp)
	}
	if asJSON {
		return relayFrames(resp.Body)
	}
	return decodeExecStream(resp.Body)
}

// relayFrames copies the control plane's frames to stdout as NDJSON, one frame
// per line, without interpreting them.
//
// This is the mode for a programmatic caller — an automated troubleshooter, a
// pipeline — and it is the reason the mode exists: the frames carry an
// explicit type and stream label, so a consumer never has to work out which
// bytes on its stdout came from the machine and which from mach. Nothing the
// remote command prints can change the exit status the caller reads, because
// the status is a field on the exit frame rather than a byte offset in a text
// stream (see decodeExecStream for the guard against forged frames).
func relayFrames(r io.Reader) int {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 64<<10))
	code := 3
	for {
		var f protocol.ExecStreamFrame
		if err := dec.Decode(&f); err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(os.Stderr, "mach: stream ended without an exit status (command may still be running)")
				return code
			}
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			return code
		}
		raw, err := json.Marshal(f)
		if err != nil {
			continue
		}
		os.Stdout.Write(append(raw, '\n'))
		if f.Type == protocol.ExecStreamExit {
			if f.Error != "" {
				fmt.Fprintln(os.Stderr, "mach: "+f.Error)
			}
			if f.ExitCode != nil {
				return *f.ExitCode
			}
			return 0
		}
	}
}

// reportHTTPError prints the control plane's error body and returns the
// client's "could not run it" status.
func reportHTTPError(resp *http.Response) int {
	const maxErr = 64 << 10
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErr))
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(data, &e)
	if e.Error != "" {
		fmt.Fprintln(os.Stderr, "mach: "+e.Error)
	} else {
		fmt.Fprintf(os.Stderr, "mach: server returned %d\n", resp.StatusCode)
	}
	return 3
}

// decodeExecStream prints output chunks as they arrive and returns the
// command's exit status. The exit record — not the HTTP status — is what says
// how the command ended: output was already flowing by the time it could fail.
//
// Where remote bytes go, and why:
//
//   - stdout carries ONLY the machine's stdout, and stderr carries the
//     machine's stderr followed by mach's own messages, which are always
//     prefixed "mach: ". A caller that keeps the two apart therefore never
//     has to guess which text came from the machine.
//   - Nothing here interprets output. A command that prints a line looking
//     like a frame, an exit status, or a mach error is relayed byte for byte
//     and changes nothing: control facts (exit status, error) are read from
//     typed fields on the exit frame, never from the output stream. Chunk
//     payloads are also base64 on the wire, so output containing newlines
//     cannot end a frame or start a new one.
//
// Output from a machine is data. Neither this client nor the agent treats it
// as instructions, and a consumer of this command must not either.
func decodeExecStream(r io.Reader) int {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 64<<10))
	for {
		var f protocol.ExecStreamFrame
		err := dec.Decode(&f)
		if errors.Is(err, io.EOF) {
			// Ended without an exit record: the connection was cut mid-command
			// (proxy timeout, control plane restart). The command's fate on
			// the machine is unknown, so do not report success.
			fmt.Fprintln(os.Stderr, "mach: stream ended without an exit status (command may still be running)")
			return 3
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			return 3
		}
		switch f.Type {
		case protocol.ExecStreamChunk:
			data, err := base64.StdEncoding.DecodeString(f.DataB64)
			if err != nil {
				fmt.Fprintln(os.Stderr, "mach: corrupt stream frame")
				return 3
			}
			if f.Stream == "stderr" {
				os.Stderr.Write(data)
			} else {
				os.Stdout.Write(data)
			}
		case protocol.ExecStreamExit:
			if f.Error != "" {
				fmt.Fprintln(os.Stderr, "mach: "+f.Error)
			}
			if f.ExitCode == nil {
				return 0
			}
			return *f.ExitCode
		default:
			// Unknown frame type: skip it, so a newer control plane can add
			// frames without breaking this client.
		}
	}
}

// Exec runs a shell-mode command (parsed once by the remote sh -c). With
// asJSON, the control plane's stream frames are re-emitted on stdout as NDJSON
// instead of being decoded into this process's streams.
//
// Use asJSON when something other than a person reads the result — an
// automated troubleshooter, a pipeline. The frames name their type and stream
// explicitly, so the caller gets the machine's output as labeled data with the
// exit status as a separate field, and never has to parse a line of text to
// find out how the command ended or which bytes came from where.
func (c *client) Exec(machine, command string, timeout int, asJSON bool) int {
	return c.runExec(machine, command, nil, timeout, asJSON)
}

// ExecArgv runs in no-shell mode: each argument is delivered as its own
// JSON string and exec'd directly on the machine — nothing parses anything,
// so spaces, quotes, $, and newlines inside arguments survive exactly.
func (c *client) ExecArgv(machine string, argv []string, timeout int, asJSON bool) int {
	return c.runExec(machine, "", argv, timeout, asJSON)
}

// Console is the interactive mode: read lines, exec each on the machine.
// Exit with Ctrl-D or :quit.
//
// Only what the operator types here is ever run. Output returned by a command
// is printed and nothing else — it is never echoed into the input stream, and
// no text in it can add, change, or trigger a command. A machine that prints
// something resembling a prompt, a mach message, or an instruction is just
// printing text.
func (c *client) Console(machine string) int {
	fmt.Fprintf(os.Stderr, "mach console — %s (commands run remotely; Ctrl-D to exit)\n", machine)
	fmt.Fprintln(os.Stderr, "output from the machine is data, printed as-is; mach never acts on it")
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for {
		fmt.Fprint(os.Stderr, "mach> ")
		if !sc.Scan() {
			fmt.Fprintln(os.Stderr)
			return 0
		}
		line := strings.TrimSpace(sc.Text())
		switch line {
		case "", "help":
			fmt.Fprintln(os.Stderr, "type a shell command; :quit or Ctrl-D to exit; :! cmd runs locally")
			continue
		case ":quit", "exit":
			return 0
		}
		if strings.HasPrefix(line, ":!") {
			LocalExec(strings.TrimSpace(strings.TrimPrefix(line, ":!")))
			continue
		}
		code := c.Exec(machine, line, 0, false)
		if code != 0 {
			// stderr, not stdout: stdout belongs to the machine's output, so a
			// caller reading stdout alone sees only what the machine printed.
			fmt.Fprintf(os.Stderr, "[exit %d]\n", code)
		}
	}
}

func (c *client) Audit(machine string, limit int) int {
	q := fmt.Sprintf("?limit=%d", limit)
	if machine != "" && machine != "*" {
		q += "&machine=" + url.QueryEscape(machine)
	}
	var resp struct {
		Entries []auditEntry `json:"entries"`
	}
	if err := c.do("GET", "/v1/audit"+q, nil, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	for _, e := range resp.Entries {
		ec := "-"
		if e.ExitCode != nil {
			ec = fmt.Sprintf("%d", *e.ExitCode)
		}
		fmt.Printf("%s  %-16s exit=%-4s src=%-24s %s\n", e.TS, e.Machine, ec, e.Source, oneLine(e.Command))
	}
	return 0
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ⏎ ")
	// Trim on a rune boundary so multi-byte UTF-8 isn't split.
	if runes := []rune(s); len(runes) > 117 {
		s = string(runes[:117]) + "..."
	}
	return s
}

// InterruptGuard exits immediately on Ctrl-C / SIGTERM. (There is no
// in-flight request to cancel in the one-shot exec path; output printed
// so far stands.)
func InterruptGuard() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		os.Exit(130)
	}()
}
