// Package console is the mach CLI client: it dials the control plane's
// console API with a bearer API key. This is the interface the Hermes
// troubleshooter (and humans) drive the fleet through.
package console

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TevaServices/mach/internal/e2e"
	"github.com/TevaServices/mach/internal/protocol"
	"golang.org/x/term"
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
		// Absent and unreadable are different answers, and conflating them is
		// dangerous here: "not configured" sends plain `mach` down the enrollment
		// path, so a console.json that exists but cannot be read (restored with
		// the wrong owner, a bad mount, a restrictive umask) turned an admin box
		// into a machine enrolling itself as a target. The pin store makes the
		// same distinction for the same reason.
		if os.IsNotExist(err) {
			return nil, errNotConfigured{dir: dir}
		}
		return nil, fmt.Errorf("could not read %s: %w", path, err)
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
	// pins remembers each machine's E2E key on first use. See pins.go for what
	// that does and does not protect against.
	pins *pinStore
}

// New builds the console client.
//
// The transport is the default one with keep-alives turned off, and that is a
// correctness setting rather than a performance one. net/http will re-send a
// request by itself in a few situations, and every one of those situations
// requires a *reused* connection (`shouldRetryRequest` returns false for a fresh
// one) — so closing each connection removes the whole class, by construction,
// instead of relying on net/http's current rules about which methods and bodies
// are replayable.
//
// That matters because of what this client carries: `mach exec` sends commands,
// and "one command is one execution" is the invariant the sealed path is built
// around. A transport that re-sent a request on its own would run the command a
// second time with nothing in the console to see or report. The cost is one TCP
// (and TLS) handshake per API call, and the console makes a handful of calls per
// command.
func New(cfg *Config) *client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true
	return &client{cfg: cfg, http: &http.Client{Timeout: 12 * time.Minute, Transport: tr}, pins: newPinStore()}
}

// maxResp bounds what one API response may be. It comes from the protocol
// because it has to be larger than the agent's own per-stream output cap: the
// reply carrying a result is bigger than the result, and a client cap equal to
// the agent's is what stopped the agent's truncation marker from ever arriving.
const maxResp = protocol.MaxExecReplyBytes

// newRequest builds one API request. It is separate from do so the properties
// that make a request unreplayable can be asserted directly (see
// TestRequestsCannotBeReplayedByTheTransport) rather than inferred from the
// transport's behaviour.
func (c *client) newRequest(method, path string, body any) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.Server, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// GetBody is the *mechanism* by which net/http gets a second copy of a body
	// to re-send, and bytes.Reader hands it to us for free. Dropping it says
	// plainly that this request must not be replayed, and it closes the one
	// branch in shouldRetryRequest that consults it (which fires only when
	// nothing was written, so it was never reachable as a second execution —
	// see TestRequestsCannotBeReplayedByTheTransport for what was checked). It
	// is belt to the keep-alive braces: the transport cannot retry a fresh
	// connection at all, and this makes the request itself unreplayable too.
	req.GetBody = nil
	return req, nil
}

func (c *client) do(method, path string, body any, out any) error {
	req, err := c.newRequest(method, path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResp))
	if len(data) == maxResp {
		// Failing open here would surface as a confusing JSON unmarshal
		// error; say what actually happened.
		return fmt.Errorf("server response exceeded %d MiB", maxResp>>20)
	}
	// 202 is an error to this client even though the wire call succeeded:
	// the server is the only caller that sends it, and it means "held, not
	// done" — a pending approval the operator must decide (there is no
	// ExecResult to parse). A body silently parsed into a zero-value result
	// would print nothing and exit 0, reporting a refused command as a
	// successful one.
	if resp.StatusCode >= 300 || resp.StatusCode == http.StatusAccepted {
		var e struct {
			Error  string `json:"error"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Error
		if msg == "" && e.Status == "pending_approval" {
			msg = "pending approval: " + e.Reason
		}
		if msg == "" {
			msg = fmt.Sprintf("server returned %d", resp.StatusCode)
		}
		return &apiError{Status: resp.StatusCode, Msg: msg}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// apiError is a non-2xx answer from the control plane: the server read the
// request and declined it. It is a distinct type because callers have to tell
// that apart from everything else that can go wrong — a refusal means nothing
// was dispatched, while a transport failure or a reply too large to read may
// mean the command is already running on the machine.
type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return e.Msg }

type MachineInfo struct {
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Online    bool   `json:"online"`
	AgentVer  string `json:"agent_version"`
	CreatedAt string `json:"created_at"`
	// E2E is this machine's org's E2E setting ("on"/"off"): whether the control
	// plane will accept a sealed command for it.
	E2E string `json:"e2e"`
	// Blocked is the operator's soft block: the machine is enrolled and may even
	// be connected, but the control plane will not dispatch to it. Reported so
	// `mach list` can say so, rather than leaving an operator to wonder why every
	// command against a machine that looks online comes back refused.
	Blocked bool `json:"blocked"`
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
// E2E is the control plane's setting, and the console's job is to obey it:
// /e2epub reports whether this control plane accepts sealed commands and, if
// so, which key to seal to. The console seals when it can, and when the
// operator explicitly asked for sealing and the server will not do it, it
// exits with a message instead of quietly sending the command in the clear.
// Nothing here downgrades silently — a client that thinks it is encrypting and
// is not, is worse off than one that refuses.
func (c *client) runExec(machine, command string, argv []string, timeout int, asJSON bool, mode E2EMode) int {
	buildBody := func() map[string]any {
		body := map[string]any{"machine": machine}
		if command != "" {
			body["command"] = command
		} else {
			body["argv"] = argv
		}
		if timeout > 0 {
			body["timeout"] = timeout
		}
		return body
	}

	// E2EForbid never asks. The server's setting is irrelevant: the operator
	// wants this command readable (by the block list, by the audit log), and
	// plaintext is always something the server accepts.
	if mode != E2EForbid {
		info, err := c.machineE2EPub(machine)
		switch {
		case err != nil:
			// An older control plane without the signal, or a transient failure.
			// Sealing is not mandatory, so fall through to plaintext — unless
			// sealing was required, in which case say why not.
			if mode == E2ERequire {
				fmt.Fprintln(os.Stderr, "mach: cannot seal: could not read the control plane's E2E setting ("+err.Error()+")")
				return 3
			}
			// Say so, for the same reason the neighbouring "no key on this
			// machine" case does. Falling back to plaintext is fine; falling back
			// *silently* is the one outcome this whole path exists to prevent —
			// an operator who believes a command was encrypted when it was not.
			// It was also the cheapest way to reach that state: a 5xx, a proxy in
			// the way, or a control plane older than the route, any of which
			// hands the command to the control plane in the clear while a fleet
			// the operator believes has E2E on says nothing.
			fmt.Fprintln(os.Stderr, "mach: could not read the control plane's E2E setting — running in plaintext ("+err.Error()+")")
		case !info.Enabled:
			if mode == E2ERequire {
				fmt.Fprintln(os.Stderr, "mach: cannot seal: "+info.Reason)
				return 3
			}
		case info.PubE2E == "":
			// The server accepts sealed commands, but this machine never
			// registered a key — it enrolled before E2E existed. Say so rather
			// than letting the operator believe the command was sealed.
			if mode == E2ERequire {
				fmt.Fprintln(os.Stderr, "mach: cannot seal: "+machine+" has no E2E key — re-enroll it to enable E2E")
				return 3
			}
			fmt.Fprintf(os.Stderr, "mach: %s has no E2E key — running in plaintext (re-enroll to enable E2E)\n", machine)
		default:
			// The key came from the control plane, which is the party the seal
			// protects against; the pin is what makes a substituted key visible
			// instead of silent. Checked before anything is sent, in every mode:
			// a changed key is not something to work around automatically.
			first, pinErr := c.pins.check(machine, info.PubE2E, info.Org)
			if pinErr != nil {
				fmt.Fprintln(os.Stderr, "mach: "+pinErr.Error())
				return 3
			}
			if first {
				fmt.Fprintf(os.Stderr, "mach: pinned the E2E key for %s (%s); "+
					"a later change is refused until you run `mach trust %s`\n",
					machine, KeyFingerprint(info.PubE2E), machine)
			}
			if code, done := c.sealedExec(machine, command, argv, timeout, asJSON, info.PubE2E, mode); done {
				return code
			}
		}
	}

	// Plaintext: what the server can read, refuse, and record in full.
	var res protocol.ExecResult
	if err := c.do("POST", "/v1/exec", buildBody(), &res); err != nil {
		// A fleet-policy refusal is not always final: the control plane answers
		// 202 with a pending approval an operator can grant (or has granted
		// since — a concurrent retry that already dispatched would be a race
		// this client cannot see, so it never assumes). Say what is pending
		// rather than reporting a bare refusal.
		var api *apiError
		if errors.As(err, &api) && api.Status == http.StatusAccepted {
			// The 202 rides the apiError's message, not a body this client
			// parsed. Say what it means: a pending approval exists, and that is
			// the path an operator uses to allow this exact command.
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			fmt.Fprintln(os.Stderr, "mach: a pending approval was recorded — an operator can approve this exact command from the web UI's approvals panel")
			return 3
		}
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	return printExecResult(&res, asJSON)
}

// sealedExec sends one command as ciphertext. done is false when the caller
// should fall back to plaintext (the server refused sealing outright and the
// operator did not ask for sealing specifically); a command the server refused
// before dispatch has not run anywhere, so that fallback cannot execute
// anything twice.
func (c *client) sealedExec(machine, command string, argv []string, timeout int, asJSON bool, e2ePub string, mode E2EMode) (code int, done bool) {
	inner, _ := json.Marshal(map[string]any{
		"command": command, "argv": argv,
		"timeout": mapDefaultTimeout(timeout),
	})
	consoleE2E, err := newConsoleE2E()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: e2e: "+err.Error())
		return 3, true
	}
	sealed, err := consoleE2E.Seal(e2ePub, inner)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: e2e: "+err.Error())
		return 3, true
	}
	body := map[string]any{
		"machine": machine, "sealed": sealed,
		"e2e_pub": consoleE2E.PublicKeyHex(),
	}
	if timeout > 0 {
		body["timeout"] = timeout
	}
	var wire struct {
		ExitCode  int    `json:"exit_code"`
		SealedB64 string `json:"sealed_b64"`
	}
	if werr := c.do("POST", "/v1/exec", body, &wire); werr != nil {
		// Only a 403 is a refusal that is *known* to be before dispatch: it is
		// what this control plane answers when it will not take a sealed command
		// (E2E off for the org, the fleet policy, the key's scope, a blocked
		// machine) and every one of those checks sits ahead of the dispatch.
		//
		// Nothing else qualifies, and the difference is not academic. A 504 means
		// the command was dispatched and the agent did not answer in time; a
		// reply too large to read means it ran and answered. Both used to be
		// treated as refusals, and the plaintext retry that followed ran the
		// command a *second* time — unsealed — while the operator, who saw
		// correct-looking output, had no way to know.
		var api *apiError
		refused := errors.As(werr, &api) && api.Status == http.StatusForbidden

		if mode == E2ERequire {
			if refused {
				// Refused before dispatch: nothing ran, so the command is simply
				// not sent rather than sent unsealed.
				fmt.Fprintln(os.Stderr, "mach: cannot seal: "+werr.Error())
				return 3, true
			}
			fmt.Fprintln(os.Stderr, "mach: --e2e: "+werr.Error())
			fmt.Fprintln(os.Stderr, "mach: the command may have run on the machine; it was not resent.")
			return 3, true
		}
		if !refused {
			fmt.Fprintln(os.Stderr, "mach: the sealed reply did not come back: "+werr.Error())
			fmt.Fprintln(os.Stderr, "mach: not retrying in plaintext — the command may already have run, and"+
				"\n      resending it would run it a second time, unsealed.")
			return 3, true
		}
		// Obey the refusal and retry in plaintext, saying so rather than making
		// the downgrade invisible.
		fmt.Fprintf(os.Stderr, "mach: sealed exec refused (%s); retrying in plaintext\n", werr.Error())
		return 0, false
	}
	if wire.SealedB64 == "" {
		// Output would be missing: a sealed reply is the only way this command's
		// output comes back, so this is a failure, not a fallback.
		fmt.Fprintln(os.Stderr, "mach: e2e: server returned no sealed reply")
		return 3, true
	}
	opened, oerr := consoleE2E.OpenB64(wire.SealedB64)
	if oerr != nil {
		fmt.Fprintln(os.Stderr, "mach: e2e: failed to open sealed result ("+oerr.Error()+")")
		return 3, true
	}
	var res protocol.ExecResult
	if jerr := json.Unmarshal(opened, &res); jerr != nil {
		fmt.Fprintln(os.Stderr, "mach: e2e: sealed result undecodable")
		return 3, true
	}
	return printExecResult(&res, asJSON), true
}

// E2EMode is what the operator asked for on the command line. The default is
// to obey the control plane's setting; the two explicit modes exist so a
// caller can require sealing (and fail loudly if it is unavailable) or refuse
// it (when the command should stay readable to the block list and the audit
// log).
type E2EMode int

const (
	E2EObey    E2EMode = iota // seal when the control plane accepts it (default)
	E2ERequire                // --e2e: fail rather than send plaintext
	E2EForbid                 // --no-e2e: always plaintext
)

func mapDefaultTimeout(timeout int) int {
	if timeout > 0 {
		return timeout
	}
	return 30
}

// printExecResult writes the result the way a human reads it, or — with
// --json — as one JSON object on stdout. In JSON mode every field is labeled
// data: a program consuming mach reads the exit status from a field rather
// than having to interpret a mix of a byte stream and a process status.
func printExecResult(res *protocol.ExecResult, asJSON bool) int {
	if asJSON {
		// protocol.MarshalResult: the machine's output is bytes, not markup, and
		// the default HTML escaping would rewrite every < and & in it on a path
		// where nothing is ever rendered as HTML.
		if b, err := protocol.MarshalResult(*res); err == nil {
			os.Stdout.Write(append(b, '\n'))
		}
		if res.Error != "" {
			fmt.Fprintln(os.Stderr, "mach: "+res.Error)
		}
		return res.ExitCode
	}
	// Output(), not the text fields: it is what carries the exact bytes when the
	// machine's output was not valid UTF-8.
	stdout, stderr := res.Output()
	os.Stdout.Write(safeForTerminal(stdout, os.Stdout))
	if len(stderr) > 0 {
		os.Stderr.Write(safeForTerminal(stderr, os.Stderr))
	}
	if res.Error != "" {
		fmt.Fprintln(os.Stderr, "mach: "+res.Error)
	}
	return res.ExitCode
}

// isTerminal decides whether a destination is a terminal. A variable so a test
// can decide it: a test binary's stdout is a terminal when `go test` is run from
// one and a pipe when it is not, which is exactly the kind of environment
// dependence a test must not have.
var isTerminal = func(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// safeForTerminal makes a machine's output safe to write to a terminal, and
// changes nothing when the destination is not one.
//
// The machine's output is data, and this is the one place that data reaches a
// device that *interprets* it. A terminal honours the escape sequences it is
// given, so a compromised machine can write the operator's clipboard (OSC 52),
// rewrite the window title or forge a hyperlink (OSC 0/8), or erase what it
// already printed and paint a fake `mach>` prompt — or a fake `mach: `
// diagnostic — over what really happened. The console's existing candour, that
// a human cannot tell machine output from mach diagnostics by content, is about
// *reading* text; a sequence that redraws the screen is a different problem and
// was not covered by it.
//
// Only the ESC byte is rewritten, and only as `^[`. Newlines, tabs, carriage
// returns and every other byte pass through untouched, and the whole function
// is a no-op unless the destination is a terminal: a pipe, a redirect and
// `--json` all get the exact bytes, which is what invariant 9 promises and what
// a program reading the output requires. The destination is a parameter rather
// than always stdout because a command's stderr has its own — `mach exec host
// cmd > out.txt` sends the machine's stderr to the terminal while its stdout
// goes to a file, and the terminal is the one that needs the filter.
func safeForTerminal(b []byte, f *os.File) []byte {
	if !bytes.ContainsRune(b, 0x1b) || !isTerminal(f) {
		return b
	}
	out := make([]byte, 0, len(b)+16)
	for _, c := range b {
		if c == 0x1b {
			out = append(out, '^', '[')
			continue
		}
		out = append(out, c)
	}
	return out
}

// SafeForTerminal is safeForTerminal for stdout, exported for the callers in
// cmd/mach that render a machine's own hostname, OS and version themselves —
// so every place those words reach a terminal goes through one function rather
// than each caller remembering.
func SafeForTerminal(b []byte) []byte { return safeForTerminal(b, os.Stdout) }

// machineE2EPub reads the control plane's E2E signal for one machine: whether
// this control plane accepts sealed exec at all, why not when it does not, and
// the X25519 key to seal to when it does.
func (c *client) machineE2EPub(machine string) (e2eTarget, error) {
	var resp e2eTarget
	if err := c.do("GET", "/v1/machines/"+url.PathEscape(machine)+"/e2epub", nil, &resp); err != nil {
		return e2eTarget{}, err
	}
	return resp, nil
}

// e2eTarget is the console's view of the same signal the server publishes.
type e2eTarget struct {
	Enabled bool   `json:"e2e_enabled"`
	Mode    string `json:"e2e"`
	Reason  string `json:"e2e_reason"`
	// Org is the machine's org, the one the setting was resolved for. It rides
	// along so the pin file a human reads can tell machines apart.
	Org     string `json:"e2e_org"`
	Machine string `json:"machine"`
	PubE2E  string `json:"pub_e2e"`
	Note    string `json:"note"`
}

// consoleE2E is the console's half of one sealed exec: a fresh X25519 keypair
// per command, plus the seal/open helpers.
//
// The crypto and the envelope format live in internal/e2e — the same code the
// agent runs — rather than in a local copy of them. A second implementation of a
// sealed-message format is how a version field goes missing on one side and
// sealing fails on a machine that is otherwise perfectly healthy; there is no
// import cycle to avoid (internal/e2e depends on nothing but the standard library
// and x/crypto), so there is no reason to carry one.
type consoleE2E struct {
	kp *e2e.KeyPair
}

// newConsoleE2E creates the ephemeral keypair for one command.
func newConsoleE2E() (*consoleE2E, error) {
	kp, err := e2e.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &consoleE2E{kp: kp}, nil
}

// PublicKeyHex is the reply key the agent seals the result back to (hex).
func (c *consoleE2E) PublicKeyHex() string { return c.kp.PublicKeyHex() }

// Seal encrypts the inner command to the machine's X25519 key, returning the
// base64 blob that goes in the "sealed" field.
func (c *consoleE2E) Seal(recipientPubHex string, plaintext []byte) (string, error) {
	pub, err := hex.DecodeString(recipientPubHex)
	if err != nil {
		return "", err
	}
	sealed, err := e2e.Seal(pub, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenB64 opens the base64 sealed reply from the machine.
func (c *consoleE2E) OpenB64(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return e2e.Open(&c.kp.Private, raw)
}

// Exec runs a shell-mode command (parsed once by the remote sh -c).
func (c *client) Exec(machine, command string, timeout int, asJSON bool, e2e E2EMode) int {
	return c.runExec(machine, command, nil, timeout, asJSON, e2e)
}

// ExecArgv runs in no-shell mode: each argument is delivered as its own
// JSON string and exec'd directly on the machine — nothing parses anything,
// so spaces, quotes, $, and newlines inside arguments survive exactly.
func (c *client) ExecArgv(machine string, argv []string, timeout int, asJSON bool, e2e E2EMode) int {
	return c.runExec(machine, "", argv, timeout, asJSON, e2e)
}

// Console is the interactive mode: streams a persistent shell session
// live over the streaming endpoint. Falls back to
// line-based exec when the streaming endpoint is unavailable.
//
// Every command here goes over the streaming relay, which is plaintext by
// design (see SECURITY-NOTES.md): the console never seals, whatever the E2E
// setting is, because a live session is not a shape that can be sealed. A
// caller who needs sealing needs `mach exec`.
func (c *client) Console(machine string) int {
	fmt.Printf("mach console — %s (Ctrl-C kills the remote session; Ctrl-D exits)\n", machine)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for {
		fmt.Print("mach> ")
		if !sc.Scan() {
			fmt.Println()
			// Scan stops for two different reasons, and reporting both as a clean
			// exit 0 made them indistinguishable: a line longer than the scanner's
			// buffer (a pasted script, a base64 blob) was silently dropped and the
			// console exited 0, exactly as Ctrl-D does — so a caller piping a long
			// command in saw success and no command ever ran.
			if err := sc.Err(); err != nil {
				fmt.Fprintln(os.Stderr, "mach: reading your input: "+err.Error())
				return 2
			}
			return 0
		}
		line := strings.TrimSpace(sc.Text())
		switch line {
		case "", "help":
			fmt.Println("type a shell command; :quit or Ctrl-D to exit; :! cmd runs locally")
			continue
		case ":quit", "exit":
			return 0
		}
		if strings.HasPrefix(line, ":!") {
			LocalExec(strings.TrimSpace(strings.TrimPrefix(line, ":!")))
			continue
		}
		// Live streaming path.
		code := streamConsole(c.cfg.Server, c.cfg.APIKey, machine, line)
		if code == streamDialFailed {
			// The stream endpoint could not be reached — an older control
			// plane, typically. Falling back to buffered exec is safe here
			// because nothing was dispatched. It is deliberately NOT done for a
			// stream that died after starting: that command already ran on the
			// machine, and replaying it would run it a second time.
			code = c.Exec(machine, line, 0, false, E2EObey)
		}
		if code != 0 {
			fmt.Printf("[exit %d]\n", code)
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

// streamOwnsInterrupt is true while a streamed command is running. In that
// window Ctrl-C belongs to the remote command — killing it is exactly what the
// console's banner promises, and what the operator means by pressing it — so
// this process's interrupt guard stands down and the signal lands on the
// streaming session instead. See streamConsole.
var streamOwnsInterrupt atomic.Bool

// InterruptGuard exits immediately on Ctrl-C / SIGTERM. (There is no in-flight
// request to cancel in the one-shot exec path; output printed so far stands.)
//
// With one exception: a running streamed command owns the interrupt, because
// exiting here is what made Ctrl-C a no-op on the machine. It used to exit the
// process on the first signal, which raced the stream handler's own
// `stream_kill` write and almost always won — so the console vanished, the
// command kept running, and the audit row said only that its fate was unknown.
func InterruptGuard() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sig {
			if streamOwnsInterrupt.Load() {
				// The streaming session owns this one: it sends the kill, and it
				// exits on a second Ctrl-C or after its grace deadline.
				continue
			}
			os.Exit(130)
		}
	}()
}
