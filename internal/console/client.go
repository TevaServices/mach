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
	"syscall"
	"time"

	"github.com/bcross/mach/internal/e2e"
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
	// pins remembers each machine's E2E key on first use. See pins.go for what
	// that does and does not protect against.
	pins *pinStore
}

func New(cfg *Config) *client {
	return &client{cfg: cfg, http: &http.Client{Timeout: 12 * time.Minute}, pins: newPinStore()}
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
		msg := e.Error
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

type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Error    string `json:"error"`
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
	var res ExecResult
	if err := c.do("POST", "/v1/exec", buildBody(), &res); err != nil {
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
	var res ExecResult
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
func printExecResult(res *ExecResult, asJSON bool) int {
	if asJSON {
		if b, err := json.Marshal(res); err == nil {
			os.Stdout.Write(append(b, '\n'))
		}
		if res.Error != "" {
			fmt.Fprintln(os.Stderr, "mach: "+res.Error)
		}
		return res.ExitCode
	}
	fmt.Print(res.Stdout)
	if res.Stderr != "" {
		os.Stderr.WriteString(res.Stderr)
	}
	if res.Error != "" {
		fmt.Fprintln(os.Stderr, "mach: "+res.Error)
	}
	return res.ExitCode
}

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
