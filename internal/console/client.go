// Package console is the mach CLI client: it dials the control plane's
// console API with a bearer API key. This is the interface the Hermes
// troubleshooter (and humans) drive the fleet through.
package console

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
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
// E2E path: fetch the machine's X25519 public key, seal the ExecCommand to
// it, and POST only ciphertext. Falls back to plaintext exec when the
// machine has no E2E key (enrolled before E2E existed).
func (c *client) runExec(machine, command string, argv []string, timeout int) int {
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

	// Try E2E first.
	e2ePub, keyErr := c.machineE2EPub(machine)
	if keyErr == nil && e2ePub != "" {
		inner, _ := json.Marshal(map[string]any{
			"command": command, "argv": argv,
			"timeout": mapDefaultTimeout(timeout),
		})
		var consoleE2E E2EKeyPair
		if genErr := consoleE2E.Generate(); genErr == nil {
			sealed, sealErr := consoleE2E.Seal(e2ePub, inner)
			if sealErr == nil {
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
				werr := c.do("POST", "/v1/exec", body, &wire)
				if werr == nil && wire.SealedB64 != "" {
					opened, oerr := consoleE2E.OpenB64(wire.SealedB64)
					if oerr != nil {
						fmt.Fprintln(os.Stderr, "mach: e2e: failed to open sealed result ("+oerr.Error()+")")
						return 3
					}
					var res ExecResult
					if jerr := json.Unmarshal(opened, &res); jerr != nil {
						fmt.Fprintln(os.Stderr, "mach: e2e: sealed result undecodable")
						return 3
					}
					return printExecResult(&res)
				}
				if werr == nil {
					// Sealed exec without sealed reply (server quirk): treat
					// as failure — output would be missing.
					fmt.Fprintln(os.Stderr, "mach: e2e: server returned no sealed reply")
					return 3
				}
				// werr != nil → fall through to plaintext attempt below.
			}
		}
	}

	// Plaintext fallback (or E2E unavailable).
	var res ExecResult
	if err := c.do("POST", "/v1/exec", buildBody(), &res); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	return printExecResult(&res)
}

func mapDefaultTimeout(timeout int) int {
	if timeout > 0 {
		return timeout
	}
	return 30
}

func printExecResult(res *ExecResult) int {
	fmt.Print(res.Stdout)
	if res.Stderr != "" {
		os.Stderr.WriteString(res.Stderr)
	}
	if res.Error != "" {
		fmt.Fprintln(os.Stderr, "mach: "+res.Error)
	}
	return res.ExitCode
}

// machineE2EPub fetches the machine's X25519 public key ("" when absent).
func (c *client) machineE2EPub(machine string) (string, error) {
	var resp struct {
		PubE2E string `json:"pub_e2e"`
	}
	if err := c.do("GET", "/v1/machines/"+url.PathEscape(machine)+"/e2epub", nil, &resp); err != nil {
		return "", err
	}
	return resp.PubE2E, nil
}

// isNoE2EKeyErr reports whether the error means "machine has no E2E key".
func isNoE2EKeyErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no E2E key")
}

// E2EKeyPair is the console-side ephemeral X25519 keypair for one exec.
type E2EKeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// Generate creates a fresh keypair.
func (k *E2EKeyPair) Generate() error {
	if _, err := rand.Read(k.Private[:]); err != nil {
		return err
	}
	pub, err := curve25519.X25519(k.Private[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	copy(k.Public[:], pub)
	return nil
}

// PublicKeyHex hex-encodes the public half.
func (k *E2EKeyPair) PublicKeyHex() string {
	return hex.EncodeToString(k.Public[:])
}

// Seal encrypts plaintext to a recipient X25519 public key (hex).
func (k *E2EKeyPair) Seal(recipientPubHex string, plaintext []byte) (sealedB64Payload string, err error) {
	pub, err := hex.DecodeString(recipientPubHex)
	if err != nil {
		return "", err
	}
	senderPub, err := curve25519.X25519(k.Private[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	shared, err := curve25519.X25519(k.Private[:], pub)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.New(shared)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, plaintext, senderPub)
	msg := e2eWire{V: 1, Eph: base64.StdEncoding.EncodeToString(senderPub), Body: base64.StdEncoding.EncodeToString(append(nonce, sealed...))}
	raw, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// OpenB64 opens a base64(e2e.SealedMessage JSON) with this keypair.
func (k *E2EKeyPair) OpenB64(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return e2eOpenRaw(&k.Private, raw)
}

// e2eOpenRaw decrypts a marshaled SealedMessage with the given private key.
// (Local copy to avoid importing internal/e2e from console — the wire JSON
// is identical: {"v":1,"eph":...,"body":...}.)
func e2eOpenRaw(privateKey *[32]byte, sealed []byte) ([]byte, error) {
	var msg e2eWire
	if err := json.Unmarshal(sealed, &msg); err != nil {
		return nil, err
	}
	ephPub, err := base64.StdEncoding.DecodeString(msg.Eph)
	if err != nil || len(ephPub) != 32 {
		return nil, fmt.Errorf("e2e: bad ephemeral key")
	}
	body, err := base64.StdEncoding.DecodeString(msg.Body)
	if err != nil || len(body) < chacha20poly1305.NonceSize+16 {
		return nil, fmt.Errorf("e2e: sealed body too short")
	}
	nonce, ct := body[:chacha20poly1305.NonceSize], body[chacha20poly1305.NonceSize:]
	shared, err := curve25519.X25519(privateKey[:], ephPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(shared)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, ephPub)
}

// e2eWire mirrors e2e.SealedMessage for the console (kept in sync: v=1).
type e2eWire struct {
	V    int    `json:"v"`
	Eph  string `json:"eph"`
	Body string `json:"body"`
}

// Exec runs a shell-mode command (parsed once by the remote sh -c).
func (c *client) Exec(machine, command string, timeout int) int {
	return c.runExec(machine, command, nil, timeout)
}

// ExecArgv runs in no-shell mode: each argument is delivered as its own
// JSON string and exec'd directly on the machine — nothing parses anything,
// so spaces, quotes, $, and newlines inside arguments survive exactly.
func (c *client) ExecArgv(machine string, argv []string, timeout int) int {
	return c.runExec(machine, "", argv, timeout)
}

// Console is the interactive mode: streams a persistent shell session
// live over the streaming endpoint. Falls back to
// line-based exec when the streaming endpoint is unavailable.
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
		if code == 3 {
			// Stream endpoint unreachable: fall back to buffered exec so
			// old deployments keep working.
			code = c.Exec(machine, line, 0)
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
