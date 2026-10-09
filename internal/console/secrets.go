package console

// Secrets, console side: the CLI's window onto the names-only registry.
//
// Everything here carries NAMES. A push reads the value from a file or stdin
// (never argv — a value on the command line lands in `ps` and shells' his-
// tory), seals it to the target machine's E2E key through the SAME trust-on-
// first-use pin path a sealed exec uses, and hands the control plane an
// opaque blob. The control plane relays it blind and records the name; the
// machine writes the value and scrubs it out of everything it sends back.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/TevaServices/mach/internal/protocol"
)

// secretValueBounds mirrors the agent's own limits: a value too short to be
// a secret would also make the machine's scrubbing meaningless. The client
// refuses before sealing so the operator learns immediately, not from the
// machine's rejection.
const (
	minSecretValueBytes = 8
	maxSecretValueBytes = 4096
)

// registrySecret is one row of the control plane's names-only registry.
type registrySecret struct {
	Name       string `json:"name"`
	Org        string `json:"org,omitempty"`
	CreatedAt  string `json:"created_at"`
	CreatedBy  string `json:"created_by,omitempty"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
}

// SecretsRegistryList prints the registry for this key's org.
func (c *client) SecretsRegistryList() int {
	var resp struct {
		Secrets []registrySecret `json:"secrets"`
	}
	if err := c.do("GET", "/v1/secrets", nil, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	if len(resp.Secrets) == 0 {
		fmt.Println("no secrets registered")
		return 0
	}
	for _, s := range resp.Secrets {
		row := s.Name
		if s.Org != "" {
			row = s.Org + "/" + s.Name
		}
		by := s.CreatedBy
		if by == "" {
			by = "-"
		}
		fmt.Printf("%s\t%s\t%s\n", row, s.CreatedAt, by)
	}
	return 0
}

// SecretsMachineList asks one machine, live, which secret NAMES it holds.
func (c *client) SecretsMachineList(machine string) int {
	var resp struct {
		Machine string   `json:"machine"`
		Org     string   `json:"org"`
		Names   []string `json:"names"`
	}
	if err := c.do("GET", "/v1/secrets?machine="+url.QueryEscape(machine), nil, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	if len(resp.Names) == 0 {
		fmt.Printf("%s holds no secrets for org %s\n", machine, resp.Org)
		return 0
	}
	for _, n := range resp.Names {
		fmt.Println(n)
	}
	return 0
}

// SecretsPush seals one secret to one machine and relays it. name and
// machine are positional; the value arrives from valueFile ("-" = stdin).
// The exit code is the command's; the value is never printed and never
// lands in argv.
func (c *client) SecretsPush(machine, name, valueFile string) int {
	if err := protocol.ValidSecretName(name); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 2
	}
	value, err := readSecretValue(valueFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 2
	}
	if len(value) < minSecretValueBytes || len(value) > maxSecretValueBytes {
		fmt.Fprintf(os.Stderr, "mach: secret value must be %d..%d bytes\n", minSecretValueBytes, maxSecretValueBytes)
		return 2
	}

	// The same preamble a sealed exec runs: the control plane's signal, the
	// machine's key, the pin. Trust-on-first-use applies here exactly as it
	// does to commands — a substituted key is a refusal naming two
	// fingerprints, and `mach trust` is the only thing that accepts it.
	info, err := c.machineE2EPub(machine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mach: cannot push: could not read the control plane's E2E setting (%v)\n", err)
		return 3
	}
	if !info.Enabled {
		// A push is the one path where a value crosses the wire, so sealing
		// is not negotiable the way it is for exec: there is no plaintext
		// fallback, because the plaintext fallback IS the leak.
		fmt.Fprintln(os.Stderr, "mach: cannot push: "+info.Reason)
		return 3
	}
	if info.PubE2E == "" {
		fmt.Fprintf(os.Stderr, "mach: cannot push: %s has no E2E key — re-enroll it to enable secret push\n", machine)
		return 3
	}
	first, pinErr := c.pins.check(machine, info.PubE2E, info.Org)
	if pinErr != nil {
		fmt.Fprintln(os.Stderr, "mach: "+pinErr.Error())
		return 3
	}
	if first {
		fmt.Fprintf(os.Stderr, "mach: pinned the E2E key for %s (%s); a later change is refused until you run `mach trust %s`\n",
			machine, KeyFingerprint(info.PubE2E), machine)
	}

	payload, err := json.Marshal(protocol.SecretPayload{
		Name:  name,
		Org:   info.Org,
		Value: string(value),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: e2e: "+err.Error())
		return 3
	}
	consoleE2E, err := newConsoleE2E()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: e2e: "+err.Error())
		return 3
	}
	sealed, err := consoleE2E.Seal(info.PubE2E, payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: e2e: "+err.Error())
		return 3
	}
	body := map[string]any{"machine": machine, "name": name, "sealed": sealed}
	var wire struct {
		OK      string `json:"ok"`
		Machine string `json:"machine"`
	}
	if err := c.do("POST", "/v1/secrets/push", body, &wire); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	fmt.Printf("pushed %s to %s (value sealed end-to-end; the control plane cannot read it)\n", name, wire.Machine)
	return 0
}

// readSecretValue reads the value from a file or stdin, with no echo and no
// argv exposure. A missing file is an error naming the flag, not a silent
// empty value.
func readSecretValue(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	if path == "" {
		return nil, fmt.Errorf("--value-file is required (a path, or - for stdin)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading --value-file: %w", err)
	}
	// A trailing newline is editor residue, not part of the secret; strip
	// exactly one.
	return trimSingleTrailingNewline(b), nil
}

func trimSingleTrailingNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	if len(b) > 0 && b[len(b)-1] == '\r' {
		b = b[:len(b)-1]
	}
	return b
}

// ParseInjectNames splits an --inject value into names, refusing an empty
// element so a typo like "A,,B" fails before anything is sent. An absent
// flag (empty spec) is no names at all, not an error.
func ParseInjectNames(spec string) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	var out []string
	for _, n := range strings.Split(spec, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			return nil, fmt.Errorf("--inject: empty name in list")
		}
		if err := protocol.ValidSecretName(n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
