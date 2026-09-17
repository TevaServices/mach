package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/bcross/mach/internal/version"
	"github.com/skip2/go-qrcode"
)

// postJSON is the tiny HTTP helper for the enrollment endpoints.
func postJSON(server, path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Post(strings.TrimRight(server, "/")+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error != "" {
			return fmt.Errorf("server: %s", e.Error)
		}
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// postJSON2 is postJSON with a typed result.
func postJSON2[Out any](server, path string, body any) (Out, error) {
	var out Out
	err := postJSON(server, path, body, &out)
	return out, err
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown"
	}
	return h
}

// pairPrefill builds the query string the QR carries, so the phone page opens
// with the org and a machine name already in it and the operator only has to
// read the challenge code off this console.
//
// Both values are suggestions in editable fields: the page shows them under a
// line saying the agent supplied them, and whatever is submitted is validated
// on the control plane exactly as it was before suggestions existed. The
// challenge code is deliberately NOT here — it is the one thing that makes a
// photograph of this QR worthless, and it stays on this screen.
func pairPrefill(org, host string) string {
	v := url.Values{}
	if o := strings.ToLower(strings.TrimSpace(org)); o != "" {
		v.Set("org", o)
	}
	if part := suggestMachinePart(host); part != "" {
		v.Set("name", part)
	}
	return v.Encode()
}

// suggestMachinePart turns a hostname into a machine-name candidate: lowercased
// (hostnames conventionally are, and it keeps the suggestion visually distinct
// from the uppercase challenge code printed on the same screen), its domain
// dropped, anything outside [a-z0-9-] folded to a single hyphen, and the whole
// thing capped at the length a machine-name part may have. A hostname that folds
// away to nothing yields "" and the page simply starts empty.
//
// The result must satisfy store.ValidMachinePart — that is the rule the control
// plane validates the submitted name with, and a suggestion it would reject is
// worse than none. This package does not import internal/store to reuse the
// function (it would drag both SQL drivers into a binary that ships to every
// target), so the agreement is asserted in register_test.go and again across the
// seam by scripts/e2e.sh, which checks the name in the QR survives to the page.
func suggestMachinePart(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(host, '.'); i >= 0 {
		host = host[:i]
	}
	var b strings.Builder
	dash := false
	for _, r := range host {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 48 {
		s = strings.Trim(s[:48], "-")
	}
	return s
}

// warnInsecureServer prints a loud warning when the control plane is plain
// http: enrollment credentials (and later, commands) cross the wire
// unencrypted. Allowed (dev deployments) but never silently.
func warnInsecureServer(server string) {
	if strings.HasPrefix(server, "http://") {
		fmt.Println("\n*** WARNING: this control plane uses plain http — enrollment credentials and ALL commands will be unencrypted on the wire. Use an https:// control plane for anything real. ***")
	}
}

func bold(s string) string { return "\033[1m" + s + "\033[0m" }

// RegisterQR runs the QR pairing flow: request a pairing session, show the
// QR + challenge code on this machine's console, wait for phone approval,
// then claim the enrollment. The QR points at the CONTROL PLANE — the
// phone never needs to reach this machine, and the challenge code is never
// embedded in the QR (the human reads it HERE and types it on the phone).
func RegisterQR(server, org, stateDir string) (*Config, error) {
	id, err := LoadOrCreate(stateDir)
	if err != nil {
		return nil, err
	}
	e2eKey, err := LoadOrCreateE2EKey(stateDir)
	if err != nil {
		return nil, err
	}
	cfg, err := registerQRCore(server, org, id, e2eKey, false)
	if err != nil {
		return nil, err
	}
	if err := SaveConfig(stateDir, cfg); err != nil {
		return nil, err
	}
	fmt.Println("Run the agent with:  mach run   (or make it permanent with: mach install)")
	return cfg, nil
}

// registerQRCore runs the pairing flow for an identity that has already been
// loaded, and does NOT persist the result. That split is what lets the temporary
// session enroll with an in-memory identity: it calls this and never reaches
// SaveConfig, so nothing it learns outlives the process.
func registerQRCore(server, org string, id *Identity, e2eKey *E2EKeyPair, temporary bool) (*Config, error) {
	warnInsecureServer(server)
	start, err := postJSON2[protocol.PairStartResponse](server, "/v1/pair/start", protocol.PairStartReq{
		PubKey: id.PubHex, PubE2E: e2eKey.PublicKeyHex(),
		Hostname: hostname(), OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVer: version.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("pair start: %w", err)
	}

	pairURL := strings.TrimRight(server, "/") + "/pair/" + start.Token
	if q := pairPrefill(org, hostname()); q != "" {
		pairURL += "?" + q
	}
	qr, err := qrcode.New(pairURL, qrcode.Medium)
	if err != nil {
		return nil, err
	}

	fmt.Println("==========================================================")
	fmt.Println("mach agent enrollment")
	fmt.Printf("  server:   %s\n", server)
	fmt.Printf("  hostname: %s (%s/%s)  agent %s\n", hostname(), runtime.GOOS, runtime.GOARCH, version.Version)
	fmt.Println()
	fmt.Println("  1. Scan this QR with your phone (or open the URL):")
	fmt.Println()
	fmt.Println(qr.ToSmallString(false))
	fmt.Printf("     %s\n", pairURL)
	fmt.Println("  2. On the phone page, TYPE this machine's challenge code")
	fmt.Printf("     (the page never shows it — read it here):  %s\n", bold(start.Code))
	fmt.Println("     Its dashes are optional; the 12 characters are what matter.")
	fmt.Println("  3. Approve. The page arrives with the org and a machine name")
	fmt.Printf("     already filled in (%s-<hostname>); edit either if it is wrong.\n", org)
	fmt.Println()
	fmt.Println("Waiting for approval (this pairing expires in ~10 minutes; 5 wrong code attempts expire it)...")
	fmt.Println("==========================================================")

	deadline := time.Now().Add(11 * time.Minute)
	for {
		if time.Now().After(deadline) {
			return nil, errors.New("pairing expired before approval — run `mach register` again")
		}
		st, err := postJSON2[protocol.PairStatusResponse](server, "/v1/pair/status", protocol.PairStatusReq{Token: start.Token})
		if err != nil {
			return nil, fmt.Errorf("pair status: %w", err)
		}
		switch st.State {
		case "approved":
			goto approved
		case "denied":
			return nil, errors.New("pairing denied on the phone — run `mach register` again")
		case "expired":
			return nil, errors.New("pairing expired (or too many wrong code attempts) — run `mach register` again")
		}
		time.Sleep(2 * time.Second)
	}
approved:
	// The phone verified the challenge code; claim creates the machine and
	// burns the one-time token. Response carries the server's public key.
	claim, err := postJSON2[struct {
		OK        string `json:"ok"`
		Machine   string `json:"machine"`
		ServerKey string `json:"server_key"`
	}](server, "/v1/pair/claim", protocol.PairClaimRequest{
		PubKey: id.PubHex, PubE2E: e2eKey.PublicKeyHex(), Token: start.Token, Temporary: temporary,
	})
	if err != nil {
		return nil, fmt.Errorf("pair claim: %w", err)
	}
	cfg := &Config{Server: server, Name: claim.Machine, ServerKey: claim.ServerKey}
	fmt.Printf("Enrolled as machine %q (server key pinned).\n", cfg.Name)
	return cfg, nil
}

// RegisterAPIKey enrolls headlessly with an enroll-scoped API key.
func RegisterAPIKey(server, apiKey, name, org, stateDir string) (*Config, error) {
	id, err := LoadOrCreate(stateDir)
	if err != nil {
		return nil, err
	}
	e2eKey, err := LoadOrCreateE2EKey(stateDir)
	if err != nil {
		return nil, err
	}
	cfg, err := registerAPIKeyCore(server, apiKey, name, org, id, e2eKey, false)
	if err != nil {
		return nil, err
	}
	if err := SaveConfig(stateDir, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// registerAPIKeyCore is registerAPIKey without the persistence, for the same
// reason registerQRCore is split out.
func registerAPIKeyCore(server, apiKey, name, org string, id *Identity, e2eKey *E2EKeyPair, temporary bool) (*Config, error) {
	warnInsecureServer(server) // the API key itself crosses the wire here
	resp, err := postJSON2[struct {
		OK        string `json:"ok"`
		Machine   string `json:"machine"`
		ServerKey string `json:"server_key"`
	}](server, "/v1/register/apikey", protocol.RegisterAPIKeyReq{
		APIKey: apiKey, PubKey: id.PubHex, PubE2E: e2eKey.PublicKeyHex(), Name: name,
		Hostname: hostname(), OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVer: version.Version,
		Temporary: temporary,
	})
	if err != nil {
		return nil, err
	}
	cfg := &Config{Server: server, Name: resp.Machine, ServerKey: resp.ServerKey}
	fmt.Printf("Enrolled as machine %q via API key.\n", cfg.Name)
	return cfg, nil
}
