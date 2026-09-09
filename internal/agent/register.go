package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/skip2/go-qrcode"
)

var Version = "0.1.0-dev"

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

func bold(s string) string { return "\033[1m" + s + "\033[0m" }

// RegisterQR runs the QR pairing flow: request a pairing session, show the
// QR + challenge code on this machine's console, wait for phone approval,
// then claim the enrollment. The QR points at the CONTROL PLANE — the
// phone never needs to reach this machine, and the challenge code is never
// embedded in the QR (the human compares phone page vs this console).
func RegisterQR(server, stateDir string) (*Config, error) {
	id, err := LoadOrCreate(stateDir)
	if err != nil {
		return nil, err
	}
	start, err := postJSON2[protocol.PairStartResponse](server, "/v1/pair/start", protocol.PairStartReq{
		PubKey: id.PubHex, Hostname: hostname(), OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVer: Version,
	})
	if err != nil {
		return nil, fmt.Errorf("pair start: %w", err)
	}

	pairURL := strings.TrimRight(server, "/") + "/pair/" + start.Token
	qr, err := qrcode.New(pairURL, qrcode.Medium)
	if err != nil {
		return nil, err
	}

	fmt.Println("==========================================================")
	fmt.Println("mach agent enrollment")
	fmt.Printf("  server:   %s\n", server)
	fmt.Printf("  hostname: %s (%s/%s)  agent %s\n", hostname(), runtime.GOOS, runtime.GOARCH, Version)
	fmt.Println()
	fmt.Println("  1. Scan this QR with your phone (or open the URL):")
	fmt.Println()
	fmt.Println(qr.ToSmallString(false))
	fmt.Printf("     %s\n", pairURL)
	fmt.Println("  2. The phone page shows a challenge code. It must match")
	fmt.Printf("     this machine's code:  %s\n", bold(start.Code))
	fmt.Println("  3. Approve and pick a machine name on the phone.")
	fmt.Println()
	fmt.Println("Waiting for approval (this pairing expires in ~10 minutes)...")
	fmt.Println("==========================================================")

	deadline := time.Now().Add(11 * time.Minute)
	for {
		if time.Now().After(deadline) {
			return nil, errors.New("pairing expired before approval — run `machd register` again")
		}
		st, err := postJSON2[protocol.PairStatusResponse](server, "/v1/pair/status", protocol.PairStatusReq{Token: start.Token})
		if err != nil {
			return nil, fmt.Errorf("pair status: %w", err)
		}
		switch st.State {
		case "approved":
			goto approved
		case "denied":
			return nil, errors.New("pairing denied on the phone — run `machd register` again")
		case "expired":
			return nil, errors.New("pairing expired — run `machd register` again")
		}
		time.Sleep(2 * time.Second)
	}
approved:
	// The phone verified the challenge code; claim creates the machine and
	// burns the one-time token.
	claim, err := postJSON2[struct {
		OK      string `json:"ok"`
		Machine string `json:"machine"`
	}](server, "/v1/pair/claim", protocol.PairClaimRequest{PubKey: id.PubHex, Token: start.Token})
	if err != nil {
		return nil, fmt.Errorf("pair claim: %w", err)
	}
	cfg := &Config{Server: server, Name: claim.Machine}
	if err := SaveConfig(stateDir, cfg); err != nil {
		return nil, err
	}
	fmt.Printf("Enrolled as machine %q.\n", cfg.Name)
	fmt.Println("Run the agent with:  mach run   (or make it permanent with: mach install)")
	return cfg, nil
}

// RegisterAPIKey enrolls headlessly with a pre-shared console API key.
func RegisterAPIKey(server, apiKey, name, stateDir string) (*Config, error) {
	id, err := LoadOrCreate(stateDir)
	if err != nil {
		return nil, err
	}
	resp, err := postJSON2[struct {
		OK      string `json:"ok"`
		Machine string `json:"machine"`
	}](server, "/v1/register/apikey", protocol.RegisterAPIKeyReq{
		APIKey: apiKey, PubKey: id.PubHex, Name: name,
		Hostname: hostname(), OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVer: Version,
	})
	if err != nil {
		return nil, err
	}
	cfg := &Config{Server: server, Name: resp.Machine}
	if err := SaveConfig(stateDir, cfg); err != nil {
		return nil, err
	}
	fmt.Printf("Enrolled as machine %q via API key.\n", cfg.Name)
	return cfg, nil
}