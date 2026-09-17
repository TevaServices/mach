// Package controlplane runs the mach server and admin commands for the
// mach-server container binary (deliberately separate from the mach
// remote-connection binary).
package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bcross/mach/internal/broker"
	"github.com/bcross/mach/internal/release"
	"github.com/bcross/mach/internal/server"
	"github.com/bcross/mach/internal/store"
)

func dbPath() string {
	if v := os.Getenv("MACH_DB"); v != "" {
		return v
	}
	return "/data/mach.db"
}

func openStore() (*store.Store, error) {
	return store.Open(dbPath())
}

// Org returns the configured org prefix for machine names.
func Org() string {
	if v := os.Getenv("MACH_ORG"); v != "" {
		return v
	}
	return "mach"
}

func serverKeyPath() string {
	if v := os.Getenv("MACH_SERVER_KEY"); v != "" {
		return v
	}
	return dbPath() + ".key"
}

func newServer(st *store.Store, br *broker.Broker) *server.Server {
	srv := server.New(st, br, Org(), serverKeyPath())
	if os.Getenv("MACH_TRUST_PROXY") == "1" {
		// Only behind the known TLS reverse proxy (Caddy/nginx) — enables
		// X-Forwarded-For for rate limiting. Off by default.
		srv.SetTrustProxy(true)
	}
	return srv
}

// Serve runs the control plane (container entrypoint / `mach-server serve`).
func Serve() {
	listen := os.Getenv("MACH_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	pubURL := os.Getenv("MACH_PUBLIC_URL")
	if pubURL == "" {
		log.Fatal("mach-server: MACH_PUBLIC_URL is required (e.g. https://mach.example.com)")
	}
	st, err := openStore()
	if err != nil {
		log.Fatalf("mach-server: open store: %v", err)
	}
	defer st.Close()
	srv := newServer(st, broker.New())
	log.Printf("mach control plane listening on %s (public URL %s, org %q, trust-proxy %v)",
		listen, pubURL, Org(), os.Getenv("MACH_TRUST_PROXY") == "1")
	// Explicit timeouts: without a ReadHeaderTimeout the public listener is
	// trivially slowloris'd.
	//
	// ReadTimeout bounds reading a request (headers plus body — every endpoint
	// takes a small JSON or form body, so 30s is generous even on a phone).
	// WriteTimeout stays UNSET on purpose: a streamed exec response can
	// legitimately last as long as the command's timeout. What bounds a slow
	// or stalled reader instead is a per-write deadline on the streaming
	// handler (relayExec, execWriteTimeout), which is strictly better than a
	// whole-response timeout — it lets a slow-but-alive console finish, and
	// drops one that has stopped reading.
	srvHTTP := &http.Server{
		Addr:              listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// The server owns background work (the housekeeping goroutine), so stopping it
	// is part of shutting down rather than something to leave to process exit.
	// Closed explicitly rather than by defer: this blocks for the process's
	// lifetime, and log.Fatal below exits without running deferred calls.
	err = srvHTTP.ListenAndServe()
	srv.Close()
	if err != nil {
		log.Fatal(err)
	}
}

// AddAPIKey creates a key with a server-generated high-entropy secret.
// Returns the generated key (shown ONCE).
func AddAPIKey(name, scopes string) (string, error) {
	st, err := openStore()
	if err != nil {
		return "", err
	}
	defer st.Close()
	switch strings.TrimSpace(scopes) {
	case "enroll":
		scopes = "enroll"
	case "readonly":
		scopes = "readonly"
	case "*", "all", "admin", "exec":
		scopes = "exec:*"
	default:
		// allowlist form: exec:m1|m2|m3 (per-machine)
		if !strings.HasPrefix(scopes, "exec:") {
			return "", fmt.Errorf("scopes must be one of: enroll | readonly | exec:* | exec:<m1>|<m2>")
		}
		// An empty allowlist would create a key that can never exec; that
		// is always a mistake (usually a truncated machine list).
		if strings.TrimSpace(strings.TrimPrefix(scopes, "exec:")) == "" {
			return "", fmt.Errorf("exec: allowlist is empty — list machines (exec:<m1>|<m2>) or use exec:*")
		}
	}
	key := "mach_" + store.RandToken(24) // 192-bit server-generated secret
	if err := st.CreateAPIKey(strings.ToLower(strings.TrimSpace(name)), key, scopes); err != nil {
		return "", err
	}
	return key, nil
}

// E2E reports or changes the control plane's end-to-end-encryption setting:
// whether it accepts sealed (E2E) exec commands, per org.
//
//	set is "" (report only), "on", "off", or "inherit" (drop an org's override
//	so it follows the default again). org is "" for the default row.
//
// It writes the same rows the running server reads, and reports the same
// effective values the server will use, so the command cannot describe a
// posture the control plane does not actually hold — including when MACH_E2E is
// set and therefore overrides whatever was just written.
func E2E(set, org string) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()

	if org != "" && !validOrgLabel(org) {
		return fmt.Errorf("%q is not a valid org label", org)
	}
	if set != "" && set != "inherit" && org == "" &&
		(strings.ToLower(strings.TrimSpace(set)) == "on" || strings.ToLower(strings.TrimSpace(set)) == "off") {
		fmt.Println("note: no --org given: this sets the default for every org without its own setting")
	}

	switch strings.ToLower(strings.TrimSpace(set)) {
	case "":
	case "inherit":
		if org == "" {
			return fmt.Errorf("inherit needs --org: there is nothing to inherit from for the default")
		}
		if err := server.ClearE2E(st, org); err != nil {
			return err
		}
		fmt.Printf("org %s: override removed; it follows the default again\n", org)
	case "on", "off":
		on := strings.ToLower(strings.TrimSpace(set)) == "on"
		if err := server.SetE2E(st, org, on); err != nil {
			return err
		}
		if org == "" {
			fmt.Printf("stored: sealed exec %s for every org without its own setting\n", set)
		} else {
			fmt.Printf("stored: sealed exec %s for org %s\n", set, org)
		}
	default:
		return fmt.Errorf("usage: mach-server e2e [on|off|inherit] [--org ORG] (got %q)", set)
	}

	printE2EReport(st, org)
	return nil
}

// printE2EReport prints the effective setting and where it came from. With an
// org, only that org; otherwise the default plus every org this shell knows
// about (MACH_ORG / MACH_ORGS) and every org with a stored override.
func printE2EReport(st *store.Store, org string) {
	if org != "" {
		mode, source := server.E2EMode(st, org)
		fmt.Printf("org %s: sealed exec %s (%s)\n", org, mode, source)
		explainE2E(mode)
		warnE2EOverride()
		return
	}

	defMode, defSource := server.E2EMode(st, "")
	fmt.Printf("default: sealed exec %s (%s)\n", defMode, defSource)

	// Configured orgs first, then any org with a stored override that this
	// shell's MACH_ORG/MACH_ORGS does not mention (the server may run with a
	// different environment than this command).
	seen := map[string]bool{}
	for _, o := range Orgs() {
		seen[o] = true
		mode, source := server.E2EMode(st, o)
		note := ""
		if mode == defMode {
			note = " (follows the default)"
		}
		fmt.Printf("org %s: sealed exec %s%s [%s]\n", o, mode, note, source)
	}
	if stored, err := server.StoredE2EOrgs(st); err == nil {
		for _, o := range stored {
			if seen[o] {
				continue
			}
			mode, _ := server.E2EMode(st, o)
			fmt.Printf("org %s: sealed exec %s (stored override; not in this shell's MACH_ORG/MACH_ORGS)\n", o, mode)
		}
	}
	explainE2E(defMode)
	warnE2EOverride()
}

func explainE2E(mode string) {
	if mode == "off" {
		fmt.Println("  sealed exec is refused (403, audited); commands run in plaintext, where")
		fmt.Println("  the fleet-wide block list can read them. Agent E2E keys are untouched, so")
		fmt.Println("  turning it back on restores sealing with no re-enrollment.")
		return
	}
	fmt.Println("  sealed exec is accepted; commands may be ciphertext the fleet-wide block")
	fmt.Println("  list cannot inspect. Turning it off stops sealing immediately.")
}

func warnE2EOverride() {
	if override := strings.TrimSpace(os.Getenv("MACH_E2E")); override != "" {
		fmt.Printf("  note: MACH_E2E=%s is set in this environment and overrides every org\n", override)
	}
}

// validOrgLabel mirrors the org half of store.ValidOrgName (2-20 label chars):
// the CLI should reject a typo before it writes a row nothing will ever read.
func validOrgLabel(org string) bool {
	if len(org) < 2 || len(org) > 20 {
		return false
	}
	for _, c := range org {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Orgs returns the org prefixes this environment configures: MACH_ORG first,
// then the comma-separated MACH_ORGS.
func Orgs() []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range []string{Org(), os.Getenv("MACH_ORGS")} {
		for _, o := range strings.Split(v, ",") {
			o = strings.ToLower(strings.TrimSpace(o))
			if o == "" || seen[o] {
				continue
			}
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}

// RevokeMachine marks a machine revoked so its agent self-retires.
func RevokeMachine(name string, purgeAudit bool) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.RevokeMachine(name); err != nil {
		return err
	}
	if purgeAudit {
		_ = st.RemoveMachineAudit(name)
	}
	fmt.Printf("machine %q revoked (its agent will retire on next connect attempt)\n", name)
	return nil
}

// DeleteMachine removes a machine row so its name and agent key can be used
// again. This is the recovery path for a revoked machine that has to
// re-enroll — the agent on that host must be stopped first, or it will keep
// retrying with a key the control plane no longer knows.
//
// The audit trail is kept unless purgeAudit is set: erasing a machine's
// command history is a separate decision from retiring the machine.
func DeleteMachine(name string, purgeAudit bool) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if m, err := st.MachineByName(name); err != nil {
		return err
	} else if m == nil {
		return fmt.Errorf("unknown machine %q", name)
	}
	if err := st.DeleteMachine(name); err != nil {
		return err
	}
	if purgeAudit {
		_ = st.RemoveMachineAudit(name)
		fmt.Printf("machine %q deleted, and its audit history purged\n", name)
	} else {
		fmt.Printf("machine %q deleted (audit history kept — use --purge-audit to erase it)\n", name)
	}
	fmt.Printf("its agent key is no longer known here; stop the agent on that host before re-enrolling\n")
	return nil
}

// updateManifest mirrors the wire struct without importing protocol here.
type updateManifest struct {
	Version string
	Sha256  string
	URL     string
	DataB64 string
}

// loadServerPriv returns the control plane's identity private key (for
// signing update manifests). Reads the persisted key file; errors surface
// through PushUpdate as a normal CLI error, not a panic.
func loadServerPriv() (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(serverKeyPath())
	if err != nil {
		return nil, fmt.Errorf("control plane key missing — run serve once first: %v", err)
	}
	b, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
	if derr != nil || len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("corrupt control plane key at %s", serverKeyPath())
	}
	return ed25519.PrivateKey(b), nil
}

// PushUpdate signs the manifest for a local agent binary and queues it for
// delivery on the machine's next live connection.
//
// When attestation is non-empty, the binary must be proved to be the one that
// attestation describes — same signature key, same sha256 — before it is
// queued. This is a release-pipeline gate rather than an agent-side control:
// the agent cannot check an attestation, because it does not receive one. What
// the agent already enforces (the pinned-key manifest signature over the
// sha256) is what protects the wire; the attestation is what makes the
// pipeline refuse to ship bytes no build recorded.
func PushUpdate(machine, binPath, version, attestation string) error {
	priv, err := loadServerPriv()
	if err != nil {
		return err
	}
	bin, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("reading agent binary: %w", err)
	}
	if len(bin) == 0 {
		return fmt.Errorf("agent binary %s is empty", binPath)
	}
	sum := sha256.Sum256(bin)
	sha := hex.EncodeToString(sum[:])

	if attestation != "" {
		env, err := release.LoadAttestation(attestation)
		if err != nil {
			return err
		}
		st, err := release.Open(context.Background(), env, priv.Public().(ed25519.PublicKey))
		if err != nil {
			return fmt.Errorf("attestation rejected: %w", err)
		}
		if err := st.VerifyArtifact("", binPath); err != nil {
			return fmt.Errorf("attestation does not describe this binary: %w", err)
		}
		pred, err := st.PredicateOf()
		if err == nil && pred.Version != version {
			return fmt.Errorf("attestation is for version %q but this push declares %q", pred.Version, version)
		}
		if err == nil && pred.Byproducts.VCSModified {
			return fmt.Errorf("attestation records a build from a modified tree — refusing to ship it; rebuild from a clean tree and re-attest")
		}
		fmt.Printf("attestation verified: %s describes %s (version %s)\n", attestation, binPath, version)
	}

	manifest := updateManifest{
		Version: version,
		Sha256:  sha,
		DataB64: base64.StdEncoding.EncodeToString(bin),
	}
	sig := ed25519.Sign(priv, []byte(manifest.Version+"|"+manifest.Sha256))
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.QueueUpdate(machine, manifest.Version, manifest.Sha256, manifest.URL, manifest.DataB64, base64.StdEncoding.EncodeToString(sig)); err != nil {
		return err
	}
	fmt.Printf("update v%s queued for %q (%d bytes, delivered on next connect; agent verifies signature + sha256 before applying)\n",
		version, machine, len(bin))
	return nil
}
