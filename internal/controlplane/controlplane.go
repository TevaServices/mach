// Package controlplane runs the mach server and admin commands for the
// mach-server container binary (deliberately separate from the mach
// remote-connection binary).
package controlplane

import (
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
	"github.com/bcross/mach/internal/server"
	"github.com/bcross/mach/internal/store"
)

// Version matches the agent's version string for now.
var Version = "0.2.0"

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
	// trivially slowloris'd. (ReadTimeout/WriteTimeout stay unset — console
	// exec requests legitimately block for up to ~10 minutes.)
	srvHTTP := &http.Server{
		Addr:              listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srvHTTP.ListenAndServe(); err != nil {
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
func PushUpdate(machine, binPath, version string) error {
	bin, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("reading agent binary: %w", err)
	}
	sum := sha256.Sum256(bin)
	manifest := updateManifest{
		Version: version,
		Sha256:  hex.EncodeToString(sum[:]),
		DataB64: base64.StdEncoding.EncodeToString(bin),
	}
	priv, err := loadServerPriv()
	if err != nil {
		return err
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
