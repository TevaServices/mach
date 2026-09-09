// Package agent implements machd: enrollment (QR or API key), the
// outbound-only daemon connection, and command execution.
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// Identity is the agent's long-term per-machine keypair. The private key
// never leaves the machine; the control plane stores only the public key.
type Identity struct {
	Priv   ed25519.PrivateKey
	PubHex string
}

// StateDir returns the default state directory: /var/lib/mach for root,
// ~/.mach otherwise (override with MACH_STATE_DIR).
func StateDir() string {
	if v := os.Getenv("MACH_STATE_DIR"); v != "" {
		return v
	}
	if os.Geteuid() == 0 {
		return "/var/lib/mach"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".mach"
	}
	return filepath.Join(home, ".mach")
}

// LoadOrCreate reads (or first-run creates) the agent keypair in stateDir.
func LoadOrCreate(stateDir string) (*Identity, error) {
	keyPath := filepath.Join(stateDir, "agent.key")
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return nil, err
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
			return nil, err
		}
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(string(raw))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("corrupt agent key at " + keyPath + " — delete it and re-enroll")
	}
	priv := ed25519.PrivateKey(b)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &Identity{Priv: priv, PubHex: hex.EncodeToString(pub)}, nil
}