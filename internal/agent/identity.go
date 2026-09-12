// Package agent implements the mach agent: enrollment (QR or API key), the
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

// NewIdentity generates an agent keypair that exists only in memory.
//
// Used by the temporary session (bare `mach`), whose whole point is that nothing
// outlives the process: the key is never written, so running again enrolls
// again. The persistent path keeps using LoadOrCreate, which does write one.
func NewIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{Priv: priv, PubHex: hex.EncodeToString(pub)}, nil
}

// NewE2EKeyPair generates an X25519 keypair that exists only in memory, for the
// same reason. Kept here beside NewIdentity so the two in-memory constructors
// are read together.
func NewE2EKeyPair() (*E2EKeyPair, error) { return generateE2EKeyPair() }

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
	// The 0600 guarantee normally holds from first-run creation, but a
	// manual copy or backup restore can leave the key loose: tighten it.
	if st, serr := os.Stat(keyPath); serr == nil && st.Mode().Perm() != 0o600 {
		_ = os.Chmod(keyPath, 0o600)
	}
	b, err := hex.DecodeString(string(raw))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("corrupt agent key at " + keyPath + " — delete it and re-enroll")
	}
	priv := ed25519.PrivateKey(b)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &Identity{Priv: priv, PubHex: hex.EncodeToString(pub)}, nil
}
