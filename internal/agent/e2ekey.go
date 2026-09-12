package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

// e2ePubFromPriv derives the X25519 public key from a private key.
func e2ePubFromPriv(priv *[32]byte) ([]byte, error) {
	return curve25519.X25519(priv[:], curve25519.Basepoint)
}

// E2EKeyPair is the agent's X25519 keypair for end-to-end encrypted exec.
// Public half is registered at enrollment; the private half never leaves
// the machine.
type E2EKeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// LoadOrCreateE2EKey reads (or creates) the agent's E2E X25519 keypair in
// stateDir. Mirrors agent identity key handling (0600 file).
func LoadOrCreateE2EKey(stateDir string) (*E2EKeyPair, error) {
	keyPath := filepath.Join(stateDir, "e2e.key")
	if raw, err := os.ReadFile(keyPath); err == nil {
		b, derr := hex.DecodeString(string(raw))
		if derr != nil || len(b) != 32 {
			return nil, errors.New("corrupt e2e key at " + keyPath + " — delete it and re-enroll")
		}
		kp := &E2EKeyPair{}
		copy(kp.Private[:], b)
		if err := kp.derivePublic(); err != nil {
			return nil, err
		}
		return kp, nil
	}
	kp, err := generateE2EKeyPair()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(kp.Private[:])), 0o600); err != nil {
		return nil, err
	}
	return kp, nil
}

func (kp *E2EKeyPair) derivePublic() error {
	pub, err := e2ePubFromPriv(&kp.Private)
	if err != nil {
		return err
	}
	copy(kp.Public[:], pub)
	return nil
}

// PublicKeyHex returns the hex-encoded public half.
func (kp *E2EKeyPair) PublicKeyHex() string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, b := range kp.Public {
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

func generateE2EKeyPair() (*E2EKeyPair, error) {
	kp := &E2EKeyPair{}
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, err
	}
	if err := kp.derivePublic(); err != nil {
		return nil, err
	}
	return kp, nil
}
