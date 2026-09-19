package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// loadOrCreateServerKey ensures the control plane has a stable identity
// keypair (agents pin its public key at enrollment and verify it on
// updates/connections via TLS + this key for signed update manifests).
// Key material lives at keyPath (persistent volume), 0600. Persisting is
// mandatory: a key that lives only in memory rotates on every restart and
// silently breaks every enrolled agent's pin, so write failures abort boot.
//
// "First boot" and "cannot read my key" are different answers, and only the
// first may mint a replacement. Reading any error as "no key yet" meant an
// EACCES or an I/O fault booted a *different* identity, and the failure then
// presented as an unexplained fleet-wide lockout: every agent fails closed on
// the pin and refuses to connect, which is the correct behaviour and a
// miserable thing to diagnose from. A corrupt file is refused for the same
// reason — it is the operator's key, and replacing it should take deleting it.
func (s *Server) loadOrCreateServerKey(keyPath string) error {
	if keyPath == "" {
		keyPath = "/data/server.key"
	}
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		return s.createServerKey(keyPath)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading the control-plane identity key %s: %w "+
			"(refusing to start rather than booting a different identity and locking out every enrolled agent)", keyPath, err)
	}
	// The 0600 guarantee normally holds from creation, but a volume restored
	// from a backup can leave it loose — the same tightening the agent's own
	// identity key does on load.
	if st, serr := os.Stat(keyPath); serr == nil && st.Mode().Perm() != 0o600 {
		_ = os.Chmod(keyPath, 0o600)
	}
	b, derr := hex.DecodeString(string(raw))
	if derr != nil || len(b) != ed25519.PrivateKeySize {
		return fmt.Errorf("corrupt control-plane identity key at %s — agents pin this key, so it cannot be "+
			"replaced silently; move it aside deliberately if that is what you mean", keyPath)
	}
	priv := ed25519.PrivateKey(b)
	pub, _ := priv.Public().(ed25519.PublicKey)
	s.serverPriv = priv
	s.serverKeyHex = hex.EncodeToString(pub)
	return nil
}

// createServerKey mints and persists a fresh identity key. Only ever reached
// when there is no key file at all.
func (s *Server) createServerKey(keyPath string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return fmt.Errorf("persisting %s: %w", keyPath, err)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	s.serverPriv = priv
	s.serverKeyHex = hex.EncodeToString(pub)
	return nil
}
