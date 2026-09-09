package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
)

// loadOrCreateServerKey ensures the control plane has a stable identity
// keypair (agents pin its public key at enrollment and verify it on
// updates/connections via TLS + this key for signed update manifests).
// Key material lives at keyPath (persistent volume), 0600.
func (s *Server) loadOrCreateServerKey(keyPath string) {
	if keyPath == "" {
		keyPath = "/data/server.key"
	}
	raw, err := os.ReadFile(keyPath)
	if err == nil {
		if b, derr := hex.DecodeString(string(raw)); derr == nil && len(b) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(b)
			pub, _ := priv.Public().(ed25519.PublicKey)
			s.serverPriv = priv
			s.serverKeyHex = hex.EncodeToString(pub)
			return
		}
	}
	// First boot (or corrupt): generate and persist.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("server key generation: " + err.Error())
	}
	_ = os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)), 0o600)
	pub, _ := priv.Public().(ed25519.PublicKey)
	s.serverPriv = priv
	s.serverKeyHex = hex.EncodeToString(pub)
}