// Package e2e provides end-to-end encryption for exec commands and
// results between consoles and agents. The control plane relays opaque
// ciphertext; it can see who ran something, when, and metadata (exit
// code, sizes) — but never the command text or output.
//
// Key hierarchy:
//   - Each agent generates an X25519 keypair at enrollment; the PUBLIC
//     half is registered with the control plane (agents already have an
//     ed25519 identity; the X25519 key is a separate DH key).
//   - Consoles fetch the target machine's X25519 public key from the
//     control plane, then seal each exec request to it.
//   - Agents reply sealed to the console's ephemeral public key.
//
// Wire shape: envelope types "exec" / "exec_result" carry payload
// {"sealed_b64": "<ciphertext>"} when E2E is on; the inner cleartext is
// the old ExecCommand / ExecResult JSON. Crypto: X25519 + ChaCha20-
// Poly1305, fresh ephemeral sender key per message (seal-box style).
package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// KeyPair is an X25519 static keypair (agent identity for E2E).
type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateKeyPair creates a fresh X25519 keypair.
func GenerateKeyPair() (*KeyPair, error) {
	var kp KeyPair
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, err
	}
	if _, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint); err != nil {
		return nil, err
	}
	// recompute properly below (clamped base mult)
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Public[:], pub)
	return &kp, nil
}

// PublicKeyHex returns the hex-encoded public half (64 chars).
func (kp *KeyPair) PublicKeyHex() string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, b := range kp.Public {
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

// SealedMessage is the JSON envelope payload for an encrypted frame.
type SealedMessage struct {
	V    int    `json:"v"`              // crypto version, 1
	Eph  string `json:"eph"`            // base64 sender ephemeral X25519 pubkey
	Body string `json:"body"`           // base64 ChaCha20-Poly1305 sealed box
}

// Seal encrypts plaintext to the recipient's X25519 public key using a
// fresh ephemeral sender key per message. Output marshals to JSON.
func Seal(recipientPub []byte, plaintext []byte) ([]byte, error) {
	if len(recipientPub) != 32 {
		return nil, errShortKey
	}
	var senderPriv [32]byte
	if _, err := rand.Read(senderPriv[:]); err != nil {
		return nil, err
	}
	senderPub, err := curve25519.X25519(senderPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(senderPriv[:], recipientPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(shared)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Additional data binds the sender's ephemeral pubkey so the ciphertext
	// cannot be re-attributed to another sender.
	sealed := aead.Seal(nil, nonce, plaintext, senderPub)
	msg := SealedMessage{
		V:    1,
		Eph:  base64.StdEncoding.EncodeToString(senderPub),
		Body: base64.StdEncoding.EncodeToString(append(nonce, sealed...)),
	}
	return json.Marshal(msg)
}

// Open decrypts a SealedMessage JSON with the recipient's X25519 private key.
func Open(privateKey *[32]byte, sealed []byte) ([]byte, error) {
	var msg SealedMessage
	if err := json.Unmarshal(sealed, &msg); err != nil {
		return nil, err
	}
	if msg.V != 1 {
		return nil, errVersion
	}
	ephPub, err := base64.StdEncoding.DecodeString(msg.Eph)
	if err != nil || len(ephPub) != 32 {
		return nil, errBadEph
	}
	body, err := base64.StdEncoding.DecodeString(msg.Body)
	if err != nil || len(body) < chacha20poly1305.NonceSize+16 {
		return nil, errShortBody
	}
	nonce, ct := body[:chacha20poly1305.NonceSize], body[chacha20poly1305.NonceSize:]
	shared, err := curve25519.X25519(privateKey[:], ephPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(shared)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, ephPub)
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }

const (
	errShortKey  = simpleErr("e2e: recipient key must be 32 bytes")
	errVersion   = simpleErr("e2e: unsupported sealed message version")
	errBadEph    = simpleErr("e2e: bad ephemeral key")
	errShortBody = simpleErr("e2e: sealed body too short")
)