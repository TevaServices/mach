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
// {"sealed_b64": "<ciphertext>"} when E2E is on; the inner cleartext is the
// ExecCommand / ExecResult JSON. Crypto: X25519 + ChaCha20-Poly1305 with a
// fresh ephemeral sender key per message (seal-box style), and the AEAD key
// derived with HKDF rather than taken from the raw Diffie-Hellman output.
//
// SealedMessage.V is the format version and this build speaks 2. Version 1 used
// the raw shared secret as the AEAD key with no domain separation; a v1 message
// against this code fails with "unsupported sealed message version" rather than
// being quietly accepted, which is what makes an upgrade skew legible instead of
// mysterious. The machine's key is unchanged by that: only the derivation is.
package e2e

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
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
	// X25519 clamps the scalar internally, so the base multiplication below is
	// the whole derivation.
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

// sealedVersion is the format this build speaks. Bump it when the derivation or
// the envelope changes: the check on the way in is the only thing that turns
// "half the fleet was updated" into an explicit error.
const sealedVersion = 2

// SealedMessage is the JSON envelope payload for an encrypted frame.
type SealedMessage struct {
	V    int    `json:"v"`    // crypto version, sealedVersion
	Eph  string `json:"eph"`  // base64 sender ephemeral X25519 pubkey
	Body string `json:"body"` // base64 ChaCha20-Poly1305 sealed box
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
	key, err := deriveKey(shared, recipientPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
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
		V:    sealedVersion,
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
	if msg.V != sealedVersion {
		return nil, versionErr(msg.V)
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
	// The recipient is us here, so the binding uses our own public key — the same
	// value the sender passed to Seal.
	ownPub, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, ownPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, ephPub)
}

// deriveKey turns a Diffie-Hellman shared secret into an AEAD key.
//
// The shared secret is a curve point's x-coordinate, not a uniformly random
// string, so it is not used as a key directly: HKDF is how you get key material
// out of a DH output, and it is also where the recipient's identity goes in. The
// info string binds the version and the recipient's public key, so a ciphertext
// sealed for one machine cannot be opened as if it had been addressed to
// another, and a future format cannot be confused with this one.
func deriveKey(shared, recipientPub []byte) ([]byte, error) {
	info := make([]byte, 0, len(domainSep)+len(recipientPub))
	info = append(info, domainSep...)
	info = append(info, recipientPub...)
	return hkdf.Key(sha256.New, shared, nil, string(info), chacha20poly1305.KeySize)
}

const domainSep = "mach-e2e-v2|"

// versionErr names both versions, because the only way to see one is an upgrade
// that has reached one end and not the other.
func versionErr(got int) error {
	return simpleErr("e2e: unsupported sealed message version " + itoa(got) +
		" (this build speaks " + itoa(sealedVersion) + ") — update the other end")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }

const (
	errShortKey  = simpleErr("e2e: recipient key must be 32 bytes")
	errVersion   = simpleErr("e2e: unsupported sealed message version")
	errBadEph    = simpleErr("e2e: bad ephemeral key")
	errShortBody = simpleErr("e2e: sealed body too short")
)
