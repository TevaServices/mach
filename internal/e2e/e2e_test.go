package e2e

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestSealOpenRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte(`{"command":"echo secret-thing","timeout":30}`)
	sealed, err := Seal(kp.Public[:], msg)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Ciphertext must not contain the plaintext.
	if bytes.Contains(sealed, []byte("secret-thing")) {
		t.Fatal("plaintext leaked into sealed payload")
	}
	opened, err := Open(&kp.Private, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, msg) {
		t.Fatalf("round trip mismatch: %q", opened)
	}
}

func TestSealRejectsWrongKey(t *testing.T) {
	kp, _ := GenerateKeyPair()
	other, _ := GenerateKeyPair()
	sealed, err := Seal(kp.Public[:], []byte("x"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(&other.Private, sealed); err == nil {
		t.Fatal("wrong key opened the message")
	}
}

func TestSealFreshEphermalPerMessage(t *testing.T) {
	kp, _ := GenerateKeyPair()
	a, _ := Seal(kp.Public[:], []byte("same"))
	b, _ := Seal(kp.Public[:], []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("ephemeral key reused across messages")
	}
}

func TestOpenRejectsTamperedBody(t *testing.T) {
	kp, _ := GenerateKeyPair()
	sealed, _ := Seal(kp.Public[:], []byte("hello"))
	// Flip a payload byte (past nonce).
	sealed[len(sealed)-3] ^= 0xFF
	if _, err := Open(&kp.Private, sealed); err == nil {
		t.Fatal("tampered body opened successfully")
	}
}

func TestSealRejectsShortKey(t *testing.T) {
	if _, err := Seal([]byte{1, 2, 3}, []byte("x")); err == nil {
		t.Fatal("short key accepted")
	}
}

// The format version is checked on the way in, so an upgrade that has reached one
// end and not the other is an explicit error instead of a decryption failure that
// looks like a wrong key.
func TestOpenRejectsAnotherFormatVersion(t *testing.T) {
	kp, _ := GenerateKeyPair()
	sealed, err := Seal(kp.Public[:], []byte("hello"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var msg SealedMessage
	if err := json.Unmarshal(sealed, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg.V != sealedVersion {
		t.Fatalf("version sealed = %d, want %d", msg.V, sealedVersion)
	}
	// The version 1 format: same envelope, no derived key. A build that speaks 1
	// must get an error naming both versions, not a confusing AEAD failure.
	msg.V = 1
	old, _ := json.Marshal(msg)
	_, err = Open(&kp.Private, old)
	if err == nil {
		t.Fatal("a v1 message was accepted by a v2 build")
	}
	if !strings.Contains(err.Error(), "unsupported sealed message version 1") ||
		!strings.Contains(err.Error(), "speaks 2") {
		t.Errorf("error = %q, want it to name both versions", err)
	}
}

// The AEAD key is derived with the recipient's public key bound in, so the same
// Diffie-Hellman secret addressed to two different machines yields two different
// keys — a ciphertext cannot be re-pointed at another recipient.
func TestDerivedKeyIsBoundToTheRecipient(t *testing.T) {
	shared := bytes.Repeat([]byte{0x5a}, 32)
	a, err := deriveKey(shared, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	b, err := deriveKey(shared, bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("the derived key does not depend on the recipient")
	}
	if len(a) != chacha20poly1305.KeySize {
		t.Errorf("key length = %d, want %d", len(a), chacha20poly1305.KeySize)
	}
	// Deterministic: both ends derive the same key from the same inputs, or
	// nothing would ever open.
	again, _ := deriveKey(shared, bytes.Repeat([]byte{1}, 32))
	if !bytes.Equal(a, again) {
		t.Error("key derivation is not deterministic")
	}
	// And the raw shared secret is not the key.
	if bytes.Equal(a, shared) {
		t.Error("the derived key is the raw shared secret")
	}
}
