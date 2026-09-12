package e2e

import (
	"bytes"
	"testing"
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
