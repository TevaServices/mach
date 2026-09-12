package release

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// Envelope is a DSSE envelope carrying a signed in-toto Statement. The JSON
// shape is the library's, so the file on disk is readable by any DSSE tool:
//
//	{"payloadType":"application/vnd.in-toto+json",
//	 "payload":"<base64 statement>",
//	 "signatures":[{"keyid":"<hex sha256 of pubkey>","sig":"<base64>"}]}
type Envelope = dsse.Envelope

// keyed is the DSSE signer/verifier for one ed25519 key. Implementing the
// library's interfaces (rather than assembling the signature by hand) means
// the pre-authentication encoding is the library's PAE, not a local
// reimplementation of it — the part where a subtle mistake would be silent.
type keyed struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewSigner returns a DSSE signer over an ed25519 private key.
func NewSigner(priv ed25519.PrivateKey) dsse.Signer {
	return keyed{priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}

// NewVerifier returns a DSSE verifier that accepts signatures from exactly one
// public key — the control plane identity key a machine pinned at enrollment.
// Being pinned is the point: this verifies a name, not "some trusted key".
func NewVerifier(pub ed25519.PublicKey) dsse.Verifier {
	return keyed{pub: pub}
}

func (k keyed) Sign(_ context.Context, data []byte) ([]byte, error) {
	if len(k.priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("not an ed25519 private key")
	}
	return ed25519.Sign(k.priv, data), nil
}

func (k keyed) Verify(_ context.Context, data, sig []byte) error {
	if len(k.pub) != ed25519.PublicKeySize {
		return fmt.Errorf("not an ed25519 public key")
	}
	if !ed25519.Verify(k.pub, data, sig) {
		return fmt.Errorf("signature does not verify against the pinned key")
	}
	return nil
}

func (k keyed) KeyID() (string, error) {
	pub := k.pub
	if len(k.priv) == ed25519.PrivateKeySize {
		pub = k.priv.Public().(ed25519.PublicKey)
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("no ed25519 key")
	}
	return KeyID(pub), nil
}

func (k keyed) Public() crypto.PublicKey {
	if len(k.priv) == ed25519.PrivateKeySize {
		return k.priv.Public()
	}
	return k.pub
}

// Sign wraps a statement in a DSSE envelope signed by priv.
func Sign(ctx context.Context, st *Statement, priv ed25519.PrivateKey) (*Envelope, error) {
	body, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	es, err := dsse.NewEnvelopeSigner(NewSigner(priv))
	if err != nil {
		return nil, err
	}
	return es.SignPayload(ctx, PayloadType, body)
}

// Open verifies an envelope against pub and returns the statement it carries.
// Verification happens before the payload is parsed, so nothing parses
// attacker-controlled structure until the signature over it has been checked.
func Open(ctx context.Context, env *Envelope, pub ed25519.PublicKey) (*Statement, error) {
	if env == nil {
		return nil, fmt.Errorf("no attestation")
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("unexpected payload type %q (want %q)", env.PayloadType, PayloadType)
	}
	ev, err := dsse.NewEnvelopeVerifier(NewVerifier(pub))
	if err != nil {
		return nil, err
	}
	if _, err := ev.Verify(ctx, env); err != nil {
		return nil, fmt.Errorf("attestation signature: %w", err)
	}
	body, err := env.DecodeB64Payload()
	if err != nil {
		return nil, err
	}
	var st Statement
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("attestation payload is not an in-toto statement: %w", err)
	}
	if st.Type != StatementType {
		return nil, fmt.Errorf("attestation payload is %q, not an in-toto statement", st.Type)
	}
	return &st, nil
}

// LoadAttestation reads a DSSE envelope from a file.
func LoadAttestation(path string) (*Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%s is not a DSSE envelope: %w", path, err)
	}
	return &env, nil
}

// SaveAttestation writes a DSSE envelope, indented so a human can read the
// statement and diff two releases' attestations.
func SaveAttestation(path string, env *Envelope) error {
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
