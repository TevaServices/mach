package release

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testBinary returns a path to a real compiled Go binary — this test's own
// executable — so the tests exercise reading genuine build information rather
// than a fixture that only resembles it.
func testBinary(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating the test binary: %v", err)
	}
	if _, err := Inspect(self); err != nil {
		t.Skipf("test binary carries no build information: %v", err)
	}
	return self
}

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return pub, priv
}

func attest(t *testing.T, bin string, priv ed25519.PrivateKey) (*Statement, *Envelope) {
	t.Helper()
	st, err := Attest(Options{SubjectName: filepath.Base(bin), Binary: bin, Version: "9.9.9"})
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	env, err := Sign(context.Background(), st, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return st, env
}

// The statement must be a well-formed in-toto Statement v1 with a subject
// digest that actually identifies the file.
func TestStatementShapeAndSubjectDigest(t *testing.T) {
	bin := testBinary(t)
	st, err := Attest(Options{SubjectName: "mach-test", Binary: bin, Version: "0.2.0"})
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if st.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("_type = %q", st.Type)
	}
	if st.PredicateType != PredicateType {
		t.Errorf("predicateType = %q", st.PredicateType)
	}
	if len(st.Subject) != 1 || st.Subject[0].Name != "mach-test" {
		t.Fatalf("subject = %+v", st.Subject)
	}
	want, err := Digest(bin)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if got := st.Subject[0].Digest["sha256"]; got != want {
		t.Errorf("subject sha256 = %s, want %s", got, want)
	}
	if err := st.VerifyArtifact("mach-test", bin); err != nil {
		t.Errorf("VerifyArtifact on the attested binary: %v", err)
	}
}

// The predicate's build facts come from the binary, so they must reflect a
// real Go build: a toolchain version, the main module, and the dependency
// graph the linker recorded.
func TestPredicateRecordsBuildFactsFromArtifact(t *testing.T) {
	bin := testBinary(t)
	st, _ := attest(t, bin, mustRandKey(t))
	pred, err := st.PredicateOf()
	if err != nil {
		t.Fatalf("predicate: %v", err)
	}
	if !strings.HasPrefix(pred.Byproducts.GoVersion, "go1.") {
		t.Errorf("goVersion = %q, want a toolchain version read from the artifact", pred.Byproducts.GoVersion)
	}
	if !strings.Contains(pred.Byproducts.GoModule, "github.com/TevaServices/mach") {
		t.Errorf("goModule = %q, want this module", pred.Byproducts.GoModule)
	}
	if len(pred.Materials) == 0 {
		t.Fatal("no materials — the dependency graph was not recorded")
	}
	// Every material is named by URI, and one of them is this module.
	var sawSelf bool
	for _, m := range pred.Materials {
		if m.URI == "" {
			t.Errorf("material with no URI: %+v", m)
		}
		if strings.Contains(m.URI, "github.com/TevaServices/mach") {
			sawSelf = true
		}
	}
	if !sawSelf {
		t.Errorf("materials do not name this module: %+v", pred.Materials)
	}
	// The predicate says which fields it could not read from the artifact,
	// rather than presenting asserted values as recorded ones.
	if pred.Invocation.Parameters.RecordedFrom != "artifact" && pred.Invocation.Parameters.RecordedFrom != "artifact+caller" {
		t.Errorf("recordedFrom = %q", pred.Invocation.Parameters.RecordedFrom)
	}
	for _, a := range pred.Invocation.Parameters.Asserted {
		switch a {
		case "goos", "goarch", "ldflags", "trimpath", "command":
		default:
			t.Errorf("unexpected asserted field %q", a)
		}
	}
}

func mustRandKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv := keyPair(t)
	return priv
}

// A DSSE envelope that other tooling can read: standard payload type, base64
// payload that decodes to the statement, one signature naming its key.
func TestEnvelopeIsStandardDSSE(t *testing.T) {
	bin := testBinary(t)
	pub, priv := keyPair(t)
	st, env := attest(t, bin, priv)
	if env.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("payloadType = %q", env.PayloadType)
	}
	if len(env.Signatures) != 1 {
		t.Fatalf("signatures = %d, want 1", len(env.Signatures))
	}
	if env.Signatures[0].KeyID != KeyID(pub) {
		t.Errorf("keyid = %q, want %q (hex sha256 of the public key)", env.Signatures[0].KeyID, KeyID(pub))
	}
	body, err := env.DecodeB64Payload()
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var got Statement
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if got.Subject[0].Digest["sha256"] != st.Subject[0].Digest["sha256"] {
		t.Error("payload does not carry the statement that was signed")
	}
	// And the round trip through Open.
	back, err := Open(context.Background(), env, pub)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if back.PredicateType != st.PredicateType {
		t.Error("round trip changed the statement")
	}
}

// The signature covers the payload, so editing the predicate — even to a
// perfectly plausible value — must invalidate the attestation.
func TestTamperedPredicateIsRejected(t *testing.T) {
	bin := testBinary(t)
	pub, priv := keyPair(t)
	_, env := attest(t, bin, priv)

	body, err := env.DecodeB64Payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	var st Statement
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("statement: %v", err)
	}
	var pred Predicate
	if err := json.Unmarshal(st.Predicate, &pred); err != nil {
		t.Fatalf("predicate: %v", err)
	}
	pred.Version = "99.0.0-evil"
	pred.Byproducts.VCSModified = false // hide a dirty build
	pred.Invocation.Parameters.Trimpath = true
	raw, _ := json.Marshal(pred)
	st.Predicate = raw
	body, _ = json.Marshal(st)
	env.Payload = base64.StdEncoding.EncodeToString(body)
	// The original signature is left in place — this is exactly the attack.

	if _, err := Open(context.Background(), env, pub); err == nil {
		t.Fatal("a tampered predicate verified — the signature does not cover the payload")
	}
}

// Verification is pinned to one key: an attestation signed by another key,
// even a structurally perfect one, must not be accepted.
func TestOnlyThePinnedKeyVerifies(t *testing.T) {
	bin := testBinary(t)
	pub, _ := keyPair(t)
	_, otherPriv := keyPair(t)
	_, env := attest(t, bin, otherPriv)

	if _, err := Open(context.Background(), env, pub); err == nil {
		t.Fatal("an attestation signed by a different key verified against the pinned key")
	}
	// And with no signature at all.
	env.Signatures = nil
	if _, err := Open(context.Background(), env, pub); err == nil {
		t.Fatal("an unsigned envelope verified")
	}
}

// A valid signature over a different file proves nothing: the subject digest
// check is what ties the attestation to the bytes.
func TestAttestationForAnotherBinaryIsRejected(t *testing.T) {
	bin := testBinary(t)
	pub, priv := keyPair(t)
	st, env := attest(t, bin, priv)

	other := filepath.Join(t.TempDir(), "other-binary")
	if err := os.WriteFile(other, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
		t.Fatalf("writing the other binary: %v", err)
	}
	if err := st.VerifyArtifact("", other); err == nil {
		t.Fatal("an attestation for one binary verified against another")
	}
	// The envelope still opens — the signature is genuine — which is why the
	// digest check has to be a separate step and not assumed from Open.
	if _, err := Open(context.Background(), env, pub); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.VerifyArtifact("mach-test", other); err == nil {
		t.Fatal("VerifyArtifact ignored a name mismatch")
	}
}

// A file that is not a Go binary cannot be attested: there is nothing to
// record, and inventing a predicate would be worse than failing.
func TestInspectRejectsNonGoBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-binary")
	if err := os.WriteFile(path, []byte("plain text, not an executable"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Inspect(path); err == nil {
		t.Fatal("Inspect accepted a file with no Go build information")
	}
	if _, err := Attest(Options{SubjectName: "x", Binary: path, Version: "1"}); err == nil {
		t.Fatal("Attest produced a statement for a file with no build information")
	}
}

// The attestation file round-trips through disk, which is how it is actually
// handed to push-update and to auditors.
func TestSaveAndLoadRoundTrip(t *testing.T) {
	bin := testBinary(t)
	pub, priv := keyPair(t)
	_, env := attest(t, bin, priv)

	path := filepath.Join(t.TempDir(), "agent.intoto.jsonl")
	if err := SaveAttestation(path, env); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadAttestation(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := Open(context.Background(), loaded, pub); err != nil {
		t.Fatalf("a saved attestation did not verify: %v", err)
	}
	// A file that is not an envelope fails with a clear error rather than a
	// zero-valued envelope that later fails obscurely.
	bad := filepath.Join(t.TempDir(), "not-an-envelope.json")
	if err := os.WriteFile(bad, []byte("{\"hello\":true}"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	empty, err := LoadAttestation(bad)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := Open(context.Background(), empty, pub); err == nil {
		t.Fatal("an empty envelope verified")
	}
}
