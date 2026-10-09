package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TevaServices/mach/internal/release"
)

// setup points the control plane's paths at a temp dir and installs a fresh
// identity key, which is what signs attestation envelopes.
func setup(t *testing.T) (priv ed25519.PrivateKey, bin string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MACH_DB", filepath.Join(dir, "mach.db"))
	t.Setenv("MACH_SERVER_KEY", filepath.Join(dir, "mach.db.key"))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := os.WriteFile(serverKeyPath(), []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		t.Fatalf("writing the identity key: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("test binary: %v", err)
	}
	if _, err := release.Inspect(self); err != nil {
		t.Skipf("test binary carries no build information: %v", err)
	}
	return priv, self
}

// The two commands are a round trip: what attest writes, verify-attestation
// accepts — and it accepts it only for the binary that was attested.
func TestAttestThenVerify(t *testing.T) {
	_, bin := setup(t)
	att := bin + ".intoto.jsonl"
	if err := Attest(bin, "1.2.3", att); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if err := VerifyAttestation(att, bin); err != nil {
		t.Fatalf("verify-attestation on the attested binary: %v", err)
	}

	// A different file with the same attestation must be rejected: the
	// signature is fine, the bytes are not.
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("not the same bytes"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := VerifyAttestation(att, other); err == nil {
		t.Fatal("verify-attestation accepted a binary the attestation does not describe")
	}
}

// Attest must refuse rather than produce a statement it cannot back up.
func TestAttestNeedsAVersionAndABuild(t *testing.T) {
	_, bin := setup(t)
	if err := Attest(bin, "", ""); err == nil {
		t.Error("attest with no version succeeded")
	}
	plain := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(plain, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := Attest(plain, "1.0.0", ""); err == nil {
		t.Error("attest of a non-Go file succeeded")
	}
}

// A statement signed by a key other than this control plane's is rejected even
// though it is structurally valid — the pin is the whole point.
func TestVerifyRejectsForeignSignature(t *testing.T) {
	_, bin := setup(t)
	st, err := release.Attest(release.Options{SubjectName: filepath.Base(bin), Binary: bin, Version: "1.2.3"})
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	env, err := release.Sign(context.Background(), st, otherPriv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := filepath.Join(t.TempDir(), "foreign.intoto.jsonl")
	if err := release.SaveAttestation(path, env); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := VerifyAttestation(path, bin); err == nil {
		t.Fatal("verify-attestation accepted an attestation signed by another key")
	}
}

// The identity key's path is derived from the database path, which only means
// something as a FILE. With a Postgres DSN, appending ".key" produced a path that
// is not a path — scheme, host and password included — so attest and
// verify-attestation could not find the key at all, and the error printed the DSN
// (password and all) into whatever collected it. There is nowhere near a DSN to
// put a key, so the command asks rather than invents one.
func TestServerKeyPathWithAPostgresDSN(t *testing.T) {
	const dsn = "postgres://user:s3cretpw@db.internal:5432/mach"

	t.Setenv("MACH_DB", dsn)
	t.Setenv("MACH_SERVER_KEY", "")
	path, err := requireServerKeyPath()
	if err == nil {
		t.Fatalf("a DSN with no MACH_SERVER_KEY was given the path %q", path)
	}
	if strings.Contains(err.Error(), "s3cretpw") {
		t.Errorf("the DSN, password included, leaked into the error: %v", err)
	}
	if !strings.Contains(err.Error(), "MACH_SERVER_KEY") {
		t.Errorf("the error does not name the variable to set: %v", err)
	}

	// Set explicitly, it is used verbatim — the DSN is not consulted at all.
	t.Setenv("MACH_SERVER_KEY", "/keys/mach.key")
	path, err = requireServerKeyPath()
	if err != nil || path != "/keys/mach.key" {
		t.Fatalf("explicit key path = %q (%v)", path, err)
	}

	// A SQLite path keeps the documented default, which is what the container
	// relies on.
	t.Setenv("MACH_DB", "/data/mach.db")
	t.Setenv("MACH_SERVER_KEY", "")
	path, err = requireServerKeyPath()
	if err != nil || path != "/data/mach.db.key" {
		t.Fatalf("sqlite key path = %q (%v), want /data/mach.db.key", path, err)
	}
}

// A statement whose signature and subject verify but whose predicate will not
// decode used to sail past BOTH checks — they were written `err == nil &&`,
// so an unreadable predicate silently skipped the version match and, worse,
// the modified-tree refusal. That refusal is what stops a build from someone's
// working copy reaching a fleet, and only the key holder can produce such an
// envelope, which is exactly why it should be a hard error rather than a
// conditional one.
func TestVerifyRefusesAnUnreadablePredicate(t *testing.T) {
	priv, bin := setup(t)

	st, err := release.Attest(release.Options{
		SubjectName: filepath.Base(bin), Binary: bin, Version: "1.2.3", Started: time.Now(),
	})
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	// The subject still describes these bytes and the envelope is still signed
	// by this control plane's own key: only the predicate is unreadable.
	st.Predicate = json.RawMessage(`"this is not an in-toto predicate"`)
	env, err := release.Sign(context.Background(), st, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	att := filepath.Join(t.TempDir(), "bogus.intoto.jsonl")
	if err := release.SaveAttestation(att, env); err != nil {
		t.Fatalf("save: %v", err)
	}

	verr := VerifyAttestation(att, bin)
	if verr == nil {
		t.Fatal("verify-attestation accepted an attestation whose predicate could not be read")
	}
	if !strings.Contains(verr.Error(), "predicate") {
		t.Fatalf("the refusal does not name the predicate: %v", verr)
	}
}

// A literal `*` as an allowlist entry is refused at mint time.
//
// `exec:web|*` is always a typo for `exec:*`: no machine is named `*`, so the
// key could exec on nothing real — while the control plane's admin check read
// the entry as "all machines" and handed it block, revoke and delete over the
// whole fleet. Refusing it here means an operator gets an error rather than a
// key that does nothing they meant and something they did not.
func TestAddAPIKeyRefusesALiteralStarEntry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MACH_DB", filepath.Join(dir, "mach.db"))
	t.Setenv("MACH_SERVER_KEY", filepath.Join(dir, "mach.db.key"))

	for _, scopes := range []string{"exec:web|*", "exec:*|web", "exec:* | web"} {
		if _, _, _, _, err := AddAPIKey("k", scopes, ""); err == nil {
			t.Errorf("AddAPIKey(%q) was accepted", scopes)
		}
	}
	// The forms that mean what they say still mint.
	for _, scopes := range []string{"exec:*", "exec:web|db-1", "readonly", "enroll"} {
		if _, _, _, _, err := AddAPIKey("k", scopes, ""); err != nil {
			t.Errorf("AddAPIKey(%q) was refused: %v", scopes, err)
		}
	}
}
