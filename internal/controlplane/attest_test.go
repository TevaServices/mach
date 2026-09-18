package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bcross/mach/internal/release"
	"github.com/bcross/mach/internal/store"
)

// setup points the control plane's paths at a temp dir and installs a fresh
// identity key, which is what signs both attestations and update manifests.
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

func queued(t *testing.T, machine string) (sha string, ok bool) {
	t.Helper()
	st, err := store.Open(dbPath())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	_, sha, _, _, sig, ok, err := st.PopPendingUpdate(machine)
	if err != nil {
		t.Fatalf("pending update: %v", err)
	}
	if !ok {
		return "", false
	}
	// The signature must verify over the manifest exactly as the agent checks
	// it (see internal/agent handleUpdate) — otherwise a queued update would
	// be refused on arrival and the test would be asserting nothing.
	pub := privOf(t).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte("1.2.3|"+sha), mustB64(t, sig)) {
		t.Fatal("queued update is not signed by the control plane key")
	}
	return sha, true
}

func privOf(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	priv, err := loadServerPriv()
	if err != nil {
		t.Fatalf("loadServerPriv: %v", err)
	}
	return priv
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
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

// The gate that matters: with --attestation, a binary the attestation does not
// describe must not be queued for any machine at all.
func TestPushUpdateRefusesMismatchedAttestation(t *testing.T) {
	_, bin := setup(t)
	att := bin + ".intoto.jsonl"
	if err := Attest(bin, "1.2.3", att); err != nil {
		t.Fatalf("attest: %v", err)
	}

	// Swap the binary for different bytes, keeping the attestation.
	swapped := filepath.Join(t.TempDir(), "agent")
	orig, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := os.WriteFile(swapped, append(orig, 0x00), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := PushUpdate("mach-a", swapped, "1.2.3", att); err == nil {
		t.Fatal("push-update queued a binary its attestation does not describe")
	}
	if _, ok := queued(t, "mach-a"); ok {
		t.Fatal("an update was queued despite the attestation check failing")
	}

	// A version that disagrees with the attestation is also refused: the
	// version is what the agent records as running after it applies the
	// update, so it has to be the one that was attested.
	if err := PushUpdate("mach-a", bin, "9.9.9", att); err == nil {
		t.Fatal("push-update accepted a version the attestation does not claim")
	}
	if _, ok := queued(t, "mach-a"); ok {
		t.Fatal("an update was queued despite the version mismatch")
	}
}

// With a matching attestation the update is queued, signed, and carries the
// digest of the attested bytes — the property the agent verifies on arrival.
func TestPushUpdateQueuesAttestedBinary(t *testing.T) {
	_, bin := setup(t)
	att := bin + ".intoto.jsonl"
	if err := Attest(bin, "1.2.3", att); err != nil {
		t.Fatalf("attest: %v", err)
	}
	// A copy at another path, as a real release would be shipped.
	shipped := filepath.Join(t.TempDir(), "mach-agent")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := os.WriteFile(shipped, data, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	seedMachine(t, "mach-b")
	if err := PushUpdate("mach-b", shipped, "1.2.3", att); err != nil {
		t.Fatalf("push-update: %v", err)
	}
	sum := sha256.Sum256(data)
	sha, ok := queued(t, "mach-b")
	if !ok {
		t.Fatal("no update was queued")
	}
	if !strings.EqualFold(sha, hex.EncodeToString(sum[:])) {
		t.Fatalf("queued sha256 = %s, want %s", sha, hex.EncodeToString(sum[:]))
	}
}

// An empty file is never a legitimate agent binary, and queueing one would
// hand the agent a zero-length "update" to apply.
func TestPushUpdateRejectsEmptyBinary(t *testing.T) {
	setup(t)
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := PushUpdate("mach-c", empty, "1.2.3", ""); err == nil {
		t.Fatal("push-update queued an empty binary")
	}
}

// push-update without an attestation keeps working, for the case where an
// operator is rolling out a locally built binary and has nothing to attest.
func TestPushUpdateWithoutAttestationStillWorks(t *testing.T) {
	_, bin := setup(t)
	seedMachine(t, "mach-d")
	if err := PushUpdate("mach-d", bin, "1.2.3", ""); err != nil {
		t.Fatalf("push-update: %v", err)
	}
	if _, ok := queued(t, "mach-d"); !ok {
		t.Fatal("no update was queued")
	}
	// And an unreadable attestation path is an error, not a silent skip.
	if err := PushUpdate("mach-d", bin, "1.2.3", filepath.Join(t.TempDir(), "missing.jsonl")); err == nil {
		t.Fatal("push-update ignored a missing attestation file")
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

// push-update must seedMachine the target it is told to update. Queueing for a
// name no machine has ever held is how a typo looks like a completed rollout:
// pending_updates has no foreign key, so the row would sit there forever while
// the command printed "delivered on next connect".
func seedMachine(t *testing.T, name string) {
	t.Helper()
	st, err := store.Open(dbPath())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.CreateMachine(name, "pub-"+name, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

// An unknown machine is refused rather than queued, and nothing is written.
func TestPushUpdateRejectsUnknownMachine(t *testing.T) {
	_, bin := setup(t)
	err := PushUpdate("mach-typo", bin, "1.2.3", "")
	if err == nil {
		t.Fatal("push-update queued an update for a machine that does not exist")
	}
	if !strings.Contains(err.Error(), "unknown machine") {
		t.Fatalf("error = %q, want it to name the unknown machine", err)
	}
	if _, ok := queued(t, "mach-typo"); ok {
		t.Fatal("an update was queued for an unknown machine")
	}
}
