package controlplane

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"time"

	"github.com/bcross/mach/internal/release"
)

// Attest writes a signed in-toto attestation for a compiled agent binary.
//
// This is a release-time step, not a runtime one: it records what the binary
// was built from, so that later anyone — an operator, an auditor, another tool
// — can check where a shipped artifact came from. The signature is made with
// the control plane's own identity key, the same key agents pin at enrollment,
// so an attestation vouches for the binary in the same terms the update path
// already does.
//
// The attestation is written next to the binary as <binary>.intoto.jsonl.
func Attest(binPath, version, outPath string) error {
	if version == "" {
		return fmt.Errorf("attest needs a version (the version the control plane will advertise for this build)")
	}
	priv, err := loadServerPriv()
	if err != nil {
		return err
	}
	// The subject name is the artifact's basename: it is what a verifier
	// holding the file will call it, and it is what the update manifest's URL
	// or filename will say.
	name := filepath.Base(binPath)
	st, err := release.Attest(release.Options{
		SubjectName: name,
		Binary:      binPath,
		Version:     version,
		Started:     time.Now(),
	})
	if err != nil {
		return err
	}
	env, err := release.Sign(context.Background(), st, priv)
	if err != nil {
		return err
	}
	if outPath == "" {
		outPath = binPath + ".intoto.jsonl"
	}
	if err := release.SaveAttestation(outPath, env); err != nil {
		return err
	}
	pred, _ := st.PredicateOf()
	fmt.Printf("attested %s as %q\n", binPath, name)
	fmt.Printf("  version    %s\n", pred.Version)
	fmt.Printf("  sha256     %s\n", st.Subject[0].Digest["sha256"])
	fmt.Printf("  toolchain  %s (cgo=%s)\n", pred.Byproducts.GoVersion, orNone(pred.Byproducts.CgoEnabled))
	if pred.Byproducts.VCSRevision != "" {
		dirty := ""
		if pred.Byproducts.VCSModified {
			dirty = "  [tree was modified at build time]"
		}
		fmt.Printf("  revision   %s%s\n", shortRev(pred.Byproducts.VCSRevision), dirty)
	} else {
		fmt.Printf("  revision   (none recorded — this build carries no VCS information)\n")
	}
	fmt.Printf("  materials  %d module(s)\n", len(pred.Materials))
	fmt.Printf("  key id     %s\n", keyIDOf(env))
	fmt.Printf("written to   %s\n", outPath)
	return nil
}

// VerifyAttestation checks an attestation against the control plane's own
// identity key and against the binary it claims to describe. Either check
// failing is fatal: a valid signature over the wrong file proves nothing, and
// a matching file with a bad signature proves less.
func VerifyAttestation(attPath, binPath string) error {
	priv, err := loadServerPriv()
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)

	env, err := release.LoadAttestation(attPath)
	if err != nil {
		return err
	}
	st, err := release.Open(context.Background(), env, pub)
	if err != nil {
		return err
	}
	// The subject name in the statement is not required to match the local
	// filename — the same binary is legitimately shipped under several names —
	// so the digest is what is matched, and the name is only displayed.
	if err := st.VerifyArtifact("", binPath); err != nil {
		return err
	}
	pred, err := st.PredicateOf()
	if err != nil {
		return fmt.Errorf("attestation predicate: %w", err)
	}

	fmt.Printf("OK  %s\n", attPath)
	fmt.Printf("  signed by  %s (this control plane)\n", release.KeyID(pub))
	fmt.Printf("  subject    %s\n", st.Subject[0].Name)
	fmt.Printf("  sha256     %s  (matches %s)\n", st.Subject[0].Digest["sha256"], binPath)
	fmt.Printf("  version    %s\n", pred.Version)
	fmt.Printf("  toolchain  %s\n", pred.Byproducts.GoVersion)
	if pred.Byproducts.VCSModified {
		fmt.Printf("  WARNING    built from a modified tree — this artifact does not correspond to the recorded revision\n")
	}
	if pred.Byproducts.VCSRevision == "" {
		fmt.Printf("  WARNING    no VCS revision recorded — this artifact cannot be traced to a commit\n")
	}
	if len(pred.Invocation.Parameters.Asserted) > 0 {
		fmt.Printf("  note       build parameters asserted by the caller, not read from the artifact: %v\n",
			pred.Invocation.Parameters.Asserted)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "unrecorded"
	}
	return s
}

func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func keyIDOf(env *release.Envelope) string {
	if len(env.Signatures) == 0 {
		return "(none)"
	}
	return env.Signatures[0].KeyID
}
