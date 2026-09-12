// Package release produces and verifies in-toto attestations for the agent
// binaries mach distributes.
//
// Why this exists: the update path already guarantees that only this control
// plane can push a binary — the agent verifies a manifest signed by the
// identity key it pinned at enrollment, over the artifact's sha256. What that
// does NOT establish is anything about where the binary came from. A signed
// digest says "this control plane vouches for these bytes"; it says nothing
// about which source revision produced them, with which toolchain, or whether
// the tree was modified. An attestation is what records that, in a format
// other tools understand.
//
// The format is in-toto (https://in-toto.io): a Statement v1 document naming
// the artifact by digest and carrying a predicate that describes how it was
// built, wrapped in a DSSE envelope signed with the control plane's identity
// key. The signature covers the DSSE payload, so the predicate cannot be
// edited without invalidating it, and any DSSE-aware verifier — not just this
// one — can check it with the control plane's public key.
//
// What this is not: a promise that builds are bit-for-bit reproducible. The
// predicate records the inputs that would make them so (toolchain version,
// GOOS/GOARCH, CGO, build flags, source revision, whether the tree was dirty)
// so a verifier can decide for itself whether two builds should have matched.
// Recorded inputs are evidence, not a guarantee.
//
// Everything the predicate says about the build is read back out of the
// artifact itself (see Inspect) rather than from the environment of the
// process running attest. The one exception is the invocation command line,
// which a compiled binary does not remember; when the caller has to supply it,
// the predicate says so.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// In-toto constants. These strings are the interop surface: they are what
// makes the file below readable by a verifier that has never heard of mach, so
// they are fixed by the specifications rather than by this code.
const (
	// StatementType is the in-toto Statement v1 type URI.
	StatementType = "https://in-toto.io/Statement/v1"
	// PayloadType identifies an in-toto Statement inside a DSSE envelope.
	PayloadType = "application/vnd.in-toto+json"
	// PredicateType names mach's release predicate. It is a URI under the
	// project's own namespace on purpose: predicates are not interchangeable,
	// and calling this SLSA provenance would claim more than it says.
	PredicateType = "https://mach.bcross.dev/attestation/agent-release/v1"
	// BuildType names the build recipe: a plain `go build` of a mach agent.
	BuildType = "https://mach.bcross.dev/buildtype/go-build/v1"
	// BuilderID names the tool that produced the attestation.
	BuilderID = "mach-server attest"
)

// Subject names the artifact an attestation is about, by digest. in-toto
// requires at least one subject, and the digest is what ties the statement to
// the bytes in hand.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is an in-toto Statement v1 document.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Predicate describes the build that produced the artifact. The nested field
// names (builder/invocation/materials/byproducts) follow in-toto's predicate
// conventions so the document reads like other attestations even though the
// type is mach's own.
type Predicate struct {
	Version         string     `json:"version"`
	BuildType       string     `json:"buildType"`
	Builder         Builder    `json:"builder"`
	Invocation      Invocation `json:"invocation"`
	Materials       []Material `json:"materials"`
	Byproducts      Byproducts `json:"byproducts"`
	BuildStartedOn  string     `json:"buildStartedOn,omitempty"`
	BuildFinishedOn string     `json:"buildFinishedOn,omitempty"`
}

// Builder is who ran the build. There is no build service here, so it names
// the tool that produced the attestation.
type Builder struct {
	ID string `json:"id"`
}

// Invocation records the parameters of the build.
type Invocation struct {
	Parameters InvocationParams `json:"parameters"`
}

// InvocationParams is the build recipe. RecordedFrom says where these values
// came from: "artifact" when the binary's own build settings supplied all of
// them, "artifact+caller" when the caller had to supply some (see Asserted).
// A verifier that only trusts artifact-derived fields can check this rather
// than having to know which toolchain produced the binary.
type InvocationParams struct {
	Command      string   `json:"command,omitempty"`
	GoOS         string   `json:"goos,omitempty"`
	GoArch       string   `json:"goarch,omitempty"`
	Ldflags      string   `json:"ldflags,omitempty"`
	Trimpath     bool     `json:"trimpath,omitempty"`
	RecordedFrom string   `json:"recordedFrom"`
	Asserted     []string `json:"assertedByCaller,omitempty"`
}

// Material is an input to the build. Two kinds appear here: the Go modules the
// binary was built from (each with the h1: content hash the toolchain
// recorded) and the VCS revision of this repository. An input whose contents
// cannot be pinned — the main module of a development build, or a dependency
// replaced by a local directory — is listed with its URI and no digest, which
// says "this input exists but its contents are not recorded" rather than
// implying a hash that does not exist.
type Material struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
}

// Byproducts record what the toolchain reported about the build. Every field
// is read from the artifact's own embedded build information. Absent fields
// mean the build recorded nothing — a binary built outside a VCS checkout has
// no vcsRevision, which is itself worth knowing, because such a release cannot
// be traced to a commit.
type Byproducts struct {
	GoVersion   string `json:"goVersion"`
	GoModule    string `json:"goModule,omitempty"`
	CgoEnabled  string `json:"cgoEnabled,omitempty"`
	VCSRevision string `json:"vcsRevision,omitempty"`
	VCSModified bool   `json:"vcsModified,omitempty"`
	VCSTime     string `json:"vcsTime,omitempty"`
}

// Artifact is what can be learned about a compiled binary without running it.
type Artifact struct {
	Byproducts Byproducts
	// Materials are the dependency modules the linker baked in, plus the VCS
	// revision when the build recorded one.
	Materials []Material
	// Settings is the raw build settings map (GOOS, GOARCH, CGO_ENABLED,
	// -ldflags, -trimpath, vcs.* ...), for callers that need more than the
	// named fields above. Toolchains differ in what they record, so it is
	// deliberately not a fixed struct.
	Settings map[string]string
}

// Digest is the hex sha256 of a file's contents, streamed so that a large
// binary does not have to be held in memory to be hashed.
func Digest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// NewSubject builds a subject for an artifact on disk.
func NewSubject(name, path string) (Subject, error) {
	sum, err := Digest(path)
	if err != nil {
		return Subject{}, err
	}
	return Subject{Name: name, Digest: map[string]string{"sha256": sum}}, nil
}

// Inspect reads the build information embedded in a compiled binary. This is
// the reason the predicate can say anything trustworthy about the build: Go's
// linker records the exact module graph and VCS state, and this reads it back
// out of the artifact rather than trusting whoever ran attest.
func Inspect(binPath string) (Artifact, error) {
	bi, err := buildinfo.ReadFile(binPath)
	if err != nil {
		return Artifact{}, fmt.Errorf("reading build information from %s: %w", binPath, err)
	}
	by := Byproducts{GoVersion: bi.GoVersion}
	if bi.Main.Path != "" {
		by.GoModule = bi.Main.Path
		if bi.Main.Version != "" {
			by.GoModule += "@" + bi.Main.Version
		}
	}
	settings := make(map[string]string, len(bi.Settings))
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}
	by.CgoEnabled = settings["CGO_ENABLED"]
	by.VCSRevision = settings["vcs.revision"]
	by.VCSModified = settings["vcs.modified"] == "true"
	by.VCSTime = settings["vcs.time"]

	// Materials: the dependency graph the linker baked in. Each module's h1:
	// hash is the go.sum content digest, so a verifier can check the modules
	// against its own go.sum rather than taking the list on faith.
	var mats []Material
	if by.VCSRevision != "" {
		mats = append(mats, Material{
			URI:    "git+https://github.com/bcross/mach@" + by.VCSRevision,
			Digest: map[string]string{"sha1": by.VCSRevision},
		})
	}
	mods := make([]*debugModule, 0, len(bi.Deps)+1)
	if bi.Main.Path != "" {
		m := bi.Main
		mods = append(mods, &debugModule{path: m.Path, version: m.Version, sum: m.Sum})
	}
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		m := &debugModule{path: d.Path, version: d.Version, sum: d.Sum}
		if d.Replace != nil {
			// The hash Go records describes what was actually linked. Naming
			// the original path here would make a verifier recomputing from
			// go.mod disagree with the artifact, so the replaced module is
			// listed in place of the one it stands in for.
			m = &debugModule{path: d.Replace.Path, version: d.Replace.Version, sum: d.Replace.Sum}
		}
		mods = append(mods, m)
	}
	for _, m := range mods {
		if m.path == "" {
			continue
		}
		uri := "pkg:golang/" + m.path
		if m.version != "" && m.version != "(devel)" {
			uri += "@" + m.version
		}
		mat := Material{URI: uri}
		if m.sum != "" {
			mat.Digest = map[string]string{"h1": strings.TrimPrefix(m.sum, "h1:")}
		}
		mats = append(mats, mat)
	}
	return Artifact{Byproducts: by, Materials: mats, Settings: settings}, nil
}

// debugModule is the flattened view of a debug.Module after any replace
// directive has been applied. A module replaced by a local directory has no
// version and no sum, which is how an unpinnable input shows up here.
type debugModule struct {
	path, version, sum string
}

// Options describes one artifact to attest.
type Options struct {
	// SubjectName is the name recorded in the statement, e.g. "mach-linux-amd64".
	SubjectName string
	// Binary is the path to the compiled agent.
	Binary string
	// Version is the release version the control plane will advertise.
	Version string
	// Started, when non-zero, is recorded as the build's start time.
	Started time.Time
	// Command, Ldflags and Trimpath are fallbacks for the invocation record.
	// They are used only when the artifact's own build settings do not carry
	// the same information, and the predicate names them as caller-asserted
	// when that happens.
	Command  string
	Ldflags  string
	Trimpath bool
}

// Attest builds a Statement for one artifact.
func Attest(opts Options) (*Statement, error) {
	if opts.SubjectName == "" || opts.Binary == "" {
		return nil, fmt.Errorf("attest needs a subject name and a binary path")
	}
	art, err := Inspect(opts.Binary)
	if err != nil {
		return nil, err
	}
	params := invocationFrom(art, opts)
	subj, err := NewSubject(opts.SubjectName, opts.Binary)
	if err != nil {
		return nil, err
	}
	pred := Predicate{
		Version:         opts.Version,
		BuildType:       BuildType,
		Builder:         Builder{ID: BuilderID},
		Invocation:      Invocation{Parameters: params},
		Materials:       art.Materials,
		Byproducts:      art.Byproducts,
		BuildFinishedOn: time.Now().UTC().Format(time.RFC3339),
	}
	if !opts.Started.IsZero() {
		pred.BuildStartedOn = opts.Started.UTC().Format(time.RFC3339)
	}
	raw, err := json.Marshal(pred)
	if err != nil {
		return nil, err
	}
	return &Statement{
		Type:          StatementType,
		Subject:       []Subject{subj},
		PredicateType: PredicateType,
		Predicate:     raw,
	}, nil
}

// invocationFrom fills the build recipe from the artifact's own settings,
// falling back to the caller's values only where the toolchain recorded
// nothing, and recording which fields were which.
func invocationFrom(art Artifact, opts Options) InvocationParams {
	p := InvocationParams{
		GoOS:     art.Settings["GOOS"],
		GoArch:   art.Settings["GOARCH"],
		Ldflags:  art.Settings["-ldflags"],
		Trimpath: art.Settings["-trimpath"] == "true",
	}
	var asserted []string
	if p.GoOS == "" {
		asserted = append(asserted, "goos")
	}
	if p.GoArch == "" {
		asserted = append(asserted, "goarch")
	}
	if p.Ldflags == "" && opts.Ldflags != "" {
		p.Ldflags = opts.Ldflags
		asserted = append(asserted, "ldflags")
	}
	if art.Settings["-trimpath"] == "" && opts.Trimpath {
		p.Trimpath = true
		asserted = append(asserted, "trimpath")
	}
	// The command line is never in the artifact: a compiled binary does not
	// remember it. It is recorded only when the caller states one.
	if opts.Command != "" {
		p.Command = opts.Command
		asserted = append(asserted, "command")
	}
	p.Asserted = asserted
	if len(asserted) == 0 {
		p.RecordedFrom = "artifact"
	} else {
		p.RecordedFrom = "artifact+caller"
	}
	return p
}

// VerifyArtifact checks that one of the statement's subjects matches the
// artifact on disk. This is the step that connects a signed attestation to
// bytes: without it, a perfectly valid attestation could describe some other
// binary. An empty name matches the first subject that carries a sha256.
func (s *Statement) VerifyArtifact(name, path string) error {
	if s.Type != StatementType {
		return fmt.Errorf("not an in-toto statement (got %q)", s.Type)
	}
	if len(s.Subject) == 0 {
		return fmt.Errorf("attestation has no subject")
	}
	sum, err := Digest(path)
	if err != nil {
		return err
	}
	for _, sub := range s.Subject {
		if name != "" && sub.Name != name {
			continue
		}
		want := sub.Digest["sha256"]
		if want == "" {
			continue
		}
		if !strings.EqualFold(want, sum) {
			return fmt.Errorf("subject %q is sha256 %s, but %s hashes to %s", sub.Name, want, path, sum)
		}
		return nil
	}
	if name == "" {
		return fmt.Errorf("attestation has no subject with a sha256 digest")
	}
	return fmt.Errorf("attestation has no subject named %q", name)
}

// PredicateOf decodes the predicate for display and inspection.
func (s *Statement) PredicateOf() (Predicate, error) {
	var p Predicate
	err := json.Unmarshal(s.Predicate, &p)
	return p, err
}

// KeyID is the DSSE key identifier for an ed25519 public key: the hex sha256
// of the key itself. Any verifier can recompute it from a key it already
// holds, so it is a name for the key rather than a lookup token — which is
// also why the library's ssh-based SHA256KeyID is not used here; mach has no
// ssh keys to name.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}
