package console

// Trust-on-first-use pinning of a machine's E2E key.
//
// The seal protects a command from the control plane — but the key it seals to
// comes from the control plane (`GET /v1/machines/{name}/e2epub`). A control
// plane that wanted to read the command could simply advertise its own X25519
// key, receive the ciphertext, open it, and forward the command on. That hole is
// structural: the key is the one thing the seal cannot protect, because the
// party handing it out is the party the seal exists to keep out.
//
// So the console remembers the first key it is given for each machine and
// refuses to seal to any other. That is trust-on-first-use, and it is worth
// being precise about what it does and does not buy:
//
//   - A control plane that substitutes a key BEFORE this console has ever sealed
//     to that machine wins, silently. There is no way around that without an
//     out-of-band fingerprint or a transparency log, and pretending otherwise
//     would be worse than the hole.
//   - A control plane that substitutes a key AFTERWARDS is caught: sealing stops
//     with an error that names both keys, and it stays stopped until a human
//     says otherwise. The capability goes from silent and permanent to one-shot
//     and loud.
//   - A machine that legitimately re-enrolled with a fresh E2E key (a wiped
//     state dir, a rebuilt host) looks exactly like that, so the remedy is
//     explicit and manual: `mach trust <machine>`.
//
// Nothing here is a secret — the pinned value is a public key — but the file is
// written 0600 and read defensively anyway: whoever can rewrite it can choose
// which key this console will seal to, which is the whole control.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// pinsFileName is the file inside the console's state dir.
const pinsFileName = "e2e_pins.json"

// pinnedKey is one machine's remembered E2E key.
type pinnedKey struct {
	PubE2E string `json:"pub_e2e"`
	// PinnedAt is when it was first seen, so the error message can say how long
	// the old key had been in use and the operator can judge what a change means.
	PinnedAt string `json:"pinned_at"`
	// OrgKey is the org this machine belonged to when it was pinned. Informational
	// only: it is here so a human reading the file can tell machines apart.
	OrgKey string `json:"org,omitempty"`
}

type pinFile struct {
	Machines map[string]pinnedKey `json:"machines"`
}

// pinStore reads and writes the pinned keys. The path is resolved once so a test
// can point it at a temp dir.
type pinStore struct {
	path string
}

func newPinStore() *pinStore {
	return &pinStore{path: filepath.Join(StateDirDefault(), pinsFileName)}
}

// Load reads the pin file. A missing file is not an error: it means this console
// has never sealed to anything.
func (p *pinStore) Load() (pinFile, error) {
	var f pinFile
	raw, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			return pinFile{Machines: map[string]pinnedKey{}}, nil
		}
		return f, err
	}
	// Whoever can rewrite this file chooses the key this console seals to, so a
	// loose mode is worth complaining about even though the contents are public.
	if st, serr := os.Stat(p.path); serr == nil && st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "mach: warning: %s had permissions %v; tightening to 0600\n", p.path, st.Mode().Perm())
		_ = os.Chmod(p.path, 0o600)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return pinFile{Machines: map[string]pinnedKey{}}, fmt.Errorf("%s is not readable as JSON: %w "+
			"(fix or delete it; deleting means the next sealed command re-pins every machine)", p.path, err)
	}
	if f.Machines == nil {
		f.Machines = map[string]pinnedKey{}
	}
	return f, nil
}

// save writes the file atomically and 0600. Atomic because a torn write would
// lose pins, and a lost pin does not fail — it silently re-pins, which turns the
// protection off without saying so.
func (p *pinStore) save(f pinFile) error {
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// check decides whether this console may seal to the advertised key.
//
// first is true when nothing was pinned before — the caller reports that, because
// a first use is the one moment the operator has no protection and should know it
// just happened.
func (p *pinStore) check(machine, advertised, org string) (first bool, err error) {
	f, err := p.Load()
	if err != nil {
		return false, err
	}
	pinned, ok := f.Machines[machine]
	if !ok {
		f.Machines[machine] = pinnedKey{
			PubE2E:   advertised,
			PinnedAt: time.Now().UTC().Format(time.RFC3339),
			OrgKey:   org,
		}
		if err := p.save(f); err != nil {
			return false, fmt.Errorf("could not record the E2E key for %s: %w", machine, err)
		}
		return true, nil
	}
	if pinned.PubE2E != advertised {
		return false, fmt.Errorf(
			"the E2E key for %s changed — refusing to seal\n"+
				"  pinned %s (%s, on %s)\n"+
				"  now    %s\n"+
				"This is what a control plane substituting a key looks like, and also what a\n"+
				"machine that re-enrolled with a fresh key looks like. If the machine was\n"+
				"rebuilt or its state dir was wiped, accept the new key with:\n"+
				"  mach trust %s\n"+
				"If it was not, do not: run the command in plaintext instead (mach exec --no-e2e),\n"+
				"or investigate first.",
			machine,
			KeyFingerprint(pinned.PubE2E), shortKey(pinned.PubE2E), pinned.PinnedAt,
			KeyFingerprint(advertised),
			machine)
	}
	return false, nil
}

// trust records the advertised key for a machine, replacing any previous pin.
// Explicit and human-initiated by construction: this is the only way a changed
// key becomes usable, and nothing else in the client calls it.
func (p *pinStore) trust(machine, advertised, org string) (previous string, err error) {
	f, err := p.Load()
	if err != nil {
		return "", err
	}
	if old, ok := f.Machines[machine]; ok {
		previous = old.PubE2E
	}
	f.Machines[machine] = pinnedKey{
		PubE2E:   advertised,
		PinnedAt: time.Now().UTC().Format(time.RFC3339),
		OrgKey:   org,
	}
	return previous, p.save(f)
}

// forget drops a machine's pin, so the next sealed command pins again from
// scratch. This is the "I want the protection off for this machine" switch.
func (p *pinStore) forget(machine string) (existed bool, err error) {
	f, err := p.Load()
	if err != nil {
		return false, err
	}
	_, existed = f.Machines[machine]
	delete(f.Machines, machine)
	return existed, p.save(f)
}

// list returns the pins, sorted by machine name.
func (p *pinStore) list() ([]string, error) {
	f, err := p.Load()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(f.Machines))
	for name := range f.Machines {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// get returns one machine's pin.
func (p *pinStore) get(machine string) (pinnedKey, bool, error) {
	f, err := p.Load()
	if err != nil {
		return pinnedKey{}, false, err
	}
	k, ok := f.Machines[machine]
	return k, ok, nil
}

// KeyFingerprint is a short, stable rendering of a public key, for a human to
// compare two keys by eye. It is a hash of the key bytes, not a prefix of them:
// two keys that differ at the end must not look alike.
func KeyFingerprint(pubHex string) string {
	raw, err := hex.DecodeString(pubHex)
	if err != nil {
		return "sha256:invalid"
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// shortKey renders a key compactly for a message: enough to recognise, with the
// middle elided, because the full 64 hex characters wrap badly in a terminal.
func shortKey(pubHex string) string {
	if len(pubHex) <= 24 {
		return pubHex
	}
	return pubHex[:12] + "…" + pubHex[len(pubHex)-8:]
}

// PinPath is where the pins live, for a message that needs to name it.
func PinPath() string { return newPinStore().path }

// TrustMachine records the key the control plane currently advertises for a
// machine, and reports what it replaced. Returns the fingerprint so the caller
// can show what was accepted.
func (c *client) TrustMachine(machine string) (fingerprint, previous string, err error) {
	info, err := c.machineE2EPub(machine)
	if err != nil {
		return "", "", err
	}
	if !info.Enabled {
		return "", "", fmt.Errorf("this control plane has sealing disabled for %s, "+
			"so there is no key to trust: %s", machine, strings.TrimSpace(info.Reason))
	}
	if info.PubE2E == "" {
		return "", "", fmt.Errorf("%s has no E2E key (it enrolled before E2E existed, "+
			"or the control plane did not advertise one) — re-enroll it to get one", machine)
	}
	prev, err := c.pins.trust(machine, info.PubE2E, info.Org)
	if err != nil {
		return "", "", err
	}
	return KeyFingerprint(info.PubE2E), KeyFingerprint(prev), nil
}

// ForgetMachine drops a machine's pin.
func (c *client) ForgetMachine(machine string) (bool, error) {
	return c.pins.forget(machine)
}

// PinnedMachines lists the machines this console has pinned.
func (c *client) PinnedMachines() ([]string, error) {
	return c.pins.list()
}

// PinnedKey reports one machine's pin for display.
func (c *client) PinnedKey(machine string) (fingerprint, pinnedAt, org string, ok bool, err error) {
	k, ok, err := c.pins.get(machine)
	if err != nil || !ok {
		return "", "", "", ok, err
	}
	return KeyFingerprint(k.PubE2E), k.PinnedAt, k.OrgKey, true, nil
}
