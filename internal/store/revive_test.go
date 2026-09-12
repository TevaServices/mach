package store

// Tests for taking over an existing enrollment — a revoked one, or a temporary
// one — through a fresh enrollment.
//
// Revocation is a forced re-enrollment, not a permanent ban: the row stays as
// the record (keeping the name and key reserved), the live agent is refused, and
// enrolling again brings the machine back. The property that must hold alongside
// that is the one these tests mostly exist for — an ACTIVELY enrolled machine is
// never displaced, at the SQL level and not merely by a caller's check.

import "testing"

func TestReenrollMachineRevivesARevokedRow(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-web", "old-key", "old-host", "linux", "amd64", "v1", "olde2e", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.RevokeMachine("bcross-web"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// A re-enrollment presents a fresh key — a temporary session always does.
	ok, err := st.ReenrollMachine("bcross-web", "new-key", "new-host", "darwin", "arm64", "v2", "newe2e", false)
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if !ok {
		t.Fatal("a revoked machine was not revived")
	}
	m, err := st.MachineByName("bcross-web")
	if err != nil || m == nil {
		t.Fatalf("machine missing after revive: %v", err)
	}
	if m.Revoked {
		t.Fatal("revive left the machine revoked")
	}
	// Re-keyed and re-described: this is the machine's new identity.
	if m.PubKey != "new-key" || m.Hostname != "new-host" || m.OS != "darwin" || m.AgentVer != "v2" || m.PubE2E != "newe2e" {
		t.Fatalf("revive did not take the new enrollment: %+v", m)
	}
	// The old key must be gone, or the machine would have two identities.
	if byOld, _ := st.MachineByPubKey("old-key"); byOld != nil {
		t.Fatal("the previous key still resolves to a machine")
	}
	if byNew, _ := st.MachineByPubKey("new-key"); byNew == nil || byNew.Name != "bcross-web" {
		t.Fatal("the new key does not resolve to the machine")
	}
	// Continuous history: the row is the same one, so the audit trail for this
	// machine name still lines up.
	if m.CreatedAt == "" {
		t.Fatal("revive lost the original creation time")
	}
}

// The anti-displacement property, and the reason the guard is in SQL rather than
// in Go: an active machine's name and key must not be takeable by an enrollment.
func TestReenrollMachineRefusesAnActiveMachine(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-web", "live-key", "host", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	ok, err := st.ReenrollMachine("bcross-web", "attacker-key", "host", "linux", "amd64", "v", "", false)
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if ok {
		t.Fatal("an ACTIVE machine was revived/re-keyed")
	}
	// And nothing changed: not the key, not the metadata.
	m, _ := st.MachineByName("bcross-web")
	if m == nil || m.PubKey != "live-key" {
		t.Fatalf("an active machine's key was displaced: %+v", m)
	}
	if byAttacker, _ := st.MachineByPubKey("attacker-key"); byAttacker != nil {
		t.Fatal("the new key was attached to an active machine")
	}
}

func TestReenrollMachineIsNoOpForAnUnknownName(t *testing.T) {
	st := testStore(t)
	ok, err := st.ReenrollMachine("bcross-nope", "k", "h", "linux", "amd64", "v", "", false)
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if ok {
		t.Fatal("reviving a machine that does not exist reported success")
	}
}

// Block and revoke are independent axes, so reviving must not silently clear an
// operator's block: a block announces itself as a refusal that names it, which
// is discoverable, where quietly discarding it would not be.
func TestReenrollMachineLeavesBlockedAlone(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-web", "k1", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.RevokeMachine("bcross-web"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := st.SetMachineBlocked("bcross-web", true); err != nil {
		t.Fatalf("block: %v", err)
	}

	ok, err := st.ReenrollMachine("bcross-web", "k2", "h", "linux", "amd64", "v", "", false)
	if err != nil || !ok {
		t.Fatalf("reactivate: ok=%v err=%v", ok, err)
	}
	m, _ := st.MachineByName("bcross-web")
	if m == nil || m.Revoked {
		t.Fatalf("not revived: %+v", m)
	}
	if !m.Blocked {
		t.Fatal("reviving cleared the operator's block")
	}
}

// The second condition a takeover is allowed for: a TEMPORARY enrollment. Its
// record belongs to a session rather than to a machine, so the next run of that
// session reuses the name without the operator revoking or deleting anything —
// which is what makes an exit that never got to retire (a kill, a power cut)
// survivable rather than a wedged name.
func TestReenrollTakesOverATemporaryMachine(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-tmp", "tmp-key", "h", "linux", "amd64", "v", "", true); err != nil {
		t.Fatalf("create: %v", err)
	}
	m, _ := st.MachineByName("bcross-tmp")
	if m == nil || !m.Temporary || m.Revoked {
		t.Fatalf("expected an active temporary enrollment: %+v", m)
	}

	// Active, but temporary: taken over without any operator action.
	ok, err := st.ReenrollMachine("bcross-tmp", "next-key", "h", "linux", "amd64", "v", "", true)
	if err != nil || !ok {
		t.Fatalf("a temporary machine was not taken over: ok=%v err=%v", ok, err)
	}
	m, _ = st.MachineByName("bcross-tmp")
	if m == nil || m.PubKey != "next-key" || !m.Temporary || m.Revoked {
		t.Fatalf("takeover did not work: %+v", m)
	}
}

// A permanent enrollment clears the flag: "the record made permanent" is the
// whole reason the flag is recorded per enrollment rather than set once.
func TestPermanentEnrollmentClearsTheTemporaryFlag(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-here", "k1", "h", "linux", "amd64", "v", "", true); err != nil {
		t.Fatalf("create: %v", err)
	}
	if m, _ := st.MachineByName("bcross-here"); m == nil || !m.Temporary {
		t.Fatal("not temporary to begin with")
	}

	// The same machine, enrolled permanently this time — `mach install` on a host
	// that ran plain `mach`.
	ok, err := st.ReenrollMachine("bcross-here", "k2", "h", "linux", "amd64", "v", "", false)
	if err != nil || !ok {
		t.Fatalf("permanent re-enrollment: ok=%v err=%v", ok, err)
	}
	m, _ := st.MachineByName("bcross-here")
	if m == nil || m.Temporary {
		t.Fatalf("the temporary flag survived a permanent enrollment: %+v", m)
	}
	// And now it is protected like any other live machine: a further enrollment
	// may not take it over.
	ok, err = st.ReenrollMachine("bcross-here", "k3", "h", "linux", "amd64", "v", "", true)
	if err != nil {
		t.Fatalf("third enrollment: %v", err)
	}
	if ok {
		t.Fatal("a machine made permanent was still takeable by a temporary enrollment")
	}
}

// A temporary machine that also got revoked is takeable under either condition.
func TestReenrollTakesOverATemporaryRevokedMachine(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("bcross-both", "k1", "h", "linux", "amd64", "v", "", true); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.RevokeMachine("bcross-both"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// A clean exit retires a temporary session, so this is the normal state of an
	// ended session: revoked AND temporary.
	ok, err := st.ReenrollMachine("bcross-both", "k2", "h", "linux", "amd64", "v", "", true)
	if err != nil || !ok {
		t.Fatalf("takeover: ok=%v err=%v", ok, err)
	}
	m, _ := st.MachineByName("bcross-both")
	if m == nil || m.Revoked || !m.Temporary {
		t.Fatalf("expected revoked cleared and temporary kept: %+v", m)
	}
}
