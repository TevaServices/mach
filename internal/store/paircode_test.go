package store

// The challenge code's two forms — as displayed (dashed) and as hashed
// (normalized) — must not drift apart, because when they did, every correct
// approval was rejected and the pairing path was unusable end to end.
//
// These tests are on the seam: they use the code CreatePairing actually returns,
// which is the dashed display form, rather than a hand-written literal.

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeCodeStripsTheDisplayForm(t *testing.T) {
	cases := map[string]string{
		"ABCD-EFGH-JKMP": "ABCDEFGHJKMP",
		"abcd-efgh-jkmp": "ABCDEFGHJKMP",
		"ABCD EFGH JKMP": "ABCDEFGHJKMP",
		" ABCDEFGHJKMP ": "ABCDEFGHJKMP",
		"ABCDEFGHJKMP":   "ABCDEFGHJKMP",
	}
	for in, want := range cases {
		if got := NormalizeCode(in); got != want {
			t.Errorf("NormalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
}

// The regression: a code straight from CreatePairing must approve. Both store
// tests and the pair page used to be individually consistent with themselves and
// inconsistent with each other, and nothing exercised the join.
func TestApprovePairingAcceptsTheCodeItReturned(t *testing.T) {
	st := testStore(t)
	id, _, code, err := st.CreatePairing("pub-1", "h", "linux", "amd64", "v", 10*time.Minute)
	if err != nil {
		t.Fatalf("create pairing: %v", err)
	}
	// NewChallengeCode formats it XXXX-XXXX-XXXX; asserting that here means a
	// future change to the display form cannot quietly make this test vacuous.
	if !strings.Contains(code, "-") {
		t.Fatalf("CreatePairing returned %q, which is not the dashed display form", code)
	}

	ok, why, err := st.ApprovePairing(id, code, "bcross-x")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !ok {
		t.Fatalf("the code CreatePairing returned was refused (why=%q) — display form and hashed form have drifted", why)
	}
}

// The operator may type it either way: the dashes are for reading, not for
// typing, and the page normalizes what it is given.
func TestApprovePairingAcceptsEitherForm(t *testing.T) {
	for _, form := range []string{"as-returned", "normalized"} {
		st := testStore(t)
		id, _, code, err := st.CreatePairing("pub-1", "h", "linux", "amd64", "v", 10*time.Minute)
		if err != nil {
			t.Fatalf("create pairing: %v", err)
		}
		submitted := code
		if form == "normalized" {
			submitted = NormalizeCode(code)
		}
		ok, why, err := st.ApprovePairing(id, submitted, "bcross-x")
		if err != nil || !ok {
			t.Fatalf("%s form refused: ok=%v why=%q err=%v", form, ok, why, err)
		}
	}
}

// A wrong code is still refused, so the fix above did not make the comparison
// accept anything.
func TestApprovePairingStillRefusesAWrongCode(t *testing.T) {
	st := testStore(t)
	id, _, code, err := st.CreatePairing("pub-1", "h", "linux", "amd64", "v", 10*time.Minute)
	if err != nil {
		t.Fatalf("create pairing: %v", err)
	}
	wrong := NormalizeCode(code)
	if wrong[0] == 'A' {
		wrong = "B" + wrong[1:]
	} else {
		wrong = "A" + wrong[1:]
	}
	ok, why, err := st.ApprovePairing(id, wrong, "bcross-x")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if ok || why != "bad-code" {
		t.Fatalf("a wrong code was not refused: ok=%v why=%q", ok, why)
	}
}
