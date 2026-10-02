package store

import (
	"errors"
	"strings"
	"testing"
)

// Revoking an API key must flip the revoked flag the auth path reads: a revoked
// key stops resolving (APIKeyExists false), the row stays listed as revoked,
// and revoking twice is fine — the command asks for an end state.
func TestRevokeAPIKeyRevokesAndStaysListed(t *testing.T) {
	st := testStore(t)
	if err := st.CreateAPIKey("auditkey", "mach_deadbeef01", "exec:*"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if ok, _, _, err := st.APIKeyExists("mach_deadbeef01"); err != nil || !ok {
		t.Fatalf("fresh key should resolve: ok=%v err=%v", ok, err)
	}
	ok, err := st.RevokeAPIKey("auditkey")
	if err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v, want true, nil", ok, err)
	}
	if ok, name, _, err := st.APIKeyExists("mach_deadbeef01"); err != nil || ok {
		t.Fatalf("revoked key must not resolve: ok=%v name=%q err=%v", ok, name, err)
	}
	keys, err := st.ListAPIKeys()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var seen bool
	for _, k := range keys {
		if k.Name == "auditkey" {
			seen = true
			if !k.Revoked {
				t.Error("listed key reports revoked=false; the flag is not reaching the list")
			}
		}
	}
	if !seen {
		t.Fatal("revoked key vanished from ListAPIKeys; revocation must be a tombstone, not a delete")
	}
	// Idempotent: revoking the already-revoked key is a success.
	if ok, err := st.RevokeAPIKey("auditkey"); err != nil || !ok {
		t.Fatalf("second revoke: ok=%v err=%v, want true, nil", ok, err)
	}
}

// An unknown name is an ERROR, not a silent success — same rule as
// RevokeMachine: a typo that prints "revoked" would mislead the operator.
func TestRevokeAPIKeyUnknownNameErrors(t *testing.T) {
	st := testStore(t)
	ok, err := st.RevokeAPIKey("no-such-key")
	if err == nil || ok {
		t.Fatalf("unknown name: ok=%v err=%v, want false + error", ok, err)
	}
	if !errors.Is(err, ErrUnknownAPIKey) {
		t.Errorf("err = %v, want ErrUnknownAPIKey wrap", err)
	}
	if !strings.Contains(err.Error(), "no-such-key") {
		t.Errorf("err = %v, want it to name the missing key", err)
	}
}
