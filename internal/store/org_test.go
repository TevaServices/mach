package store

// Tests for org CRUD and for the API-key listing that backs the UI's org
// membership view. The membership view shows keys to anyone who can sign in, so
// what ListAPIKeys does NOT expose matters as much as what it does.

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestValidOrgLabel(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"bcross", true},
		{"ac", true},                     // minimum length
		{strings.Repeat("a", 20), true},  // maximum length
		{"a", false},                     // too short
		{strings.Repeat("a", 21), false}, // too long
		{"", false},
		{"Acme", true}, // case is allowed; callers normalise
		{"a-b", true},  // hyphen allowed
		{"a_b", false}, // underscore is not
		{"a.b", false}, // dot is not
		{"a b", false}, // space is not
		{"acme/evil", false},
		{"-ab", true}, // leading hyphen: ValidOrgName permits it, so stay consistent
	}
	for _, c := range cases {
		if got := ValidOrgLabel(c.in); got != c.ok {
			t.Errorf("ValidOrgLabel(%q) = %v, want %v", c.in, got, c.ok)
		}
	}
}

func TestOrgCRUD(t *testing.T) {
	st := testStore(t)

	if exists, err := st.OrgExists("acme"); err != nil || exists {
		t.Fatalf("org exists before creation: %v %v", exists, err)
	}
	if err := st.CreateOrg("acme", "e2e-operator"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if exists, err := st.OrgExists("acme"); err != nil || !exists {
		t.Fatalf("org missing after creation: %v %v", exists, err)
	}
	// A duplicate must be a clean sentinel, not a driver-specific error string.
	if err := st.CreateOrg("acme", "someone-else"); !errors.Is(err, ErrOrgExists) {
		t.Fatalf("duplicate create returned %v, want ErrOrgExists", err)
	}

	orgs, err := st.ListOrgsDB()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(orgs) != 1 || orgs[0].Name != "acme" {
		t.Fatalf("list = %+v, want exactly acme", orgs)
	}
	// Pinned is the environment's business, never the store's.
	if orgs[0].Pinned {
		t.Fatal("ListOrgsDB marked a stored org as pinned")
	}
	if orgs[0].CreatedBy != "e2e-operator" || orgs[0].CreatedAt == "" {
		t.Fatalf("provenance not recorded: %+v", orgs[0])
	}

	if err := st.DeleteOrg("acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if exists, err := st.OrgExists("acme"); err != nil || exists {
		t.Fatalf("org survived delete: %v %v", exists, err)
	}
	// Deleting something that is not there is not an error: the caller is
	// trying to reach a state, not to consume a row.
	if err := st.DeleteOrg("acme"); err != nil {
		t.Fatalf("deleting an absent org errored: %v", err)
	}
}

// The membership view renders keys to any signed-in operator. It must be
// structurally incapable of showing a secret: not "we remembered not to",
// but "there is no field to put one in".
func TestAPIKeyInfoHasNoSecretFields(t *testing.T) {
	// Reflecting on the struct is the point: a field added later fails this
	// test rather than silently reaching a page.
	typ := reflect.TypeOf(APIKeyInfo{})
	forbidden := map[string]bool{
		"salt": true, "keylookup": true, "keyhash": true, "lookup": true, "hash": true,
	}
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		if forbidden[name] {
			t.Fatalf("APIKeyInfo exposes a secret-bearing field %q; the org membership view renders this struct", typ.Field(i).Name)
		}
	}
	want := map[string]bool{"Name": true, "Scopes": true, "CreatedAt": true, "Revoked": true}
	if typ.NumField() != len(want) {
		t.Fatalf("APIKeyInfo has %d fields; update this test deliberately if that is intended", typ.NumField())
	}
	for i := 0; i < typ.NumField(); i++ {
		if !want[typ.Field(i).Name] {
			t.Fatalf("unexpected field %q on APIKeyInfo", typ.Field(i).Name)
		}
	}
}

func TestListAPIKeys(t *testing.T) {
	st := testStore(t)
	if err := st.CreateAPIKey("deploy", "mach_"+RandToken(24), "enroll"); err != nil {
		t.Fatalf("create key: %v", err)
	}
	if err := st.CreateAPIKey("ops", "mach_"+RandToken(24), "exec:*"); err != nil {
		t.Fatalf("create key: %v", err)
	}

	keys, err := st.ListAPIKeys()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	// Ordered by name, so the membership view is stable between renders.
	if keys[0].Name != "deploy" || keys[1].Name != "ops" {
		t.Fatalf("keys not ordered by name: %+v", keys)
	}
	if keys[0].Scopes != "enroll" || keys[1].Scopes != "exec:*" {
		t.Fatalf("scopes wrong: %+v", keys)
	}
	for _, k := range keys {
		if k.CreatedAt == "" {
			t.Fatalf("created_at missing for %q", k.Name)
		}
		if k.Revoked {
			t.Fatalf("fresh key %q reported revoked", k.Name)
		}
	}

	// The listing must not weaken the bearer-key path it sits beside.
	secret := "mach_" + RandToken(24)
	if err := st.CreateAPIKey("probe", secret, "readonly"); err != nil {
		t.Fatalf("create key: %v", err)
	}
	keys, _ = st.ListAPIKeys()
	for _, k := range keys {
		if strings.Contains(k.Name, secret) || strings.Contains(k.Scopes, secret) {
			t.Fatal("listing leaked the key secret")
		}
	}
	// And the row still holds what it must for authentication to work.
	var hashes int
	if err := st.queryRow(`SELECT COUNT(*) FROM api_keys WHERE key_lookup <> '' AND key_hash <> ''`).Scan(&hashes); err != nil {
		t.Fatalf("count hashes: %v", err)
	}
	if hashes != 3 {
		t.Fatalf("expected 3 keyed rows to carry hashes, got %d", hashes)
	}
	if ok, _, _, err := st.APIKeyExists(secret); err != nil || !ok {
		t.Fatalf("the key still authenticates: ok=%v err=%v", ok, err)
	}
}
