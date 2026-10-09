package store

import "testing"

func TestSecretsRegistry(t *testing.T) {
	st := testStore(t)
	if err := st.UpsertSecret("acme", "DB_PASSWORD", "console:ops"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := st.UpsertSecret("acme", "AWS_KEY", "agent"); err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if err := st.UpsertSecret("xy", "DB_PASSWORD", "agent"); err != nil {
		t.Fatalf("upsert other org: %v", err)
	}
	rows, err := st.ListSecrets("acme")
	if err != nil || len(rows) != 2 || rows[0].Name != "AWS_KEY" || rows[1].Name != "DB_PASSWORD" {
		t.Fatalf("org list = %+v err=%v", rows, err)
	}
	if rows[1].CreatedBy != "console:ops" {
		t.Fatalf("created_by = %q", rows[1].CreatedBy)
	}
	// A re-announce refreshes last_seen, not provenance. Backdate first so
	// the refresh is observable despite RFC3339's second resolution.
	if _, err := st.db.Exec(`UPDATE secrets SET last_seen_at='2000-01-01T00:00:00Z' WHERE org='acme' AND name='DB_PASSWORD'`); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if err := st.UpsertSecret("acme", "DB_PASSWORD", "agent"); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	rows, _ = st.ListSecrets("acme")
	if rows[1].CreatedBy != "console:ops" {
		t.Fatalf("re-upsert overwrote created_by: %+v", rows[1])
	}
	if rows[1].LastSeenAt == "2000-01-01T00:00:00Z" {
		t.Fatal("re-upsert did not refresh last_seen_at")
	}
	// The other org's row is untouched.
	if xy, _ := st.ListSecrets("xy"); len(xy) != 1 || xy[0].Name != "DB_PASSWORD" {
		t.Fatalf("xy list = %+v", xy)
	}
	// Known / not-known per org.
	if ok, _ := st.SecretKnown("acme", "DB_PASSWORD"); !ok {
		t.Fatal("acme should know DB_PASSWORD")
	}
	if ok, _ := st.SecretKnown("xy", "AWS_KEY"); ok {
		t.Fatal("xy should not know AWS_KEY (cross-org)")
	}
	// Removal reports presence.
	if ok, err := st.RemoveSecret("acme", "AWS_KEY"); err != nil || !ok {
		t.Fatalf("remove: %v %v", ok, err)
	}
	if ok, err := st.RemoveSecret("acme", "AWS_KEY"); err != nil || ok {
		t.Fatalf("second remove: ok=%v err=%v, want false", ok, err)
	}
}
