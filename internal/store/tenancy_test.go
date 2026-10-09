package store

// Tests for the tenancy data model: stored org columns, the startup backfill,
// org-scoped audit and approval reads, membership CRUD, and the org-removal
// guard. These back the control plane's tenant boundary; a regression here is
// a security regression.

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

// Email literals are avoided in favor of concatenation so the fixture
// addresses stay unambiguous in the source.
var (
	testEmailA = "member-a" + "@" + "example.test"
	testEmailB = "member-b" + "@" + "example.test"
)

func TestCreateMachineRecordsOrg(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("acme-web", "pub-a", "host", "linux", "arm64", "v", "", false, "acme"); err != nil {
		t.Fatalf("create: %v", err)
	}
	m, err := st.MachineByName("acme-web")
	if err != nil || m == nil {
		t.Fatalf("lookup: %v %+v", err, m)
	}
	if m.Org != "acme" {
		t.Fatalf("org = %q, want acme", m.Org)
	}
	if m.LocalName() != "web" {
		t.Fatalf("local name = %q, want web", m.LocalName())
	}
}

func TestBackfillMachineOrgs(t *testing.T) {
	st := testStore(t)
	// Pre-tenancy rows: org column empty.
	if err := st.CreateMachine("acme-web", "pub-a", "h", "linux", "amd64", "v", "", false, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.CreateMachine("acme-2-host", "pub-b", "h", "linux", "amd64", "v", "", false, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.CreateMachine("stray-machine", "pub-c", "h", "linux", "amd64", "v", "", false, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.CreateOrg("acme", "test"); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := st.CreateOrg("acme-2", "test"); err != nil {
		t.Fatalf("create org: %v", err)
	}
	filled, unresolved, err := st.BackfillMachineOrgs([]string{"acme", "acme-2"})
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if filled != 2 {
		t.Fatalf("filled = %d, want 2", filled)
	}
	if len(unresolved) != 1 || unresolved[0] != "stray-machine" {
		t.Fatalf("unresolved = %v, want [stray-machine]", unresolved)
	}
	// Longest-prefix: "acme-2-host" belongs to "acme-2", not "acme".
	m, _ := st.MachineByName("acme-2-host")
	if m == nil || m.Org != "acme-2" {
		t.Fatalf("acme-2-host org = %+v, want acme-2", m)
	}
	m, _ = st.MachineByName("acme-web")
	if m == nil || m.Org != "acme" {
		t.Fatalf("acme-web org = %+v, want acme", m)
	}
	// Idempotent: a second run changes nothing.
	filled2, unresolved2, err := st.BackfillMachineOrgs([]string{"acme", "acme-2"})
	if err != nil || filled2 != 0 || len(unresolved2) != 1 {
		t.Fatalf("second pass: filled=%d unresolved=%v err=%v", filled2, unresolved2, err)
	}
}

func TestBackfillAPIKeyOrgs(t *testing.T) {
	st := testStore(t)
	if err := st.CreateAPIKey("legacy", "mach_abc", "exec:*", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.CreateAPIKey("new", "mach_def", "exec:*", "acme"); err != nil {
		t.Fatalf("create: %v", err)
	}
	n, err := st.BackfillAPIKeyOrgs("mach")
	if err != nil || n != 1 {
		t.Fatalf("backfill: n=%d err=%v", n, err)
	}
	_, _, _, org, err := st.APIKeyExists("mach_abc")
	if err != nil || org != "mach" {
		t.Fatalf("org = %q err=%v, want mach", org, err)
	}
	// Idempotent.
	if n, err := st.BackfillAPIKeyOrgs("mach"); err != nil || n != 0 {
		t.Fatalf("second pass: n=%d err=%v", n, err)
	}
}

func TestAPIKeyOrgRoundTrip(t *testing.T) {
	st := testStore(t)
	if err := st.CreateAPIKey("ops", "mach_abc", "exec:*", "acme"); err != nil {
		t.Fatalf("create: %v", err)
	}
	ok, name, scopes, org, err := st.APIKeyExists("mach_abc")
	if err != nil || !ok || name != "ops" || scopes != "exec:*" || org != "acme" {
		t.Fatalf("ok=%v name=%q scopes=%q org=%q err=%v", ok, name, scopes, org, err)
	}
	keys, err := st.ListAPIKeys("acme")
	if err != nil || len(keys) != 1 || keys[0].Org != "acme" {
		t.Fatalf("org list = %+v err=%v", keys, err)
	}
	if others, err := st.ListAPIKeys("other"); err != nil || len(others) != 0 {
		t.Fatalf("other-org list = %+v err=%v", others, err)
	}
}

func TestAuditOrgScoped(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("acme-web", "pub-a", "h", "linux", "amd64", "v", "", false, "acme"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.CreateMachine("xy-web", "pub-b", "h", "linux", "amd64", "v", "", false, "xy"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.AuditInsert(now(), "acme", "acme-web", "echo a", "console:k", sql.NullInt64{Int64: 0, Valid: true}, "a", ""); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := st.AuditInsert(now(), "xy", "xy-web", "echo b", "console:k", sql.NullInt64{Int64: 0, Valid: true}, "b", ""); err != nil {
		t.Fatalf("insert: %v", err)
	}
	acme, err := st.AuditList("acme", "*", 50)
	if err != nil || len(acme) != 1 || acme[0].Org != "acme" || acme[0].Machine != "acme-web" {
		t.Fatalf("acme list = %+v err=%v", acme, err)
	}
	xy, err := st.AuditList("xy", "*", 50)
	if err != nil || len(xy) != 1 || xy[0].Machine != "xy-web" {
		t.Fatalf("xy list = %+v err=%v", xy, err)
	}
	// A cross-org machine filter must return nothing for this org.
	if rows, err := st.AuditList("acme", "xy-web", 50); err != nil || len(rows) != 0 {
		t.Fatalf("cross-org filter = %+v err=%v", rows, err)
	}
}

func TestApprovalsOrgScoped(t *testing.T) {
	st := testStore(t)
	if _, err := st.CreateCommandApproval("acme", "acme-web", "echo a", "echo a", ApprovalScopeOnce, "console:k"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := st.CreateCommandApproval("xy", "xy-web", "echo b", "echo b", ApprovalScopeOnce, "console:k"); err != nil {
		t.Fatalf("create: %v", err)
	}
	pending, err := st.ListCommandApprovals("acme", "pending", 50)
	if err != nil || len(pending) != 1 || pending[0].Org != "acme" {
		t.Fatalf("acme pending = %+v err=%v", pending, err)
	}
}

func TestDeleteOrgRefusesWhenMachinesRemain(t *testing.T) {
	st := testStore(t)
	if err := st.CreateOrg("acme", "test"); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := st.CreateMachine("acme-web", "pub-a", "h", "linux", "amd64", "v", "", false, "acme"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.DeleteOrg("acme"); err == nil {
		t.Fatal("delete of org with machines succeeded; want refusal")
	}
	if exists, _ := st.OrgExists("acme"); !exists {
		t.Fatal("org row was removed despite the machines guard")
	}
	if err := st.CreateMachine("xy-web", "pub-b", "h", "linux", "amd64", "v", "", false, "xy"); err != nil {
		t.Fatalf("create other-org machine: %v", err)
	}
	if n, err := st.CountMachinesInOrg("acme"); err != nil || n != 1 {
		t.Fatalf("count: %d err=%v", n, err)
	}
}

func TestDeleteOrgRemovesMembers(t *testing.T) {
	st := testStore(t)
	if err := st.CreateOrg("acme", "test"); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := st.AddMember("acme", testEmailA, "", "admin", "test"); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := st.DeleteOrg("acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if members, err := st.MembersByEmail(testEmailA); err != nil || len(members) != 0 {
		t.Fatalf("members after org delete = %+v err=%v", members, err)
	}
}

func TestMemberCRUD(t *testing.T) {
	st := testStore(t)
	if err := st.AddMember("acme", testEmailA, "", "admin", "test"); err != nil {
		t.Fatalf("add: %v", err)
	}
	// One identity may hold both a wildcard role and an org binding: the
	// superadmin row is org '*', the admin row is the org itself.
	if err := st.AddMember("", testEmailA, "", "superadmin", "test"); err != nil {
		t.Fatalf("add superadmin: %v", err)
	}
	// Invalid role refused.
	if err := st.AddMember("acme", testEmailA, "", "owner", "test"); err == nil {
		t.Fatal("invalid role accepted")
	}
	// Non-superadmin with wildcard org refused.
	if err := st.AddMember("*", testEmailA, "", "admin", "test"); err == nil {
		t.Fatal("non-superadmin wildcard org accepted")
	}
	// Duplicate binding refused by the unique index.
	if err := st.AddMember("acme", testEmailA, "", "viewer", "test"); err == nil {
		t.Fatal("duplicate membership accepted")
	}
	members, err := st.MembersByEmail(testEmailA)
	if err != nil || len(members) != 2 {
		t.Fatalf("members by email = %+v err=%v", members, err)
	}
	if members[0].Org != "acme" || members[0].Role != "admin" {
		t.Fatalf("first member = %+v", members[0])
	}
	if members[1].Org != "*" || members[1].Role != "superadmin" {
		t.Fatalf("second member = %+v", members[1])
	}
	acme, err := st.ListMembers("acme")
	if err != nil || len(acme) != 1 || acme[0].Role != "admin" {
		t.Fatalf("org members = %+v err=%v", acme, err)
	}
	if err := st.RemoveMember("acme", testEmailA); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if members, err := st.MembersByEmail(testEmailA); err != nil || len(members) != 1 {
		t.Fatalf("members after removal = %+v err=%v", members, err)
	}
	if err := st.RemoveMember("acme", testEmailA); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("removing absent member = %v, want ErrUnknownMember", err)
	}
	// A second identity's rows are untouched by any of the above.
	if err := st.AddMember("acme", testEmailB, "", "viewer", "test"); err != nil {
		t.Fatalf("add second member: %v", err)
	}
	if members, err := st.MembersByEmail(testEmailB); err != nil || len(members) != 1 || members[0].Role != "viewer" {
		t.Fatalf("second member = %+v err=%v", members, err)
	}
}

func TestBackfillLeavesUnresolvableMachinesEmpty(t *testing.T) {
	st := testStore(t)
	if err := st.CreateMachine("acme-web", "pub-a", "h", "linux", "amd64", "v", "", false, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	filled, unresolved, err := st.BackfillMachineOrgs(nil)
	if err != nil || filled != 0 || len(unresolved) != 1 || unresolved[0] != "acme-web" {
		t.Fatalf("filled=%d unresolved=%v err=%v", filled, unresolved, err)
	}
	m, _ := st.MachineByName("acme-web")
	if m == nil || m.Org != "" {
		t.Fatalf("org = %+v, want empty", m)
	}
}

func TestPairingOrgRecordedAtApproval(t *testing.T) {
	st := testStore(t)
	id, token, code, err := st.CreatePairing("pubkey-hex", "host", "", "", "", time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ok, why, err := st.ApprovePairing(id, code, "acme-web", "acme"); err != nil || !ok || why != "" {
		t.Fatalf("approve: ok=%v why=%q err=%v", ok, why, err)
	}
	p := mustPairingByToken(t, st, token)
	if p.Org != "acme" || p.Name != "acme-web" {
		t.Fatalf("pairing = %+v", p)
	}
	consumed, err := st.ConsumePairing(p, "", false)
	if err != nil || !consumed {
		t.Fatalf("consume: %v %v", consumed, err)
	}
	m, err := st.MachineByName("acme-web")
	if err != nil || m == nil || m.Org != "acme" {
		t.Fatalf("machine = %+v err=%v", m, err)
	}
}
