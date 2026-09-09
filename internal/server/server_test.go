package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHasScope(t *testing.T) {
	cases := []struct {
		scopes, want string
		ok           bool
	}{
		{"exec:*", "exec", true},
		{"exec:*", "enroll", false},
		{"enroll", "enroll", true},
		{"enroll", "exec", false},
		{"readonly", "enroll", false},
		{"exec:bcross-a", "exec", true}, // allowlist keys carry exec capability
		{"exec:bcross-a|bcross-b", "exec", true},
		{"", "exec", false},
		{"readonly", "exec", false},
	}
	for _, c := range cases {
		if got := hasScope(c.scopes, c.want); got != c.ok {
			t.Errorf("hasScope(%q, %q) = %v, want %v", c.scopes, c.want, got, c.ok)
		}
	}
}

func TestKeyCanExecOn(t *testing.T) {
	cases := []struct {
		scopes, machine string
		want            bool
	}{
		{"exec:*", "bcross-a", true},
		{"exec:bcross-a", "bcross-a", true},
		{"exec:bcross-a|bcross-b", "bcross-b", true},
		{"exec:bcross-a|bcross-b", "bcross-c", false},
		{"readonly", "bcross-a", false},
		{"enroll", "bcross-a", false},
	}
	for _, c := range cases {
		if got := keyCanExecOn(c.scopes, c.machine); got != c.want {
			t.Errorf("keyCanExecOn(%q, %q) = %v, want %v", c.scopes, c.machine, got, c.want)
		}
	}
}

func TestListOrgs(t *testing.T) {
	t.Setenv("MACH_ORGS", "alpha, beta,Gamma,gamma,dup,")
	s := New(nil, nil, "https://x", "bcross", t.TempDir()+"/key")
	got := s.ListOrgs()
	want := []string{"bcross", "alpha", "beta", "gamma", "dup"}
	if len(got) != len(want) {
		t.Fatalf("ListOrgs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ListOrgs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestOrgRegistered(t *testing.T) {
	s := New(nil, nil, "https://x", "bcross", t.TempDir()+"/key")
	if !s.orgRegistered("bcross") {
		t.Error("primary org not registered")
	}
	if s.orgRegistered("nope") {
		t.Error("unknown org accepted")
	}
}

func TestNormalizeCode(t *testing.T) {
	cases := [][2]string{
		{"abcd-efgh-jklm", "ABCDEFGHJKLM"},
		{"ABCD EFGH JKLM", "ABCDEFGHJKLM"},
		{"  ab12-cd34-ef56  ", "AB12CD34EF56"},
	}
	for _, c := range cases {
		if got := normalizeCode(c[0]); got != c[1] {
			t.Errorf("normalizeCode(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestPairPageRendersOrgList(t *testing.T) {
	t.Setenv("MACH_ORGS", "alpha,beta")
	s := New(nil, nil, "https://x", "bcross", t.TempDir()+"/key")
	rec := httptest.NewRecorder()
	renderPair(rec, pairPageData{
		Hostname: "host1", OS: "linux", Arch: "arm64", AgentVer: "v1",
		Token: "tok", Orgs: s.ListOrgs(),
	})
	body := rec.Body.String()
	for _, want := range []string{"bcross", "alpha", "beta", "challenge code", "Machine name"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}