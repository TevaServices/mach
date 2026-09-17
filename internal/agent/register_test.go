package agent

// Tests for what the QR carries.
//
// The pre-fill exists to shorten the phone flow, and it is bounded by two rules
// worth testing directly: the challenge code is never part of it (a photograph of
// the QR must stay useless on its own), and whatever name the hostname yields has
// to be one the control plane will accept — a suggestion the pair page shows and
// the store then refuses is worse than no suggestion.

import (
	"net/url"
	"strings"
	"testing"
)

func TestSuggestMachinePartFoldsAHostnameIntoAName(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"web-01", "web-01"},
		{"Web-01.Example.COM", "web-01"}, // lowercased, domain dropped
		{"my laptop", "my-laptop"},       // a space folds to one hyphen
		{"a__b.c", "a-b"},                // a run of them still folds to one
		{"box-01.corp.internal", "box-01"},
		{"", ""},    // nothing to suggest
		{"...", ""}, // a domain with no host part
		{"---", ""}, // nothing but separators
		{"_", ""},
		{strings.Repeat("x", 80), strings.Repeat("x", 48)}, // capped, not truncated mid-hyphen
	} {
		if got := suggestMachinePart(tc.host); got != tc.want {
			t.Errorf("suggestMachinePart(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

// The property that matters end to end: every name this produces is one the
// control plane will accept. The rule it satisfies is store.ValidMachinePart
// (1-48 characters of [A-Za-z0-9-]); internal/agent deliberately does not import
// internal/store to reuse the function — that package drags in both SQL drivers,
// and this binary ships to every target — so the agreement is asserted here and
// again across the seam in scripts/e2e.sh, which checks that the name in the QR
// comes back out of the pair page unchanged.
func TestSuggestedMachinePartsSatisfyTheNameRule(t *testing.T) {
	hosts := []string{
		"web-01", "Web-01.Example.COM", "my laptop", "a__b.c", "box-01.corp.internal",
		"", "...", "---", "_", strings.Repeat("x", 80), "Ünïcödé-Host", "host:with:colons",
		"127.0.0.1", "-leading-and-trailing-",
	}
	for _, h := range hosts {
		got := suggestMachinePart(h)
		if got == "" {
			continue // "no suggestion" is always acceptable; the field starts empty
		}
		if len(got) < 1 || len(got) > 48 {
			t.Errorf("suggestMachinePart(%q) = %q, length outside 1-48", h, got)
		}
		for _, r := range got {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				t.Errorf("suggestMachinePart(%q) = %q, which contains %q", h, got, r)
			}
		}
		if strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") {
			t.Errorf("suggestMachinePart(%q) = %q, which starts or ends with a hyphen", h, got)
		}
	}
}

// pairPrefill is the whole of what the QR adds, and it must add exactly two
// things. In particular it must never carry the challenge code: that code is
// what makes photographing the QR insufficient, and it is passed to this
// function nowhere — this test is the guard on that staying true.
func TestPairPrefillCarriesTheOrgAndNameOnly(t *testing.T) {
	q := pairPrefill("BCross", "web-01.example.com")
	v, err := url.ParseQuery(q)
	if err != nil {
		t.Fatalf("the prefill is not a query string: %v", err)
	}
	if got := v.Get("org"); got != "bcross" {
		t.Errorf("org = %q, want the lowercased org", got)
	}
	if got := v.Get("name"); got != "web-01" {
		t.Errorf("name = %q, want the machine part folded from the hostname", got)
	}
	if len(v) != 2 {
		t.Errorf("prefill carries %d parameters, want exactly org and name: %q", len(v), q)
	}
	// A hostname that folds away to nothing contributes nothing rather than an
	// empty parameter the page would then have to special-case.
	if q := pairPrefill("bcross", "..."); q != "org=bcross" {
		t.Errorf("pairPrefill with no usable hostname = %q, want just the org", q)
	}
	if q := pairPrefill("", "..."); q != "" {
		t.Errorf("pairPrefill with nothing to say = %q, want empty", q)
	}
}
