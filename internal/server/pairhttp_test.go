package server

// The browser-side pairing flow, driven over HTTP exactly as a phone would.
//
// This is the seam that hid a real bug: the pair page normalized the submitted
// code before comparing it, while the code had been hashed in its dashed display
// form — so every correct approval was refused, and the QR enrollment path could
// never be completed. The store's tests approved with the raw code, the server
// tests exercised normalizeCode alone, and the e2e asserted only that a correct
// code is *refused* after five wrong attempts — which passed precisely because
// the correct code was refused too.
//
// So this test does the whole loop: pair/start → approve → the pairing is really
// approved.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bcross/mach/internal/protocol"
)

func TestPairApprovalWorksOverHTTP(t *testing.T) {
	s, st := newAuthTestServer(t)
	h := s.Routes()

	// The agent asks to pair.
	code, body := bearerJSON(t, h, "POST", "/v1/pair/start", "",
		`{"pub_key":"`+strings.Repeat("ab", 32)+`","hostname":"h","os":"linux","arch":"amd64"}`)
	if code != http.StatusOK {
		t.Fatalf("pair start: %d (%s)", code, body)
	}
	var start protocol.PairStartResponse
	if err := json.Unmarshal([]byte(body), &start); err != nil {
		t.Fatalf("decode pair start: %v", err)
	}
	if start.Token == "" || start.Code == "" {
		t.Fatalf("pair start returned no token/code: %s", body)
	}
	// The code goes to the agent's console only, and is displayed dashed.
	if !strings.Contains(start.Code, "-") {
		t.Fatalf("challenge code %q is not the dashed display form", start.Code)
	}

	// The operator opens the pair page — never seeing the code — and types it.
	form := url.Values{
		"code":    {start.Code},
		"org":     {"bcross"},
		"name":    {"web-01"}, // machine part; the page composes <org>-<part>
		"approve": {"1"},
	}
	req := httptest.NewRequest("POST", "/pair/"+start.Token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d", rec.Code)
	}
	rendered := rec.Body.String()
	if strings.Contains(rendered, "Wrong code") {
		t.Fatal("the correct challenge code was refused by the pair page")
	}
	if strings.Contains(rendered, "Too many wrong") {
		t.Fatal("the correct code counted as a wrong attempt")
	}

	// And the pairing really is approved, with the composed name.
	p, err := st.PairingByToken(start.Token)
	if err != nil || p == nil {
		t.Fatalf("pairing missing: %v", err)
	}
	if got := st.PairingState(p); got != "approved" {
		t.Fatalf("pairing state = %q, want approved", got)
	}
	if p.Name != "bcross-web-01" {
		t.Fatalf("pairing name = %q, want bcross-web-01", p.Name)
	}

	// The agent completes it, and the machine exists.
	claim := fmt.Sprintf(`{"pub_key":%q,"token":%q,"name":%q}`,
		strings.Repeat("ab", 32), start.Token, "bcross-web-01")
	if code, body := bearerJSON(t, h, "POST", "/v1/pair/claim", "", claim); code != http.StatusOK {
		t.Fatalf("claim: %d (%s)", code, body)
	}
	if m, _ := st.MachineByName("bcross-web-01"); m == nil {
		t.Fatal("the claimed machine was not created")
	}
}

// A wrong code must still be refused — the fix for the above must not have
// turned the comparison into one that accepts anything.
func TestPairApprovalRefusesAWrongCodeOverHTTP(t *testing.T) {
	s, st := newAuthTestServer(t)
	h := s.Routes()

	code, body := bearerJSON(t, h, "POST", "/v1/pair/start", "",
		`{"pub_key":"`+strings.Repeat("cd", 32)+`","hostname":"h"}`)
	if code != http.StatusOK {
		t.Fatalf("pair start: %d (%s)", code, body)
	}
	var start protocol.PairStartResponse
	_ = json.Unmarshal([]byte(body), &start)

	form := url.Values{"code": {"AAAA-AAAA-AAAA"}, "org": {"bcross"}, "name": {"web-01"}, "approve": {"1"}}
	req := httptest.NewRequest("POST", "/pair/"+start.Token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Wrong code") {
		t.Fatal("a wrong challenge code was accepted")
	}
	p, _ := st.PairingByToken(start.Token)
	if p == nil || s.st.PairingState(p) == "approved" {
		t.Fatal("a wrong code approved the pairing")
	}
}

// approvePair drives the pair page for a machine name and returns the rendered
// page plus the pairing's resulting state.
func approvePair(t *testing.T, s *Server, pubHex, name string) (page, state string) {
	t.Helper()
	h := s.Routes()
	code, body := bearerJSON(t, h, "POST", "/v1/pair/start", "",
		`{"pub_key":"`+pubHex+`","hostname":"h"}`)
	if code != http.StatusOK {
		t.Fatalf("pair start: %d (%s)", code, body)
	}
	var start protocol.PairStartResponse
	if err := json.Unmarshal([]byte(body), &start); err != nil {
		t.Fatalf("decode: %v", err)
	}
	org, part, _ := strings.Cut(name, "-")
	form := url.Values{"code": {start.Code}, "org": {org}, "name": {part}, "approve": {"1"}}
	req := httptest.NewRequest("POST", "/pair/"+start.Token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d", rec.Code)
	}
	p, err := s.st.PairingByToken(start.Token)
	if err != nil || p == nil {
		t.Fatalf("pairing missing: %v", err)
	}
	return rec.Body.String(), s.st.PairingState(p)
}

// The name-taken rule lives in ONE place. It used to be duplicated here with a
// simpler condition — "any row with this name" — which disagreed with the store
// about revoked and temporary rows, so a temporary session could retire itself
// and then never come back under its own name.
func TestPairPageAcceptsANameARevokedOrTemporaryMachineHolds(t *testing.T) {
	for _, tc := range []struct {
		what      string
		revoked   bool
		temporary bool
	}{
		{"revoked", true, false},
		{"temporary", false, true},
		{"revoked and temporary", true, true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			s, st := newAuthTestServer(t)
			if err := st.CreateMachine("bcross-tmp", strings.Repeat("11", 32), "h", "linux", "amd64", "v", "", tc.temporary); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if tc.revoked {
				if err := st.RevokeMachine("bcross-tmp"); err != nil {
					t.Fatalf("revoke: %v", err)
				}
			}
			page, state := approvePair(t, s, strings.Repeat("22", 32), "bcross-tmp")
			if strings.Contains(page, "already taken") {
				t.Fatalf("the pair page refused a %s machine's name: %s", tc.what, page)
			}
			if state != "approved" {
				t.Fatalf("pairing state = %q, want approved", state)
			}
		})
	}
}

// And an ACTIVE, permanent machine's name is still refused — the page must not
// have been loosened into accepting anything.
func TestPairPageStillRefusesAnActiveMachinesName(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.CreateMachine("bcross-live", strings.Repeat("33", 32), "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	page, _ := approvePair(t, s, strings.Repeat("44", 32), "bcross-live")
	if !strings.Contains(page, "already taken") {
		t.Fatalf("an active machine's name was offered to a new agent: %s", page)
	}
}
