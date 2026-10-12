package server

// Tests for the secrets page in the web UI. The page's one hard security
// property — values never cross this server — lives in three places, and each
// is pinned here: the push handler refuses a form that arrives with a
// plaintext value field; a missing seal is refused with the CLI fallback
// rather than any plaintext path; and the happy path carries a REAL sealed
// blob through a REAL agent websocket, like a browser's wasm would produce.
// The org scoping (membership on the read, operator-and-better on the write,
// "no such secret" answers outside one's reach) mirrors the machine actions'
// gates and is pinned against probing.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TevaServices/mach/internal/e2e"
	"github.com/TevaServices/mach/internal/oidcauth"
	"github.com/TevaServices/mach/internal/protocol"
	"github.com/TevaServices/mach/internal/store"
)

// seedE2EMachine enrolls a machine like seedMachine does, and gives it a
// REAL X25519 E2E key, which the browser-seal paths need. Returns the E2E
// keypair (to seal against), the identity pubkey hex (to dial with) and the
// identity key (to sign the hello with).
func seedE2EMachine(t *testing.T, st *store.Store, mach, org string) (*e2e.KeyPair, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kp, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("e2e keygen: %v", err)
	}
	if err := st.CreateMachine(mach, hex.EncodeToString(pub), "h", "linux", "amd64", "v", kp.PublicKeyHex(), false, org); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	return kp, hex.EncodeToString(pub), priv
}

// sealForUI produces the sealed blob the browser's wasm would: a fresh
// ephemeral sender key, the SecretPayload sealed to the machine's key.
func sealForUI(t *testing.T, machineKp *e2e.KeyPair, payload protocol.SecretPayload) string {
	t.Helper()
	if _, err := e2e.GenerateKeyPair(); err != nil {
		t.Fatalf("sender keygen: %v", err)
	}
	inner, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	// e2e.Seal makes its own ephemeral sender key per message, which is what
	// the page's wasm does — there is no sender argument to thread through.
	sealed, err := e2e.Seal(machineKp.Public[:], inner)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sealed)
}

// signInAs drives a sign-in whose identity carries exactly one membership:
// role in org (org "" = the superadmin wildcard). Each call replaces the
// server's UI config — the previous session's cookie goes dead with it, so
// callers sign in, act, and sign in again; the role gates under test must not
// ride on a superadmin fixture. Routes() must be built AFTER every
// enableUI here: the /ui route block exists only when s.ui does, so a handler
// list captured before the first enableUI serves no UI at all.
func signInAs(t *testing.T, s *Server, st *store.Store, org, role, subject string) (*http.Cookie, string) {
	t.Helper()
	p := &fakeProvider{ident: oidcauth.Identity{Subject: subject, Email: subject + "@example.com", EmailVerified: true}}
	s.enableUI(p, "http://127.0.0.1:8099/ui/callback", false)
	seeded := false
	if members, err := st.MembersByEmail(p.ident.Email); err != nil {
		t.Fatalf("members: %v", err)
	} else {
		for _, m := range members {
			// A superadmin membership is stored under the wildcard org, not
			// under "", which is the spelling this helper was called with.
			if m.Org == org || (org == "" && m.Role == store.RoleSuperadmin) {
				seeded = true
			}
		}
	}
	if !seeded {
		if err := st.AddMember(org, p.ident.Email, p.ident.Subject, role, "test"); err != nil {
			t.Fatalf("seed member: %v", err)
		}
	}
	return uiSignIn(t, s, p)
}

// machinePubE2E reads one machine's pub_e2e, for asserting on what the page
// carried. Test helper only.
func machinePubE2E(t *testing.T, st *store.Store, mach string) string {
	t.Helper()
	m, err := st.MachineByName(mach)
	if err != nil || m == nil {
		t.Fatalf("machine %s: %v", mach, err)
	}
	return m.PubE2E
}

func TestUISecretsPageIsOrgScoped(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedE2EMachine(t, st, "bcross-web", "bcross")
	seedE2EMachine(t, st, "xy-web", "xy")
	if err := st.UpsertSecret("bcross", "DB_PASSWORD", "console:ops"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecret("xy", "XY_ONLY", "agent"); err != nil {
		t.Fatal(err)
	}
	// Sign in once before Routes(): the /ui route block is registered only
	// while the server has UI config, so a handler list captured before the
	// first enableUI serves no UI at all.
	_, _ = signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
	h := s.Routes()

	t.Run("superadmin sees every org's rows with the org column", func(t *testing.T) {
		session, _ := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
		body := uiGetPage(t, h, session, "/ui/secrets")
		if !strings.Contains(body, "DB_PASSWORD") || !strings.Contains(body, "XY_ONLY") {
			t.Errorf("superadmin page missing a row: %s", body)
		}
		if !strings.Contains(body, `<th scope="col">Org</th>`) {
			t.Error("the superadmin view does not carry the org column")
		}
		if !strings.Contains(body, `data-mach-seal="{`) {
			t.Error("the page does not carry the seal-info map browsers seal with")
		}
	})

	t.Run("an org member sees only their org's rows and keys", func(t *testing.T) {
		session, _ := signInAs(t, s, st, "bcross", store.RoleOperator, "member-1")
		body := uiGetPage(t, h, session, "/ui/secrets")
		if !strings.Contains(body, "DB_PASSWORD") {
			t.Errorf("member page missing their org's row: %s", body)
		}
		if strings.Contains(body, "XY_ONLY") {
			t.Errorf("member page leaked another org's secret name: %s", body)
		}
		if strings.Contains(body, machinePubE2E(t, st, "xy-web")) {
			t.Error("the page carried another org's machine key")
		}
		if !strings.Contains(body, machinePubE2E(t, st, "bcross-web")) {
			t.Error("the member page is missing the key their machines seal with")
		}
	})
}

func TestUISecretPushCarriesARealSealToTheMachine(t *testing.T) {
	s, st := newSecretsTestServer(t)
	kp, pubHex, priv := seedE2EMachine(t, st, "bcross-web", "bcross")
	session, csrf := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
	h := s.Routes()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	ws := dialAgent(t, ts.URL, "bcross-web", pubHex, priv)
	frames := readAgentFrames(ws)

	sealed := sealForUI(t, kp, protocol.SecretPayload{Name: "DB_PASSWORD", Org: "bcross", Value: "s3cr3tvalue"})

	type result struct {
		code int
		body string
	}
	done := make(chan result, 1)
	go func() {
		code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/push",
			"machine=bcross-web&name=DB_PASSWORD&sealed="+sealed, true)
		done <- result{code, body}
	}()

	deadline := time.After(10 * time.Second)
	var reqID string
	for reqID == "" {
		select {
		case env := <-frames:
			if env.Type != "secret_push" {
				continue
			}
			var push protocol.SealedSecretPush
			if err := json.Unmarshal(env.Payload, &push); err != nil {
				t.Fatalf("secret_push payload: %v", err)
			}
			// What arrived is the sealed blob and nothing else: open it with
			// the machine's key, as the agent would, and find the payload.
			raw, err := base64.StdEncoding.DecodeString(push.SealedB64)
			if err != nil {
				t.Fatalf("sealed blob not base64: %v", err)
			}
			opened, err := e2e.Open(&kp.Private, raw)
			if err != nil {
				t.Fatalf("the machine's key cannot open what the page sent: %v", err)
			}
			var sp protocol.SecretPayload
			if err := json.Unmarshal(opened, &sp); err != nil || sp.Name != "DB_PASSWORD" || sp.Org != "bcross" {
				t.Fatalf("desealed payload = %s (%v)", opened, err)
			}
			reqID = env.ReqID
		case <-deadline:
			t.Fatal("no secret_push frame within 10s")
		}
	}
	reply, _ := json.Marshal(protocol.SecretPushResult{Name: "DB_PASSWORD", OK: true})
	if err := ws.WriteJSON(protocol.Envelope{Type: "secret_push_result", ReqID: reqID, Payload: reply}); err != nil {
		t.Fatalf("write result: %v", err)
	}
	res := <-done
	if res.code != http.StatusOK {
		t.Fatalf("push = %d %s", res.code, res.body)
	}
	// The registry learned the NAME and the acting identity, and the fragment
	// refreshed the table with the row.
	rows, err := st.ListSecrets("bcross")
	if err != nil || len(rows) != 1 || rows[0].Name != "DB_PASSWORD" || rows[0].CreatedBy != "ui:op-1" {
		t.Fatalf("registry = %+v err=%v", rows, err)
	}
	if !strings.Contains(res.body, "DB_PASSWORD") {
		t.Errorf("the refreshed fragment does not show the pushed row: %s", res.body)
	}
	if !strings.Contains(res.body, "sealed end-to-end") {
		t.Errorf("the confirmation does not say what actually happened: %s", res.body)
	}
	// And the attempt is in the audit trail as a push whose value stayed sealed.
	audit, err := st.AuditList("bcross", "bcross-web", 10)
	if err != nil || len(audit) == 0 || !strings.Contains(audit[0].Command, "secret push DB_PASSWORD") {
		t.Fatalf("audit = %+v err=%v", audit, err)
	}
}

// The one absolute line of this feature: a form that arrives with a plaintext
// value field is refused WITHOUT dispatch, whatever else it carries. The page
// cannot produce one (the value input has no name), so reaching this refusal
// means someone is trying to make this server hold secrets.
func TestUISecretPushRefusesAPlaintextField(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedE2EMachine(t, st, "bcross-web", "bcross")
	session, csrf := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
	h := s.Routes()
	code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/push",
		"machine=bcross-web&name=DB_PASSWORD&value=s3cr3tvalue", true)
	if code != http.StatusForbidden {
		t.Fatalf("plaintext push = %d %s, want 403", code, body)
	}
	if !strings.Contains(body, "unsealed") {
		t.Errorf("the refusal does not say why: %s", body)
	}
	// Nothing went anywhere: no registry row, and the attempt must not have
	// been turned into a push by dropping the field.
	rows, _ := st.ListSecrets("bcross")
	if len(rows) != 0 {
		t.Fatalf("a plaintext form registered a secret: %+v", rows)
	}
}

// With scripting off the form submits without a seal; the server answers with
// the CLI fallback rather than inventing a plaintext path.
func TestUISecretPushWithoutASealIsCLIReferral(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedE2EMachine(t, st, "bcross-web", "bcross")
	session, csrf := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
	h := s.Routes()
	code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/push",
		"machine=bcross-web&name=DB_PASSWORD", true)
	if code != http.StatusBadRequest || !strings.Contains(body, "mach secrets push") {
		t.Fatalf("seal-less push = %d %s, want 400 with the CLI fallback", code, body)
	}
}

// A name that cannot exist is refused before anything is dispatched, on the
// UI path exactly as on the console API's — one home for the rule.
func TestUISecretPushRefusesInvalidName(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedE2EMachine(t, st, "bcross-web", "bcross")
	session, csrf := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
	h := s.Routes()
	code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/push",
		"machine=bcross-web&name=MACH_TOKEN&sealed=AAAA", true)
	if code != http.StatusBadRequest || !strings.Contains(body, "reserved") {
		t.Fatalf("bad-name push = %d %s", code, body)
	}
}

// The machine gate is uiMayTouchMachineRow: operator-and-better in the
// machine's org, everyone else told nothing exists.
func TestUISecretPushRoleAndOrgGates(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedE2EMachine(t, st, "bcross-web", "bcross")
	seedE2EMachine(t, st, "xy-web", "xy")
	_, _ = signInAs(t, s, st, "", store.RoleSuperadmin, "op-1") // register the UI routes
	h := s.Routes()

	t.Run("a viewer member is told the machine does not exist", func(t *testing.T) {
		session, csrf := signInAs(t, s, st, "bcross", store.RoleViewer, "viewer-1")
		code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/push",
			"machine=bcross-web&name=DB_PASSWORD&sealed=AAAA", true)
		if code != http.StatusNotFound || !strings.Contains(body, "No machine by that name") {
			t.Fatalf("viewer push = %d %s, want 404", code, body)
		}
	})

	t.Run("a member cannot act on another org's machine", func(t *testing.T) {
		session, csrf := signInAs(t, s, st, "bcross", store.RoleOperator, "bcross-op")
		code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/push",
			"machine=xy-web&name=DB_PASSWORD&sealed=AAAA", true)
		if code != http.StatusNotFound {
			t.Fatalf("cross-org push = %d %s, want 404 like an absent machine", code, body)
		}
	})
}

// The E2E-off org refuses pushes — there is no plaintext fallback, from a
// browser or anywhere else — while the NAMES-only delete keeps working, which
// is the point of delete carrying no value.
func TestUISecretPushAndDeleteAroundTheE2EGate(t *testing.T) {
	s, st := newSecretsTestServer(t)
	kp, pubHex, priv := seedE2EMachine(t, st, "bcross-web", "bcross")
	if err := st.SetSetting("e2e:bcross", "off"); err != nil {
		t.Fatal(err)
	}
	_, _ = signInAs(t, s, st, "", store.RoleSuperadmin, "op-1") // register the UI routes
	h := s.Routes()

	t.Run("the page advertises no key while E2E is off", func(t *testing.T) {
		session, _ := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
		body := uiGetPage(t, h, session, "/ui/secrets")
		if strings.Contains(body, kp.PublicKeyHex()) {
			t.Error("the page carried a machine key for an org with sealing off")
		}
		if !strings.Contains(body, "disabled for org") {
			t.Errorf("the page does not say why pushing is unavailable: %s", body)
		}
	})

	t.Run("push is refused and audited", func(t *testing.T) {
		session, csrf := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
		code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/push",
			"machine=bcross-web&name=DB_PASSWORD&sealed=AAAA", true)
		if code != http.StatusForbidden || !strings.Contains(body, "disabled") {
			t.Fatalf("push with E2E off = %d %s", code, body)
		}
		audit, err := st.AuditList("bcross", "bcross-web", 10)
		if err != nil || len(audit) == 0 || !strings.Contains(audit[0].Command, "secret push DB_PASSWORD") {
			t.Fatalf("audit = %+v err=%v", audit, err)
		}
	})

	// A live agent, to prove the names-only delete is not gated behind E2E.
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	ws := dialAgent(t, ts.URL, "bcross-web", pubHex, priv)
	frames := readAgentFrames(ws)

	t.Run("delete works while E2E is off", func(t *testing.T) {
		if err := st.UpsertSecret("bcross", "OLD_KEY", "agent"); err != nil {
			t.Fatal(err)
		}
		session, csrf := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
		type result struct {
			code int
			body string
			loc  string
		}
		done := make(chan result, 1)
		go func() {
			code, body, rec := uiPOST(t, h, session, csrf, "/ui/secrets/delete",
				"org=bcross&name=OLD_KEY&confirm=1&confirm_name=OLD_KEY", false)
			done <- result{code, body, rec.Header().Get("Location")}
		}()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case env := <-frames:
				if env.Type != "secret_delete" {
					continue
				}
				var req protocol.SecretDeleteRequest
				if err := json.Unmarshal(env.Payload, &req); err != nil || req.Name != "OLD_KEY" {
					t.Fatalf("delete payload = %s (%v)", env.Payload, err)
				}
				reply, _ := json.Marshal(protocol.SecretDeleteResult{Name: "OLD_KEY", OK: true})
				_ = ws.WriteJSON(protocol.Envelope{Type: "secret_delete_result", ReqID: env.ReqID, Payload: reply})
			case res := <-done:
				if res.code != http.StatusSeeOther {
					t.Fatalf("delete = %d %s, want 303 redirect", res.code, res.body)
				}
				if !strings.Contains(res.loc, "/ui/secrets?n=secretdeleted") {
					t.Errorf("redirect did not carry the fixed notice: %q", res.loc)
				}
				if known, _ := st.SecretKnown("bcross", "OLD_KEY"); known {
					t.Fatal("the registry row survived the delete")
				}
				return
			case <-deadline:
				t.Fatal("no secret_delete frame or completion within 5s")
			}
		}
	})
}

func TestUISecretDeleteRequiresTheTypedName(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedE2EMachine(t, st, "bcross-web", "bcross")
	if err := st.UpsertSecret("bcross", "DB_PASSWORD", "console:ops"); err != nil {
		t.Fatal(err)
	}
	session, csrf := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
	h := s.Routes()

	t.Run("first post shows the confirmation", func(t *testing.T) {
		code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/delete",
			"org=bcross&name=DB_PASSWORD", true)
		if code != http.StatusOK || !strings.Contains(body, "Type <code>DB_PASSWORD</code>") {
			t.Fatalf("confirm panel = %d %s", code, body)
		}
		if known, _ := st.SecretKnown("bcross", "DB_PASSWORD"); !known {
			t.Fatal("a confirmation render deleted the row")
		}
	})

	t.Run("a mistyped name does not delete", func(t *testing.T) {
		code, _, _ := uiPOST(t, h, session, csrf, "/ui/secrets/delete",
			"org=bcross&name=DB_PASSWORD&confirm=1&confirm_name=DB_PASSWORd", true)
		if code != http.StatusOK {
			t.Fatalf("mistyped confirm = %d", code)
		}
		if known, _ := st.SecretKnown("bcross", "DB_PASSWORD"); !known {
			t.Fatal("a mistyped name deleted the row")
		}
	})
}

// The fan-out: the registry row goes, every reachable machine of the org is
// told to drop the value, and the states an operator must still fix by hand
// are named in the summary — offline machines keep their value, blocked ones
// refuse, and all of it is audited per machine.
func TestUISecretDeleteFansOutAcrossTheOrg(t *testing.T) {
	s, st := newSecretsTestServer(t)
	_, pubHex, priv := seedE2EMachine(t, st, "bcross-web", "bcross")
	seedMachine(t, st, "bcross-offline", "bcross")
	seedMachine(t, st, "bcross-blocked", "bcross")
	if _, err := st.SetMachineBlocked("bcross-blocked", true); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecret("bcross", "DB_PASSWORD", "console:ops"); err != nil {
		t.Fatal(err)
	}
	session, csrf := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
	h := s.Routes()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	ws := dialAgent(t, ts.URL, "bcross-web", pubHex, priv)
	frames := readAgentFrames(ws)

	type result struct {
		code int
		body string
	}
	done := make(chan result, 1)
	go func() {
		code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/delete",
			"org=bcross&name=DB_PASSWORD&confirm=1&confirm_name=DB_PASSWORD", true)
		done <- result{code, body}
	}()

	var replied bool
	deadline := time.After(10 * time.Second)
	for !replied {
		select {
		case env := <-frames:
			if env.Type != "secret_delete" {
				continue
			}
			var req protocol.SecretDeleteRequest
			if err := json.Unmarshal(env.Payload, &req); err != nil || req.Name != "DB_PASSWORD" {
				t.Fatalf("delete payload = %s (%v)", env.Payload, err)
			}
			reply, _ := json.Marshal(protocol.SecretDeleteResult{Name: "DB_PASSWORD", OK: true})
			if err := ws.WriteJSON(protocol.Envelope{Type: "secret_delete_result", ReqID: env.ReqID, Payload: reply}); err != nil {
				t.Fatalf("write result: %v", err)
			}
			replied = true
		case <-deadline:
			t.Fatal("no secret_delete frame within 10s")
		}
	}
	res := <-done
	if res.code != http.StatusOK {
		t.Fatalf("delete = %d %s", res.code, res.body)
	}
	if known, _ := st.SecretKnown("bcross", "DB_PASSWORD"); known {
		t.Fatal("the registry row survived the delete")
	}
	// The summary names what is left to do by hand, not just the success;
	// the other tenant's machine counts as nothing at all.
	for _, want := range []string{
		"1 online machine(s) report clean",
		"1 offline machine(s) keep the value",
		"refused on bcross-blocked",
		"re-registers the name here at its next connect",
	} {
		if !strings.Contains(res.body, want) {
			t.Errorf("summary missing %q: %s", want, res.body)
		}
	}
	audit, err := st.AuditList("bcross", "bcross-blocked", 10)
	if err != nil || len(audit) == 0 || !strings.Contains(audit[0].Command, "secret delete DB_PASSWORD") {
		t.Fatalf("the blocked machine's refusal was not audited: %+v err=%v", audit, err)
	}
}

// The delete's org gate: a viewer member and a non-member both learn
// nothing, the way the machine actions refuse.
func TestUISecretDeleteOrgGate(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedTwoOrgs(t, st)
	if err := st.UpsertSecret("bcross", "DB_PASSWORD", "console:ops"); err != nil {
		t.Fatal(err)
	}
	_, _ = signInAs(t, s, st, "", store.RoleSuperadmin, "op-1") // register the UI routes
	h := s.Routes()

	t.Run("a viewer member is told the row does not exist", func(t *testing.T) {
		session, csrf := signInAs(t, s, st, "bcross", store.RoleViewer, "viewer-1")
		code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/delete",
			"org=bcross&name=DB_PASSWORD", true)
		if code != http.StatusNotFound {
			t.Fatalf("viewer delete = %d %s, want 404", code, body)
		}
	})

	t.Run("a non-member learns nothing", func(t *testing.T) {
		session, csrf := signInAs(t, s, st, "xy", store.RoleOperator, "xy-op")
		code, body, _ := uiPOST(t, h, session, csrf, "/ui/secrets/delete",
			"org=bcross&name=DB_PASSWORD", true)
		if code != http.StatusNotFound {
			t.Fatalf("cross-org delete = %d %s, want 404", code, body)
		}
	})
}

// The secrets POSTs go through uiPost like every other state change: no CSRF
// token, no action.
func TestUISecretsNeedTheCSRFToken(t *testing.T) {
	s, st := newSecretsTestServer(t)
	seedE2EMachine(t, st, "bcross-web", "bcross")
	_, _ = signInAs(t, s, st, "", store.RoleSuperadmin, "op-1") // register the UI routes
	h := s.Routes()
	session, _ := signInAs(t, s, st, "", store.RoleSuperadmin, "op-1")
	// X-CSRF-Token deliberately absent, and the synchronizer token not in the
	// form either — only the session cookie rides along.
	code, _, _ := uiPOST(t, h, session, "", "/ui/secrets/push",
		"machine=bcross-web&name=DB_PASSWORD&sealed=AAAA", true)
	if code != http.StatusForbidden {
		t.Fatalf("push without CSRF = %d, want 403", code)
	}
}
