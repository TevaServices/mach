package oidcauth

// Tests for the real verifier, against a fake issuer on loopback.
//
// The point of these is not the happy path — it is that each verification step
// actually rejects. A verifier that accepts everything passes a happy-path test,
// so every knob below exists to make one specific check fail while everything
// else remains valid: a wrong audience, a wrong issuer, an expired token, a
// replayed nonce, and an unsigned token.
//
// Loopback only, so this needs no network beyond 127.0.0.1.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// fakeIssuer is a minimal OpenID provider: a discovery document, a JWKS, and a
// token endpoint. The knobs each break exactly one verification step.
type fakeIssuer struct {
	ts  *httptest.Server
	key *rsa.PrivateKey
	kid string

	// issuerOverride replaces the iss claim (must still be a valid discovery
	// match for the provider to start, so tests that use it start the provider
	// against the same URL and only lie in the token).
	issuerOverride   string
	audienceOverride string
	nonceOverride    string
	expiry           time.Duration
	algHeader        string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	f := &fakeIssuer{key: key, kid: "test-key-1", expiry: time.Hour}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSONTest(w, map[string]any{
			"issuer":                                f.ts.URL,
			"authorization_endpoint":                f.ts.URL + "/authorize",
			"token_endpoint":                        f.ts.URL + "/token",
			"jwks_uri":                              f.ts.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(f.key.PublicKey.E))
		writeJSONTest(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": f.kid, "use": "sig", "alg": "RS256",
				"n": b64url(f.key.PublicKey.N.Bytes()),
				"e": b64url(e.Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		iss := f.ts.URL
		if f.issuerOverride != "" {
			iss = f.issuerOverride
		}
		aud := "mach-ui"
		if f.audienceOverride != "" {
			aud = f.audienceOverride
		}
		nonce := "the-nonce"
		if f.nonceOverride != "" {
			nonce = f.nonceOverride
		}
		writeJSONTest(w, map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"id_token":     f.signIDToken(t, iss, aud, nonce),
		})
	})
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

// signIDToken mints a compact JWS over the standard claims, honouring the
// broken-step knobs.
func (f *fakeIssuer) signIDToken(t *testing.T, iss, aud, nonce string) string {
	t.Helper()
	alg := "RS256"
	if f.algHeader != "" {
		alg = f.algHeader
	}
	header := map[string]any{"alg": alg, "kid": f.kid, "typ": "JWT"}
	claims := map[string]any{
		"iss": iss, "aud": aud, "sub": "operator-1",
		"exp": time.Now().Add(f.expiry).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
		"nonce": nonce, "email": "op@example.com", "email_verified": true, "name": "Op",
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signing := b64url(hb) + "." + b64url(cb)

	if alg == "none" {
		// The classic algorithm-confusion token: a valid-looking payload with no
		// signature at all.
		return signing + "."
	}
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + b64url(sig)
}

func writeJSONTest(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newTestProvider builds a provider against the fake issuer.
func newTestProvider(t *testing.T, f *fakeIssuer, cfg Config) Provider {
	t.Helper()
	cfg.Issuer = f.ts.URL
	if cfg.ClientID == "" {
		cfg.ClientID = "mach-ui"
	}
	if cfg.RedirectURL == "" {
		cfg.RedirectURL = "http://127.0.0.1:8098/ui/callback"
	}
	// An http loopback issuer is exactly what this carve-out is for.
	cfg.AllowInsecureIssuer = true
	p, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestExchangeAcceptsAValidToken(t *testing.T) {
	f := newFakeIssuer(t)
	p := newTestProvider(t, f, Config{ClientSecret: "s"})

	id, err := p.Exchange(context.Background(), "any-code", "the-nonce")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Subject != "operator-1" {
		t.Fatalf("subject = %q, want operator-1", id.Subject)
	}
	if id.Email != "op@example.com" || !id.EmailVerified {
		t.Fatalf("claims wrong: %+v", id)
	}
}

func TestAuthCodeURL(t *testing.T) {
	f := newFakeIssuer(t)
	p := newTestProvider(t, f, Config{ClientSecret: "s"})

	u := p.AuthCodeURL("state-abc", "nonce-xyz")
	for _, want := range []string{"state=state-abc", "nonce=nonce-xyz", "client_id=mach-ui", "response_type=code"} {
		if !strings.Contains(u, want) {
			t.Fatalf("AuthCodeURL missing %q: %s", want, u)
		}
	}
	// It must point at the discovered authorization endpoint, not a guess.
	if !strings.HasPrefix(u, f.ts.URL+"/authorize") {
		t.Fatalf("AuthCodeURL does not use the discovered endpoint: %s", u)
	}
}

// Each of these breaks exactly one check, with everything else valid. If the
// verifier accepted everything, they would all pass — which is the point.

func TestExchangeRejectsWrongAudience(t *testing.T) {
	f := newFakeIssuer(t)
	f.audienceOverride = "some-other-client"
	p := newTestProvider(t, f, Config{ClientSecret: "s"})
	if _, err := p.Exchange(context.Background(), "c", "the-nonce"); err == nil {
		t.Fatal("a token minted for another client was accepted")
	}
}

func TestExchangeRejectsWrongIssuer(t *testing.T) {
	f := newFakeIssuer(t)
	f.issuerOverride = "https://evil.example.com"
	p := newTestProvider(t, f, Config{ClientSecret: "s"})
	if _, err := p.Exchange(context.Background(), "c", "the-nonce"); err == nil {
		t.Fatal("a token from the wrong issuer was accepted")
	}
}

func TestExchangeRejectsExpiredToken(t *testing.T) {
	f := newFakeIssuer(t)
	f.expiry = -time.Hour
	p := newTestProvider(t, f, Config{ClientSecret: "s"})
	if _, err := p.Exchange(context.Background(), "c", "the-nonce"); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

// The nonce check is ours, not the library's — go-oidc documents that it does
// not verify this field. Without the explicit comparison a captured ID token
// could be replayed into a fresh login.
func TestExchangeRejectsReplayedNonce(t *testing.T) {
	f := newFakeIssuer(t)
	p := newTestProvider(t, f, Config{ClientSecret: "s"})
	if _, err := p.Exchange(context.Background(), "c", "a-different-nonce"); err == nil {
		t.Fatal("a token minted for another login's nonce was accepted")
	}
	// An empty expected nonce must not match a token that simply has none.
	f2 := newFakeIssuer(t)
	f2.nonceOverride = ""
	p2 := newTestProvider(t, f2, Config{ClientSecret: "s"})
	if _, err := p2.Exchange(context.Background(), "c", ""); err == nil {
		t.Fatal("an empty nonce was accepted; the check must not degrade to 'absent is fine'")
	}
}

// "alg: none" is the classic algorithm-confusion token. It is refused by the
// pinned allowlist, not by the signature being wrong — there is no signature.
func TestExchangeRejectsUnsignedToken(t *testing.T) {
	f := newFakeIssuer(t)
	f.algHeader = "none"
	p := newTestProvider(t, f, Config{ClientSecret: "s"})
	if _, err := p.Exchange(context.Background(), "c", "the-nonce"); err == nil {
		t.Fatal("an unsigned (alg:none) token was accepted")
	}
}

func TestNewRejectsUnreachableIssuer(t *testing.T) {
	// A closed listener: discovery cannot succeed.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	_, err := New(context.Background(), Config{
		Issuer: dead.URL, ClientID: "mach-ui", AllowInsecureIssuer: true,
	})
	if err == nil {
		t.Fatal("New accepted an unreachable issuer")
	}
}

// An http issuer is refused unless the operator explicitly opted into the
// carve-out. Without this, a typo'd issuer would silently downgrade discovery.
func TestNewRefusesInsecureIssuerWithoutOptIn(t *testing.T) {
	f := newFakeIssuer(t)
	_, err := New(context.Background(), Config{Issuer: f.ts.URL, ClientID: "mach-ui"})
	if err == nil {
		t.Fatal("an http issuer was accepted without AllowInsecureIssuer")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("refusal does not mention https: %v", err)
	}
}

func TestNewRequiresIssuerAndClientID(t *testing.T) {
	if _, err := New(context.Background(), Config{ClientID: "x"}); err == nil {
		t.Fatal("New accepted an empty issuer")
	}
	if _, err := New(context.Background(), Config{Issuer: "https://x.example"}); err == nil {
		t.Fatal("New accepted an empty client id")
	}
}

// The domain allowlist is off by default — "any verified identity" is the
// configured policy — but the seam has to actually work when it is set.
func TestDomainAllowlist(t *testing.T) {
	f := newFakeIssuer(t)

	// Off: the fake's example.com address signs in.
	p := newTestProvider(t, f, Config{ClientSecret: "s"})
	if _, err := p.Exchange(context.Background(), "c", "the-nonce"); err != nil {
		t.Fatalf("empty allowlist should permit any identity: %v", err)
	}

	// A matching domain, with and without a leading @ and in either case.
	for _, d := range []string{"example.com", "@example.com", "EXAMPLE.COM"} {
		p := newTestProvider(t, f, Config{ClientSecret: "s", AllowDomains: []string{d}})
		if _, err := p.Exchange(context.Background(), "c", "the-nonce"); err != nil {
			t.Fatalf("allowed domain %q was refused: %v", d, err)
		}
	}

	// A different domain is refused.
	p = newTestProvider(t, f, Config{ClientSecret: "s", AllowDomains: []string{"elsewhere.test"}})
	if _, err := p.Exchange(context.Background(), "c", "the-nonce"); err == nil {
		t.Fatal("an identity outside the allowlist signed in")
	}
}

// A provider that sends email_verified as a string must not have its whole
// claims decode fail — that would reject a valid login and look like a
// signature problem.
func TestEmailVerifiedAcceptsStringForm(t *testing.T) {
	var b boolish
	if err := b.UnmarshalJSON([]byte(`"true"`)); err != nil || !bool(b) {
		t.Fatalf("string true: %v %v", bool(b), err)
	}
	if err := b.UnmarshalJSON([]byte(`true`)); err != nil || !bool(b) {
		t.Fatalf("bool true: %v %v", bool(b), err)
	}
	if err := b.UnmarshalJSON([]byte(`"false"`)); err != nil || bool(b) {
		t.Fatalf("string false: %v %v", bool(b), err)
	}
	if err := b.UnmarshalJSON([]byte(`null`)); err != nil || bool(b) {
		t.Fatalf("null: %v %v", bool(b), err)
	}
}
