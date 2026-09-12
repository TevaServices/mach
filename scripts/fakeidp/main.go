// Command fakeidp is a minimal OpenID Connect provider used by scripts/e2e.sh
// to exercise the control plane's web UI end to end.
//
// It exists because the UI's sign-in path cannot be proven with a stub: the
// point of the test is that the real verifier and the real HTTP flow work
// against a real issuer. This speaks just enough of the protocol — a discovery
// document, a JWKS, an /authorize that redirects straight back, and a /token that
// mints an RS256 ID token — and nothing else.
//
// It lives under scripts/ rather than cmd/ because it is never shipped: cmd/ is
// for the two released binaries. It uses only the standard library, so `go build
// ./...` and `go vet ./...` cover it without adding a dependency to the module.
//
// It has no security properties whatsoever and must never be pointed at by a real
// deployment: it authenticates nobody, accepts any authorization code it issued,
// and signs with a key it regenerates on every start.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type server struct {
	issuer   string
	clientID string
	key      *rsa.PrivateKey
	kid      string

	mu sync.Mutex
	// pending maps an issued authorization code to the nonce that request
	// carried, so /token can mint an ID token the caller's nonce check accepts.
	pending map[string]string
	// subject is who every sign-in claims to be.
	subject string
	email   string
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8097", "listen address")
	issuer := flag.String("issuer", "", "issuer URL (default http://<addr>)")
	clientID := flag.String("client-id", "mach-ui", "client id to mint tokens for")
	subject := flag.String("subject", "e2e-operator", "sub claim")
	email := flag.String("email", "e2e@example.com", "email claim")
	flag.Parse()

	if *issuer == "" {
		*issuer = "http://" + *addr
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("fakeidp: keygen: %v", err)
	}
	s := &server{
		issuer: *issuer, clientID: *clientID, key: key, kid: "fakeidp-1",
		pending: map[string]string{}, subject: *subject, email: *email,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/jwks", s.jwks)
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("/token", s.token)

	log.Printf("fakeidp: issuer=%s listening on %s (FOR TESTS ONLY)", s.issuer, *addr)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("fakeidp: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"jwks_uri":                              s.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
	})
}

func (s *server) jwks(w http.ResponseWriter, r *http.Request) {
	e := big.NewInt(int64(s.key.PublicKey.E))
	writeJSON(w, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "kid": s.kid, "use": "sig", "alg": "RS256",
			"n": b64url(s.key.PublicKey.N.Bytes()),
			"e": b64url(e.Bytes()),
		}},
	})
}

// authorize records the nonce against a fresh code and redirects straight back —
// no login form, no consent, no user. The test drives curl, so anything
// interactive would have to be scripted anyway.
func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	code := "code-" + b64url(randomBytes(8))
	s.mu.Lock()
	s.pending[code] = q.Get("nonce")
	s.mu.Unlock()

	u, err := urlWithQuery(redirect, map[string]string{"code": code, "state": q.Get("state")})
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *server) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.FormValue("code")
	s.mu.Lock()
	nonce, ok := s.pending[code]
	delete(s.pending, code)
	s.mu.Unlock()
	if !ok {
		writeJSON(w, map[string]any{"error": "invalid_grant"})
		return
	}
	idt, err := s.idToken(nonce)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idt,
	})
}

// idToken mints a compact JWS over the standard claims. The nonce is whatever
// /authorize was given, which is what lets the control plane's own nonce check
// pass without the test having to reach inside.
func (s *server) idToken(nonce string) (string, error) {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": s.kid, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": s.issuer, "aud": s.clientID, "sub": s.subject,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
		"nonce": nonce, "email": s.email, "email_verified": true, "name": "E2E Operator",
	})
	signing := b64url(header) + "." + b64url(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64url(sig), nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func urlWithQuery(base string, params map[string]string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
