// Package oidcauth is the control plane's OIDC sign-in: discovery-backed ID
// token verification behind a deliberately narrow seam, so the login handlers
// can be tested against a fake and no request path talks to the identity
// provider unless a human is actually signing in.
//
// It is a separate package rather than a file in internal/server for two
// reasons: the verifier needs neither a store nor the control plane's identity
// key, and the tests that prove it actually rejects a bad token need a fake
// issuer rather than a fake verifier — the opposite arrangement from the
// handler tests.
//
// The verification itself is delegated to github.com/coreos/go-oidc/v3 rather
// than hand-written. Writing it by hand means writing JWKS fetching, key
// rotation, `kid` selection, algorithm allowlisting and exp/nbf/iat validation —
// every one of them a known CVE pattern — inside the one component whose
// compromise means control of every machine on the fleet.
package oidcauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is the verified result of a login — the only thing the rest of the
// control plane is allowed to know about it.
//
// Subject is the audit key: it is what an operator action is attributed to.
// Email and Name are for display, and EmailVerified is reported rather than
// enforced, because the configured policy is "any verified identity" and
// silently gating on a claim the operator did not ask to gate on would be a
// surprising place to hide a decision.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Config is everything the verifier needs. It is built from the environment by
// the caller; nothing here reads it.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Scopes defaults to openid, email, profile.
	Scopes []string

	// AllowInsecureIssuer permits an http:// issuer, and lets discovery work
	// when the issuer the provider reports differs from the discovery URL. It
	// must only ever be set when the control plane itself is served over http,
	// because it disables the check that stops a tampered discovery document
	// from relabelling the issuer. Same carve-out the agent already makes for
	// update fetches.
	AllowInsecureIssuer bool

	// AllowDomains, when non-empty, restricts sign-in to those email domains
	// (case-insensitive, no leading "@"). Empty means any verified identity may
	// sign in, which is the configured policy — it is here so that tightening it
	// later is a configuration change rather than a code change.
	AllowDomains []string
}

// Provider is the entire surface the login handlers need, and nothing else.
type Provider interface {
	// AuthCodeURL builds the redirect to the identity provider for a state and
	// nonce pair.
	AuthCodeURL(state, nonce string) string

	// Exchange consumes an authorization code and returns the verified identity.
	// It checks the nonce, which the OIDC library deliberately leaves to the
	// caller.
	Exchange(ctx context.Context, code, nonce string) (Identity, error)
}

// signingAlgs is the algorithm allowlist. Asymmetric only: HS* would let a
// client that knows the shared secret mint tokens, and "none" is the classic
// algorithm-confusion attack. Being explicit also stops a provider's advertised
// list from silently widening what this control plane accepts.
var signingAlgs = []string{"RS256", "ES256", "PS256"}

type goOIDC struct {
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	// allow is the lowercased domain allowlist; empty means any.
	allow []string
}

// New performs discovery and returns a ready provider. It contacts the identity
// provider, so callers do it lazily — on the first sign-in attempt, not at
// startup — to keep the control plane serving agents whether or not the IdP is
// reachable, and to keep unit tests off the network.
func New(ctx context.Context, cfg Config) (Provider, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("oidcauth: issuer is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("oidcauth: client id is required")
	}
	if !cfg.AllowInsecureIssuer && !strings.HasPrefix(cfg.Issuer, "https://") {
		return nil, fmt.Errorf("oidcauth: issuer %q must be https", cfg.Issuer)
	}

	dctx := ctx
	if cfg.AllowInsecureIssuer {
		// Only reachable on a loopback/dev control plane, where the issuer
		// legitimately reports an http URL and there is no TLS to mismatch.
		dctx = oidc.InsecureIssuerURLContext(ctx, cfg.Issuer)
	}
	p, err := oidc.NewProvider(dctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: discovery against %s: %w", cfg.Issuer, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return &goOIDC{
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: signingAlgs}),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		allow: normalizeDomains(cfg.AllowDomains),
	}, nil
}

func normalizeDomains(in []string) []string {
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "@")))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func (g *goOIDC) AuthCodeURL(state, nonce string) string {
	// AccessTypeOnline: this control plane has no use for a refresh token, and
	// asking for one would make it a credential worth stealing.
	return g.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.AccessTypeOnline)
}

func (g *goOIDC) Exchange(ctx context.Context, code, nonce string) (Identity, error) {
	tok, err := g.oauth.Exchange(ctx, code)
	if err != nil {
		return Identity{}, fmt.Errorf("oidcauth: token exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, errors.New("oidcauth: token response carried no id_token (is the openid scope granted?)")
	}
	// Signature, issuer, audience and expiry are the library's to check.
	idt, err := g.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("oidcauth: id token: %w", err)
	}
	// The nonce is ours. The library documents that it does not verify this
	// field, and it is what stops a captured ID token being replayed into a
	// fresh login.
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		return Identity{}, errors.New("oidcauth: id token nonce does not match this login")
	}
	if idt.Subject == "" {
		return Identity{}, errors.New("oidcauth: id token carries no subject")
	}

	var claims struct {
		Email         string  `json:"email"`
		EmailVerified boolish `json:"email_verified"`
		Name          string  `json:"name"`
	}
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("oidcauth: id token claims: %w", err)
	}
	if !g.domainAllowed(claims.Email) {
		return Identity{}, fmt.Errorf("oidcauth: %q is not in an allowed email domain", claims.Email)
	}
	return Identity{
		Subject:       idt.Subject,
		Email:         claims.Email,
		EmailVerified: bool(claims.EmailVerified),
		Name:          claims.Name,
	}, nil
}

// domainAllowed reports whether the signed-in email is permitted. An empty
// allowlist permits everyone — that is the configured policy, not an oversight.
func (g *goOIDC) domainAllowed(email string) bool {
	if len(g.allow) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range g.allow {
		if domain == d {
			return true
		}
	}
	return false
}

// boolish tolerates the two spellings identity providers use for a boolean
// claim: `true` and `"true"`. Decoding straight into a bool would fail the whole
// claims decode on a provider that sends the string form, turning a valid login
// into a rejection — and the failure would look like a signature problem.
type boolish bool

func (b *boolish) UnmarshalJSON(data []byte) error {
	s := strings.ToLower(strings.Trim(string(data), `"`))
	switch s {
	case "true", "1", "yes":
		*b = true
	default:
		*b = false
	}
	return nil
}
