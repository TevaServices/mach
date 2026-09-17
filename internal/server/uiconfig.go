package server

// Configuration and session state for the control-plane web UI.
//
// The UI is off unless it is fully configured, and it is never served without
// OIDC: with no MACH_OIDC_* variables at all, its routes are not registered and
// the paths 404. A partial configuration is a startup failure rather than a
// silently missing admin surface — an operator who typos one variable should be
// told, not left with a control plane whose UI quietly does not exist.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bcross/mach/internal/oidcauth"
	"github.com/bcross/mach/internal/store"
)

const (
	envOIDCIssuer       = "MACH_OIDC_ISSUER"
	envOIDCClientID     = "MACH_OIDC_CLIENT_ID"
	envOIDCClientSecret = "MACH_OIDC_CLIENT_SECRET"
	envOIDCRedirectURL  = "MACH_OIDC_REDIRECT_URL"
	envOIDCScopes       = "MACH_OIDC_SCOPES"
	envOIDCDomains      = "MACH_OIDC_ALLOWED_DOMAINS"

	// uiProviderTimeout bounds discovery and the token exchange. A sign-in that
	// hangs must not hold a request (or an operator) indefinitely.
	uiProviderTimeout = 10 * time.Second
)

type uiConfig struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
	domains      []string
	insecure     bool // the dev carve-out for an http issuer
	cookieSecure bool

	// mu guards provider. Discovery is lazy: the control plane must start (and
	// keep serving agents) whether or not the identity provider is reachable,
	// and unit tests must never need the network.
	mu       sync.Mutex
	provider oidcauth.Provider

	sessions *uiSessionStore
	logins   *uiLoginStore
	// Separate limiters from s.authFails, so a burst of UI sign-in failures
	// cannot lock out API-key clients and vice versa.
	loginRate    *ipLimiter
	callbackRate *ipLimiter
}

// providerFor returns the identity provider, performing discovery on first use.
//
// A failure is deliberately NOT cached: a transient outage must be retried on
// the next sign-in attempt rather than latching the UI off until a restart.
func (u *uiConfig) providerFor(ctx context.Context) (oidcauth.Provider, error) {
	u.mu.Lock()
	p := u.provider
	u.mu.Unlock()
	if p != nil {
		return p, nil
	}
	// Built outside the lock: discovery is a network round trip, and holding the
	// mutex across it would serialise every sign-in behind the first. Two
	// concurrent first sign-ins may both discover, which is harmless.
	np, err := oidcauth.New(ctx, oidcauth.Config{
		Issuer:              u.issuer,
		ClientID:            u.clientID,
		ClientSecret:        u.clientSecret,
		RedirectURL:         u.redirectURL,
		Scopes:              u.scopes,
		AllowInsecureIssuer: u.insecure,
		AllowDomains:        u.domains,
	})
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	u.provider = np
	u.mu.Unlock()
	return np, nil
}

// loadUIConfig builds the UI configuration from the environment. It returns
// (nil, nil) when the UI is not configured at all, which is the normal case for
// a deployment that does not want one.
func loadUIConfig(publicURL string) (*uiConfig, error) {
	issuer := strings.TrimSpace(os.Getenv(envOIDCIssuer))
	clientID := strings.TrimSpace(os.Getenv(envOIDCClientID))
	secret := strings.TrimSpace(os.Getenv(envOIDCClientSecret))
	redirect := strings.TrimSpace(os.Getenv(envOIDCRedirectURL))

	if issuer == "" && clientID == "" && secret == "" && redirect == "" {
		return nil, nil
	}
	// Something is set, so the operator meant to enable the UI. Name whatever is
	// missing rather than booting with the admin surface absent.
	var missing []string
	if issuer == "" {
		missing = append(missing, envOIDCIssuer)
	}
	if clientID == "" {
		missing = append(missing, envOIDCClientID)
	}
	if secret == "" {
		missing = append(missing, envOIDCClientSecret)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("the web UI is partly configured: set %s, %s and %s together (missing: %s)",
			envOIDCIssuer, envOIDCClientID, envOIDCClientSecret, strings.Join(missing, ", "))
	}

	cookieSecure := strings.HasPrefix(publicURL, "https://")
	// The http-issuer carve-out is granted only when this control plane is
	// itself served over http, which is the dev/loopback case. It disables the
	// check that stops a tampered discovery document relabelling the issuer.
	insecure := strings.HasPrefix(publicURL, "http://")
	if !insecure && !strings.HasPrefix(issuer, "https://") {
		return nil, fmt.Errorf("%s=%q must be https when %s is https", envOIDCIssuer, issuer, "MACH_PUBLIC_URL")
	}

	if redirect == "" {
		if u, err := url.Parse(publicURL); err == nil && u.Path != "" && u.Path != "/" {
			// The mux is mounted at the root, so a path-prefixed public URL would
			// derive a redirect the server cannot serve. Failing here beats an
			// opaque redirect_uri mismatch from the identity provider.
			return nil, fmt.Errorf("%s has a path prefix (%q), so set %s explicitly",
				"MACH_PUBLIC_URL", u.Path, envOIDCRedirectURL)
		}
		redirect = strings.TrimSuffix(publicURL, "/") + "/ui/callback"
	}

	var scopes []string
	if v := strings.TrimSpace(os.Getenv(envOIDCScopes)); v != "" {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				scopes = append(scopes, s)
			}
		}
	}
	var domains []string
	if v := strings.TrimSpace(os.Getenv(envOIDCDomains)); v != "" {
		for _, d := range strings.Split(v, ",") {
			if d = strings.TrimSpace(d); d != "" {
				domains = append(domains, d)
			}
		}
	}

	return &uiConfig{
		issuer:       issuer,
		clientID:     clientID,
		clientSecret: secret,
		redirectURL:  redirect,
		scopes:       scopes,
		domains:      domains,
		insecure:     insecure,
		cookieSecure: cookieSecure,
		sessions:     newUISessionStore(),
		logins:       newUILoginStore(),
		loginRate:    newIPLimiter(30, 10*time.Minute),
		callbackRate: newIPLimiter(20, 10*time.Minute),
	}, nil
}

// ---- sessions ----

const (
	uiSessionCookie = "mach_ui_session"
	uiStateCookie   = "mach_ui_state"
	uiSessionTTL    = 12 * time.Hour
	uiStateTTL      = 10 * time.Minute
	maxUISessions   = 1024
	maxUIStates     = 4096
)

type uiSession struct {
	Ident   oidcauth.Identity
	CSRF    string
	Expires time.Time
}

// sessionDigest derives the map key for a session token. A distinct prefix from
// the API-key lookup hash, so the two can never collide, and a digest rather
// than the token itself so a heap dump or a stray log line yields nothing live.
func sessionDigest(token string) string {
	sum := sha256.Sum256([]byte("mach-ui-session\x00" + token))
	return hex.EncodeToString(sum[:])
}

// uiSessionStore is in-memory and bounded, and surviving nothing is the point:
// no part of UI authorization touches the disk, so a leaked database grants no
// UI access and a restart logs every operator out.
type uiSessionStore struct {
	mu sync.Mutex
	m  map[string]uiSession
}

func newUISessionStore() *uiSessionStore { return &uiSessionStore{m: map[string]uiSession{}} }

// create mints a session and returns the raw token for the cookie. ok is false
// when the store is full of live sessions, so the caller refuses the login
// rather than evicting someone else's.
func (s *uiSessionStore) create(id oidcauth.Identity) (token string, sess uiSession, ok bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.m) >= maxUISessions {
		return "", uiSession{}, false
	}
	token = store.RandToken(32)
	sess = uiSession{Ident: id, CSRF: store.RandToken(32), Expires: now.Add(uiSessionTTL)}
	s.m[sessionDigest(token)] = sess
	return token, sess, true
}

func (s *uiSessionStore) get(token string) (uiSession, bool) {
	if token == "" {
		return uiSession{}, false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[sessionDigest(token)]
	if !ok {
		return uiSession{}, false
	}
	if now.After(sess.Expires) {
		delete(s.m, sessionDigest(token))
		return uiSession{}, false
	}
	return sess, true
}

func (s *uiSessionStore) delete(token string) {
	s.mu.Lock()
	delete(s.m, sessionDigest(token))
	s.mu.Unlock()
}

// sweepLocked drops expired sessions. Called on create, so an idle control plane
// does no work for a store nobody is using.
func (s *uiSessionStore) sweepLocked(now time.Time) {
	for k, v := range s.m {
		if now.After(v.Expires) {
			delete(s.m, k)
		}
	}
}

// ---- pending logins ----

// uiLoginState is one sign-in in flight: the nonce to expect back in the ID
// token, and the binding that ties the callback to the browser that started it.
type uiLoginState struct {
	Nonce   string
	Binding string
	Expires time.Time
}

type uiLoginStore struct {
	mu sync.Mutex
	m  map[string]uiLoginState
}

func newUILoginStore() *uiLoginStore { return &uiLoginStore{m: map[string]uiLoginState{}} }

func (s *uiLoginStore) put(state string, st uiLoginState) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if now.After(v.Expires) {
			delete(s.m, k)
		}
	}
	if len(s.m) >= maxUIStates {
		return false
	}
	s.m[state] = st
	return true
}

// peek returns a pending login without consuming it.
//
// The callback peeks, checks the browser binding, and only then consumes. Doing
// it the other way round — consume, then check — burns the state on any callback
// that fails the binding check, including a stray one from another browser, and
// the legitimate operator's next click then fails with "already used" for a
// reason that has nothing to do with their login.
func (s *uiLoginStore) peek(state string) (uiLoginState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[state]
	if !ok || time.Now().After(st.Expires) {
		return uiLoginState{}, false
	}
	return st, true
}

// consume removes a state, so a replayed callback finds nothing. That is what
// stops a captured authorization code being exchanged twice.
func (s *uiLoginStore) consume(state string) {
	s.mu.Lock()
	delete(s.m, state)
	s.mu.Unlock()
}

// ---- notices ----

// uiNotices maps a fixed code to a fixed sentence. The query parameter is never
// reflected, so the page cannot be made to say anything an attacker chose.
var uiNotices = map[string]string{
	"blocked":    "Machine blocked. It stays connected, but no commands will be dispatched to it until you unblock it.",
	"unblocked":  "Machine unblocked. Commands can be dispatched to it again.",
	"revoked":    "Machine revoked. Its agent has been told to retire, its key can never re-enroll, and its name stays reserved.",
	"deleted":    "Machine deleted. Its name and key are free to enroll again.",
	"orgadded":   "Org added. Machines may now enroll under that prefix.",
	"orgremoved": "Org removed. Existing machines keep working; new enrollment under that prefix stops.",
	"e2eset":     "E2E setting updated for that org.",
	"signedout":  "Signed out.",
}

func uiNoticeText(code string) string { return uiNotices[code] }

// ErrUIFull is returned when the session store is at capacity.
var ErrUIFull = errors.New("too many active sessions")
