// Package server implements the mach control plane: pairing (QR + API key),
// the agent WebSocket endpoint, the console REST API, and the phone-facing
// approve page. Agents and consoles both dial OUT to this service; it is the
// only publicly reachable component.
package server

import (
	"crypto/ed25519"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bcross/mach/internal/broker"
	"github.com/bcross/mach/internal/store"
	"github.com/gorilla/websocket"
)

type Server struct {
	st           *store.Store
	br           *broker.Broker
	org          string // org prefix for machine names, e.g. "bcross"
	serverKeyHex string // ed25519 public key of this control plane (pinned by agents)
	serverPriv   ed25519.PrivateKey
	pairingTTL   time.Duration
	upgrader     websocket.Upgrader
	trustProxy   bool // trust X-Forwarded-For (set when behind a known TLS proxy)

	// pending execs: reqID -> waiter
	pendMu  sync.Mutex
	pending map[string]*pendingExec

	// pair-start rate limiting: max 5 per IP per 10 minutes
	pairStarts *ipLimiter

	// failed console-auth attempts per client (rate limiting): only actual
	// failures count, max 20 per IP per 10 minutes
	authFails *ipLimiter

	// pair-token lookups (page views, agent polls): generous but bounded
	//
	// Only the endpoints that create state or hash a low-entropy secret need
	// a limiter. Token and API-key lookups are a single indexed probe against
	// a deterministic hash (see store.LookupHash), so an unauthenticated
	// caller cannot make the server do per-request work proportional to a
	// secret's length or to the size of a table — the amplification that used
	// to justify a tighter limit here is gone.
	pairLookups *ipLimiter

	// policyAcks records the fleet-policy version each machine last confirmed,
	// so "which agents are enforcing the current rules" is answerable.
	policyMu   sync.Mutex
	policyAcks map[string]string

	// global exec policy: server-side block list applied to every client
	execPolicy execPolicy

	// cleanup ticker stop
	cleanupStop chan struct{}
}

func New(st *store.Store, br *broker.Broker, org, keyPath string) *Server {
	if org == "" {
		org = "mach"
	}
	s := &Server{
		st:          st,
		br:          br,
		org:         org,
		pairingTTL:  10 * time.Minute,
		upgrader:    websocket.Upgrader{ReadBufferSize: 32 * 1024, WriteBufferSize: 32 * 1024},
		pending:     map[string]*pendingExec{},
		pairStarts:  newIPLimiter(5, 10*time.Minute),
		authFails:   newIPLimiter(20, 10*time.Minute),
		pairLookups: newIPLimiter(600, 10*time.Minute),
		cleanupStop: make(chan struct{}),
	}
	if err := s.loadOrCreateServerKey(keyPath); err != nil {
		// Refusing to start is deliberate: a server that silently rotates
		// its identity key breaks every enrolled agent's update pin.
		panic("server: identity key: " + err.Error())
	}
	if err := s.execPolicy.loadEnv(); err != nil {
		// Also deliberate: booting without a configured block list because a
		// volume was not mounted yet is a silent loss of a security control.
		panic("server: " + execPolicyFileEnv + ": " + err.Error())
	}
	if err := validateE2EEnv(); err != nil {
		// Same reasoning as the policy file: an unusable value must not be
		// ignored, or the operator cannot tell an honoured setting from a typo.
		panic("server: " + err.Error())
	}
	s.logExecPolicy()
	s.logE2E()
	// Housekeeping: purge terminal pairings hourly (keep 24h for forensics),
	// and pick up global exec-policy edits without a restart.
	go func() {
		t := time.NewTicker(time.Hour)
		pt := time.NewTicker(execPolicyPollInterval)
		defer t.Stop()
		defer pt.Stop()
		for {
			select {
			case <-s.cleanupStop:
				return
			case <-t.C:
				n, err := st.CleanupExpiredPairings(24 * time.Hour)
				if err != nil {
					log.Printf("server: pairing cleanup: %v", err)
				} else if n > 0 {
					log.Printf("server: pairing cleanup: removed %d", n)
				}
			case <-pt.C:
				s.pollPolicyOnce()
			}
		}
	}()
	return s
}

// logExecPolicy prints the active global policy at startup (and on reload).
// The rules are logged even when there are none: "the fleet has no server-side
// block list" is itself operational information, and its absence from the log
// is how you would notice the policy was configured in the wrong place.
func (s *Server) logExecPolicy() {
	rules := s.execPolicy.Rules()
	if len(rules) == 0 {
		log.Printf("server: global exec policy: none configured (%s / %s unset)", execPolicyEnv, execPolicyFileEnv)
		return
	}
	log.Printf("server: global exec policy from %s: %s", s.execPolicy.Source(), strings.Join(rules, " "))
}

// logE2E prints the E2E posture at startup: the default, then any org that
// differs from it, with where each came from. Logged in both states for the
// same reason the policy is: "this control plane will refuse sealed commands"
// is operational information, and the absence of a line saying so is how an
// operator ends up believing the wrong thing about it.
func (s *Server) logE2E() {
	defMode, defSource := E2EMode(s.st, "")
	log.Printf("server: e2e: sealed exec %s by default (%s)", defMode, defSource)
	for _, org := range s.ListOrgs() {
		mode, source := E2EMode(s.st, org)
		if mode != defMode {
			log.Printf("server: e2e: org %s: sealed exec %s (%s)", org, mode, source)
			continue
		}
		// Matching the default: say so, without repeating where it came from.
		log.Printf("server: e2e: org %s: sealed exec %s (follows the default)", org, mode)
	}
}

// SetExecPolicy installs global exec rules at runtime and reports what is
// active. Rules replace (never append to) the previous set.
func (s *Server) SetExecPolicy(spec string) {
	s.execPolicy.Replace(spec, "SetExecPolicy")
	s.logExecPolicy()
	s.broadcastFleetPolicy()
}

// SetTrustProxy controls whether X-Forwarded-For is honored. Only enable
// when the service is actually behind the trusted reverse proxy.
func (s *Server) SetTrustProxy(v bool) { s.trustProxy = v }

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Agent side (agent dials out to these)
	mux.HandleFunc("POST /v1/pair/start", s.handlePairStart)
	mux.HandleFunc("POST /v1/pair/status", s.handlePairStatus)
	mux.HandleFunc("POST /v1/pair/claim", s.handlePairClaim)
	mux.HandleFunc("POST /v1/register/apikey", s.handleRegisterAPIKey)
	mux.HandleFunc("GET /v1/agent/ws", s.handleAgentWS)

	// Phone/browser side (approve-on-phone)
	mux.HandleFunc("GET /pair/{token}", s.pairPageHandler)
	mux.HandleFunc("POST /pair/{token}", s.pairPageHandler)

	// Console API (mach CLI, bearer key)
	mux.HandleFunc("GET /v1/machines", s.authConsole(s.handleMachines))
	// E2E key distribution: consoles fetch the target machine's X25519
	// public key (public information; still auth-scoped).
	mux.HandleFunc("GET /v1/machines/{name}/e2epub", s.authConsole(s.handleE2EPub))
	mux.HandleFunc("POST /v1/exec", s.authConsole(s.handleExec))
	mux.HandleFunc("GET /v1/audit", s.authConsole(s.handleAudit))

	// Server management API: machine lifecycle (exec:* keys only). Three
	// distinct axes — block is soft and reversible, revoke is the sticky
	// tombstone, delete removes the machine and frees its name. They are on the
	// console API as well as the web UI so the fleet is operable without a
	// browser, and so scripts/e2e.sh can exercise them without an identity
	// provider.
	mux.HandleFunc("POST /v1/admin/revoke", s.authConsole(s.handleRevokeMachine))
	mux.HandleFunc("POST /v1/admin/block", s.authConsole(s.handleBlockMachine))
	mux.HandleFunc("POST /v1/admin/delete", s.authConsole(s.handleDeleteMachine))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	// Streaming console: live output relay. authConsole
	// works for WS too (bearer header on the upgrade request).
	mux.HandleFunc("GET /v1/console/stream", s.authConsole(func(w http.ResponseWriter, r *http.Request, keyName, scopes string) {
		s.handleConsoleStreamWS(w, r, keyName, scopes)
	}))
	// Enrollment landing page: OS-detected agent downloads.
	mux.HandleFunc("GET /{$}", s.handleEnrollRoot)
	mux.HandleFunc("GET /download/{file}", s.handleAgentDownload)
	return mux
}

// clientIP: trust X-Forwarded-For only when the operator enabled proxy mode.
// With one trusted proxy layer, the RIGHTMOST XFF entry is the one that
// proxy appended (the actual client) — leftmost entries are client-supplied
// and spoofable. The port is always stripped: RemoteAddr carries an
// ephemeral per-connection port, and rate limiting must not key on it.
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			parts := strings.Split(xf, ",")
			host := strings.TrimSpace(parts[len(parts)-1])
			if ip, _, err := net.SplitHostPort(host); err == nil {
				host = ip
			}
			if host != "" {
				return host
			}
		}
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

// maxTrackedIPs caps an ipLimiter's map. It is reachable only under a large
// distributed flood — the case a per-IP limiter cannot help with anyway — and
// the cap exists so that flood cannot turn into unbounded memory growth. At
// the cap we sweep fully-aged-out entries; if that frees nothing we decline to
// track the new source rather than evicting a source already being limited.
const maxTrackedIPs = 50_000

// ipLimiter is a mutex-guarded sliding-window counter per client IP.
// Entries (and keys) that age out of the window are dropped so the map
// cannot grow without bound.
type ipLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	return &ipLimiter{max: max, window: window, hits: map[string][]time.Time{}}
}

// record appends a hit and reports whether the IP is over its limit.
func (l *ipLimiter) record(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	_, tracked := l.hits[ip]
	if !tracked && len(l.hits) >= maxTrackedIPs {
		l.sweepLocked(now)
		if len(l.hits) >= maxTrackedIPs {
			// Nothing to reclaim: allow this request untracked. Every other
			// source keeps its own limit, so single-source floods are still
			// stopped; only a flood wide enough to fill the map escapes it.
			return false
		}
	}
	// Filter in place (write index never passes the read index).
	times := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if now.Sub(t) < l.window {
			times = append(times, t)
		}
	}
	over := len(times) >= l.max
	if !over {
		times = append(times, now)
	}
	if len(times) == 0 {
		delete(l.hits, ip)
		return over
	}
	l.hits[ip] = times
	return over
}

// sweepLocked drops entries whose hits have all aged out. Only called at the
// cap, so it never runs on the hot path.
func (l *ipLimiter) sweepLocked(now time.Time) {
	for ip, times := range l.hits {
		live := false
		for _, t := range times {
			if now.Sub(t) < l.window {
				live = true
				break
			}
		}
		if !live {
			delete(l.hits, ip)
		}
	}
}

// blocked reports whether the IP is at/over its limit without recording
// a hit (for gating requests before validation).
func (l *ipLimiter) blocked(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, t := range l.hits[ip] {
		if now.Sub(t) < l.window {
			n++
		}
	}
	return n >= l.max
}

func (s *Server) logf(format string, args ...any) {
	log.Printf("server: "+format, args...)
}

// hasScope checks a key's scope string covers a capability.
//   - "exec:*" covers exec on any machine
//   - "exec:<name>|<name>" (or comma-separated) covers exec only on the
//     listed machines
//   - "readonly" covers machines + audit reads (no exec)
//   - "enroll" covers API-key enrollment only (not console reads or admin)
func hasScope(scopes, want string) bool {
	for _, s := range strings.Split(scopes, ",") {
		s = strings.TrimSpace(s)
		switch {
		case s == want:
			return true
		case want == "exec" && s == "exec:*":
			return true
		case want == "exec" && strings.HasPrefix(s, "exec:"):
			return true // allowlist check happens against the target machine
		}
	}
	return false
}

// execAllowlist returns the machines an exec-scoped key may touch.
// (nil, true) means unrestricted (exec:* or a non-exec scope the caller has
// already vetted); (names, false) restricts to those machine names,
// case-insensitively. Accepts both allowlist separators: "exec:m1|m2" and
// "exec:m1,m2" (the comma form was the documented one in the store, so bare
// comma segments following an exec: entry are absorbed into its allowlist).
func execAllowlist(scopes string) (allowed []string, all bool) {
	segs := strings.Split(scopes, ",")
	for i := 0; i < len(segs); i++ {
		s := strings.TrimSpace(segs[i])
		if s == "exec:*" {
			return nil, true
		}
		if !strings.HasPrefix(s, "exec:") {
			continue
		}
		allow := strings.TrimPrefix(s, "exec:")
		for j := i + 1; j < len(segs); j++ {
			nxt := strings.TrimSpace(segs[j])
			if nxt == "" || strings.HasPrefix(nxt, "exec:") || nxt == "readonly" || nxt == "enroll" {
				break
			}
			allow += "|" + nxt
			i = j
		}
		for _, m := range splitAny(allow, ",|") {
			if m = strings.ToLower(strings.TrimSpace(m)); m != "" {
				allowed = append(allowed, m)
			}
		}
	}
	return allowed, false
}

func splitAny(s, seps string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(seps, r) })
}

// keyCanExecOn enforces the exec allowlist for scoped keys.
func keyCanExecOn(scopes, machine string) bool {
	allowed, all := execAllowlist(scopes)
	if all {
		return true
	}
	machine = strings.ToLower(machine)
	for _, m := range allowed {
		if m == machine {
			return true
		}
	}
	return false
}
