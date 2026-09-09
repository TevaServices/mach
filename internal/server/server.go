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
	pairLookups *ipLimiter

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
		pairLookups: newIPLimiter(240, 10*time.Minute),
		cleanupStop: make(chan struct{}),
	}
	if err := s.loadOrCreateServerKey(keyPath); err != nil {
		// Refusing to start is deliberate: a server that silently rotates
		// its identity key breaks every enrolled agent's update pin.
		panic("server: identity key: " + err.Error())
	}
	// Housekeeping: purge terminal pairings hourly (keep 24h for forensics).
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
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
			}
		}
	}()
	return s
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

	// Server management API: machine revocation (exec:* keys only)
	mux.HandleFunc("POST /v1/admin/revoke", s.authConsole(s.handleRevokeMachine))

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
	l.hits[ip] = times
	return over
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
