// Package server implements the mach control plane: pairing (QR + API key),
// the agent WebSocket endpoint, the console REST API, and the phone-facing
// approve page. Agents and consoles both dial OUT to this service; it is the
// only publicly reachable component.
package server

import (
	"crypto/ed25519"
	"log"
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
	pubURL       string // public base URL, e.g. https://mach.example.com
	org          string // org prefix for machine names, e.g. "bcross"
	serverKeyHex string // ed25519 public key of this control plane (pinned by agents)
	serverPriv   ed25519.PrivateKey
	pairingTTL   time.Duration
	upgrader     websocket.Upgrader
	trustProxy   bool // trust X-Forwarded-For (set when behind a known TLS proxy)

	// pending execs: reqID -> waiter
	pendMu  sync.Mutex
	pending map[string]*pendingExec

	// pair-start rate limiting: ip -> start times
	rlMu       sync.Mutex
	pairStarts map[string][]time.Time

	// failed console-auth attempts per client (rate limiting)
	authFails authLimiter

	// cleanup ticker stop
	cleanupStop chan struct{}
}

func New(st *store.Store, br *broker.Broker, pubURL, org, keyPath string) *Server {
	if org == "" {
		org = "mach"
	}
	s := &Server{
		st:          st,
		br:          br,
		pubURL:      pubURL,
		org:         org,
		pairingTTL:  10 * time.Minute,
		upgrader:    websocket.Upgrader{ReadBufferSize: 32 * 1024, WriteBufferSize: 32 * 1024},
		pending:     map[string]*pendingExec{},
		pairStarts:  map[string][]time.Time{},
		cleanupStop: make(chan struct{}),
	}
	s.loadOrCreateServerKey(keyPath)
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
	mux.HandleFunc("POST /v1/exec", s.authConsole(s.handleExec))
	mux.HandleFunc("GET /v1/audit", s.authConsole(s.handleAudit))

	// Server management API (enroll-scoped keys): revoke + updates
	mux.HandleFunc("POST /v1/admin/revoke", s.authConsole(s.handleRevokeMachine))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("mach control plane\n"))
	})
	return mux
}

// pairURL is no longer needed (QR encodes the URL client-side).
func (s *Server) pairURL(token string) string { return s.pubURL + "/pair/" + token }

// clientIP: trust X-Forwarded-For only when the operator enabled proxy mode.
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			for i := 0; i < len(xf); i++ {
				if xf[i] == ',' {
					return strings.TrimSpace(xf[:i])
				}
			}
			return strings.TrimSpace(xf)
		}
	}
	return r.RemoteAddr
}

// tooManyPairStarts enforces max 5 pair starts per IP per 10 minutes.
func (s *Server) tooManyPairStarts(ip string) bool {
	now := time.Now()
	s.pairStarts[ip] = append(filterRecent(s.pairStarts[ip], now, 10*time.Minute), now)
	return len(s.pairStarts[ip]) > 5
}

func filterRecent(times []time.Time, now time.Time, window time.Duration) []time.Time {
	out := times[:0]
	for _, t := range times {
		if now.Sub(t) < window {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) logf(format string, args ...any) {
	log.Printf("server: "+format, args...)
}

// hasScope checks a key's scope string covers a capability.
//   - "exec:*" covers exec on any machine
//   - "exec:<name>,<name>" covers exec only on the listed machines
//   - "readonly" covers machines + audit reads (no exec)
//   - "enroll" covers API-key enrollment (not console exec)
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

// keyCanExecOn enforces the exec allowlist for scoped keys.
func keyCanExecOn(scopes, machine string) bool {
	for _, s := range strings.Split(scopes, ",") {
		s = strings.TrimSpace(s)
		if s == "exec:*" {
			return true
		}
		if strings.HasPrefix(s, "exec:") {
			for _, m := range strings.Split(strings.TrimPrefix(s, "exec:"), "|") {
				if strings.TrimSpace(m) == machine {
					return true
				}
			}
		}
	}
	return false
}