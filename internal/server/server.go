// Package server implements the mach control plane: pairing (QR + API key),
// the agent WebSocket endpoint, the console REST API, and the phone-facing
// approve page. Agents and consoles both dial OUT to this service; it is the
// only publicly reachable component.
package server

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/bcross/mach/internal/broker"
	"github.com/bcross/mach/internal/protocol"
	"github.com/bcross/mach/internal/store"
	"github.com/gorilla/websocket"
)

type Server struct {
	st          *store.Store
	br          *broker.Broker
	pubURL      string // public base URL, e.g. https://mach.example.com
	pairingTTL  time.Duration
	upgrader    websocket.Upgrader

	// pending execs: reqID -> waiter
	pendMu  sync.Mutex
	pending map[string]*pendingExec

	// pair-start rate limiting: ip -> start times
	rlMu       sync.Mutex
	pairStarts map[string][]time.Time
}

type pendingExec struct {
	ch      chan protocol.ExecResult
	machine string
	command string
	source  string
}

func New(st *store.Store, br *broker.Broker, pubURL string) *Server {
	return &Server{
		st:         st,
		br:         br,
		pubURL:     pubURL,
		pairingTTL: 10 * time.Minute,
		upgrader:   websocket.Upgrader{ReadBufferSize: 32 * 1024, WriteBufferSize: 32 * 1024},
		pending:    map[string]*pendingExec{},
		pairStarts: map[string][]time.Time{},
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Agent side (agent dials out to these)
	mux.HandleFunc("POST /v1/pair/start", s.handlePairStart)
	mux.HandleFunc("POST /v1/pair/status", s.handlePairStatus)
	mux.HandleFunc("POST /v1/pair/claim", s.handlePairClaim)
	mux.HandleFunc("POST /v1/register/apikey", s.handleRegisterAPIKey)
	mux.HandleFunc("GET /v1/agent/ws", s.handleAgentWS)

	// Phone/browser side (approve-on-phone)
	mux.HandleFunc("GET /pair/{token}", s.handlePairPage)
	mux.HandleFunc("POST /pair/{token}", s.handlePairPage)

	// Console API (mach CLI, bearer key)
	mux.HandleFunc("GET /v1/machines", s.authConsole(s.handleMachines))
	mux.HandleFunc("POST /v1/exec", s.authConsole(s.handleExec))
	mux.HandleFunc("GET /v1/audit", s.authConsole(s.handleAudit))

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

func (s *Server) pairURL(token string) string {
	return s.pubURL + "/pair/" + token
}

// clientIP prefers X-Forwarded-For (reverse proxy) and falls back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		for i := 0; i < len(xf); i++ {
			if xf[i] == ',' {
				return trimSpace(xf[:i])
			}
		}
		return trimSpace(xf)
	}
	return r.RemoteAddr
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// tooManyPairStarts enforces max 5 pair starts per IP per 10 minutes.
func (s *Server) tooManyPairStarts(ip string) bool {
	now := time.Now()
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	times := s.pairStarts[ip][:0]
	for _, t := range s.pairStarts[ip] {
		if now.Sub(t) < 10*time.Minute {
			times = append(times, t)
		}
	}
	if len(times) >= 5 {
		s.pairStarts[ip] = times
		return true
	}
	times = append(times, now)
	s.pairStarts[ip] = times
	return false
}

func (s *Server) logf(format string, args ...any) {
	log.Printf("server: "+format, args...)
}