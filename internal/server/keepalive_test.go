package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
	"github.com/gorilla/websocket"
)

// keepaliveServer starts a handler wired exactly like the agent pump's
// keepalive — startPings, plus a pong-refreshing deadline when refreshDeadline
// is set — at test-sized intervals, and reports how long its read loop ran.
// With the pinger and the pong handler both left out this is the pre-fix
// shape, which is the negative control: the deadline fires on an idle
// connection.
func keepaliveServer(t *testing.T, refreshDeadline bool, interval, idle time.Duration) (url string, ranFor <-chan time.Duration) {
	t.Helper()
	up := websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024}
	ranCh := make(chan time.Duration, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		conn := protocol.NewWSConn(ws)
		if refreshDeadline {
			ws.SetPongHandler(func(string) error {
				return ws.SetReadDeadline(time.Now().Add(idle))
			})
		}
		pingDone := make(chan struct{})
		defer close(pingDone)
		go startPings(conn.Ping, interval, pingDone)
		start := time.Now()
		for {
			_ = ws.SetReadDeadline(time.Now().Add(idle))
			if _, err := conn.ReadEnvelope(); err != nil {
				ranCh <- time.Since(start)
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/", ranCh
}

// The client half of the harness: connect and read continuously, which is
// what makes gorilla answer the server's pings with pongs.
func keepaliveClient(t *testing.T, url string, answerPongs bool) {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { ws.Close() })
	if answerPongs {
		go func() {
			for {
				if _, _, err := ws.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}
}

// An answering agent is never dropped, however idle: the pinger provokes
// pongs, the pong handler refreshes the deadline, and the connection outlives
// several times the deadline it would meet if nothing refreshed it. This is
// the regression test for the fleet flapping (idle connections cut at exactly
// 90s), which happened because agent pings are control frames a read loop
// never sees.
func TestAgentKeepaliveKeepsIdleConnectionAlive(t *testing.T) {
	const interval, idle = 50 * time.Millisecond, 200 * time.Millisecond
	url, ranFor := keepaliveServer(t, true, interval, idle)
	keepaliveClient(t, url, true)

	// 1s is 5× the unrefreshed deadline: without the pings and the pong
	// handler the read loop has long since returned by now.
	select {
	case d := <-ranFor:
		t.Fatalf("idle connection cut after %v — the keepalive did not refresh the deadline", d)
	case <-time.After(time.Second):
	}
}

// A dead or black-holed agent — one that stops answering pongs — is still
// detected, within one idle timeout of its last life sign. The fix must keep
// that property, not remove the deadline.
func TestAgentKeepaliveDetectsDeadAgent(t *testing.T) {
	const interval, idle = 50 * time.Millisecond, 200 * time.Millisecond
	url, ranFor := keepaliveServer(t, true, interval, idle)
	// Connected, and deliberately not reading: gorilla answers pings only
	// while a read is in progress, so this client never pongs.
	keepaliveClient(t, url, false)

	select {
	case d := <-ranFor:
		if d > 3*idle {
			t.Fatalf("silent agent dropped after %v, want within a few of %v", d, idle)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a silent agent was not dropped within the idle timeout")
	}
}

// The negative control — the pre-fix shape, a deadline nothing refreshes —
// drops even a healthy, answering agent, at the deadline.
func TestAgentKeepaliveWithoutPingsDropsIdleConnection(t *testing.T) {
	const interval, idle = 50 * time.Millisecond, 200 * time.Millisecond
	url, ranFor := keepaliveServer(t, false, interval, idle)
	keepaliveClient(t, url, true)

	select {
	case d := <-ranFor:
		if d > 3*idle {
			t.Fatalf("answering agent dropped after %v, want at about %v", d, idle)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a deadline nothing refreshed never fired")
	}
}

// startPings itself: stops when told to, and stops at the first failed ping.
func TestStartPingsStops(t *testing.T) {
	var n atomic.Int64
	done := make(chan struct{})
	go startPings(func() error { n.Add(1); return nil }, 10*time.Millisecond, done)
	deadline := time.Now().Add(time.Second)
	for n.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if n.Load() < 3 {
		t.Fatalf("pinger sent %d pings in 1s, want >= 3", n.Load())
	}
	close(done)
	stopped := n.Load()
	time.Sleep(50 * time.Millisecond)
	if n.Load() != stopped {
		t.Fatalf("pinger kept sending after done: %d -> %d", stopped, n.Load())
	}
}

func TestStartPingsStopsOnPingFailure(t *testing.T) {
	var n atomic.Int64
	done := make(chan struct{})
	go startPings(func() error {
		n.Add(1)
		return errFakePing
	}, 10*time.Millisecond, done)
	deadline := time.Now().Add(time.Second)
	for n.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := n.Load(); got != 1 {
		t.Fatalf("pinger called failed ping %d times, want 1", got)
	}
}

var errFakePing = errors.New("fake ping failure")
