package server

import "time"

// agentIdleTimeout bounds one quiet direction of an agent connection: how long
// it may go without a pong or a frame. agentPingInterval is how often the
// control plane pings to keep that from firing on a healthy idle agent. The
// two are the agent path's twin of the console stream's
// (streamPingInterval/consoleStreamIdle) — same intervals, for the same
// reason: a deadline refreshed only by data frames is not a keepalive on a
// quiet fleet, because the other side's pings are control frames a read loop
// never sees.
const (
	agentIdleTimeout  = 90 * time.Second
	agentPingInterval = 30 * time.Second
)

// startPings sends a websocket-level ping every interval until done closes,
// stopping early if a ping write fails — a failed write means the connection
// is already broken, and the read loop will learn that at its own deadline
// without the pinger saying more about it.
func startPings(ping func() error, interval time.Duration, done <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if ping() != nil {
				return
			}
		}
	}
}
