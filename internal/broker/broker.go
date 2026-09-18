// Package broker tracks live agent connections and console subscribers.
// The control plane holds one outbound-registered connection per machine
// (the agent dials in; nothing listens on the agent side).
package broker

import (
	"log"
	"sync"
	"time"

	"github.com/bcross/mach/internal/protocol"
)

type AgentConn struct {
	Name     string
	Conn     *protocol.WSConn
	LastSeen time.Time
	Hostname string
	OS       string
	Arch     string
	AgentVer string
}

type Broker struct {
	mu      sync.RWMutex
	agents  map[string]*AgentConn                 // by machine name
	waiters map[string]map[chan struct{}]struct{} // name -> waiters for reconnect
	streams map[string]*streamBinding             // sessionID -> console relay
}

func New() *Broker {
	return &Broker{
		agents:  map[string]*AgentConn{},
		waiters: map[string]map[chan struct{}]struct{}{},
	}
}

// Add registers a live agent connection (agent just completed hello).
func (b *Broker) Add(a *AgentConn) {
	b.mu.Lock()
	if old, ok := b.agents[a.Name]; ok && old != a {
		// A previous connection exists; drop it (agent reconnect replaced it).
		go old.Conn.Close()
	}
	b.agents[a.Name] = a
	// Wake anything waiting on this machine's reconnect.
	var waiters []chan struct{}
	for ch := range b.waiters[a.Name] {
		waiters = append(waiters, ch)
	}
	b.mu.Unlock()
	log.Printf("broker: agent online: %s (%s/%s %s)", a.Name, a.OS, a.Arch, a.AgentVer)
	for _, ch := range waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Remove drops the agent connection if it is still the same one.
func (b *Broker) Remove(a *AgentConn) {
	b.mu.Lock()
	if cur, ok := b.agents[a.Name]; ok && cur == a {
		delete(b.agents, a.Name)
	}
	b.mu.Unlock()
	log.Printf("broker: agent offline: %s", a.Name)
}

func (b *Broker) Get(name string) *AgentConn {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.agents[name]
}

// WaitOnline blocks until the named agent is connected or timeout elapses.
func (b *Broker) WaitOnline(name string, timeout time.Duration) *AgentConn {
	deadline := time.Now().Add(timeout)
	for {
		if a := b.Get(name); a != nil {
			return a
		}
		if time.Now().After(deadline) {
			return nil
		}
		// Re-check shortly; sufficient for a fleet-scale broker.
		ch := b.registerWaiter(name)
		remaining := time.Until(deadline)
		if remaining > 200*time.Millisecond {
			remaining = 200 * time.Millisecond
		}
		select {
		case <-ch:
		case <-time.After(remaining):
		}
		b.dropWaiter(name, ch)
	}
}

func (b *Broker) registerWaiter(name string) chan struct{} {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	if b.waiters == nil {
		b.waiters = map[string]map[chan struct{}]struct{}{}
	}
	if b.waiters[name] == nil {
		b.waiters[name] = map[chan struct{}]struct{}{}
	}
	b.waiters[name][ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Broker) dropWaiter(name string, ch chan struct{}) {
	b.mu.Lock()
	if set := b.waiters[name]; set != nil {
		delete(set, ch)
		if len(set) == 0 {
			delete(b.waiters, name)
		}
	}
	b.mu.Unlock()
}

// List returns snapshot info for all registered machines known to the broker.
func (b *Broker) OnlineNames() map[string]bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := map[string]bool{}
	for name := range b.agents {
		out[name] = true
	}
	return out
}

// Each calls fn for every live agent connection. The slice is a snapshot, so fn
// may take its time (writing a frame, say) without holding the broker's lock or
// racing a concurrent disconnect.
func (b *Broker) Each(fn func(*AgentConn)) {
	b.mu.RLock()
	conns := make([]*AgentConn, 0, len(b.agents))
	for _, a := range b.agents {
		conns = append(conns, a)
	}
	b.mu.RUnlock()
	for _, a := range conns {
		fn(a)
	}
}

// ---- streaming session binding (console ↔ agent relay) ----

// BindStream registers a console session's delivery channel against the
// machine's live agent connection. The agent pump sends frames tagged with
// the session ID here; SendToStream pushes them to the bound channel.
func (b *Broker) BindStream(sessionID string, console chan protocol.Envelope, machine string) {
	b.mu.Lock()
	if b.streams == nil {
		b.streams = map[string]*streamBinding{}
	}
	b.streams[sessionID] = &streamBinding{machine: machine, console: console}
	b.mu.Unlock()
}

// UnbindStream drops the binding (console disconnect or stream end).
func (b *Broker) UnbindStream(sessionID string) {
	b.mu.Lock()
	delete(b.streams, sessionID)
	b.mu.Unlock()
}

// SendToStream routes a frame to the bound console channel, if any.
//
// A full buffer drops an output chunk — that is the documented best-effort trade,
// and it is what keeps a console that has stopped reading from stalling the agent
// pump that serves every other command on the connection.
//
// The terminal record is the exception, and it is not a nicety. stream_end is how
// the console learns the exit status, and a console that never receives one waits
// forever: it has no read deadline (the relay's own pings keep the socket healthy
// even when nothing else arrives), so a dropped terminal frame is an interactive
// session that hangs with no output and no status, and an audit row written as
// "the command's fate on the machine is unknown" for a command that finished
// cleanly. So it makes room by discarding one already-queued output chunk
// instead: output is lossy by design and the status is not.
func (b *Broker) SendToStream(sessionID string, env protocol.Envelope) {
	b.mu.Lock()
	bind, ok := b.streams[sessionID]
	b.mu.Unlock()
	if !ok {
		return
	}
	select {
	case bind.console <- env:
		return
	default:
	}
	if env.Type != "stream_end" {
		return
	}
	// Exactly one goroutine writes a given session's channel (the agent's read
	// pump), so an eviction here cannot race another producer; the only other
	// actor is the reader, which is what emptied the slot we just freed.
	select {
	case <-bind.console:
	default:
	}
	select {
	case bind.console <- env:
	default: // lost the race with a refilling producer; better than blocking
	}
}

// StreamTarget returns the agent connection bound to a session's machine,
// for the console-pump to write exec_stream frames onto.
func (b *Broker) StreamTarget(sessionID string) *AgentConn {
	b.mu.Lock()
	bind, ok := b.streams[sessionID]
	b.mu.Unlock()
	if !ok {
		return nil
	}
	return b.Get(bind.machine)
}

type streamBinding struct {
	machine string
	console chan protocol.Envelope
}
