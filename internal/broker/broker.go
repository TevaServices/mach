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
	agents  map[string]*AgentConn          // by machine name
	waiters map[string]map[chan struct{}]struct{} // name -> waiters for reconnect
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
	b.mu.Unlock()
	log.Printf("broker: agent online: %s (%s/%s %s)", a.Name, a.OS, a.Arch, a.AgentVer)
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