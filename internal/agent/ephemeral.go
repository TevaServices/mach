package agent

// The temporary session: what plain `mach` does on a target.
//
// It enrolls this host, holds the live connection, and keeps every secret — the
// identity key, the E2E key, the pinned server key — in memory only. Nothing is
// written to the state directory, so the session ends when the process does:
// Ctrl-C is a real shutdown, and running `mach` again means enrolling again.
//
// That is the whole difference from `mach run`, which uses the files an
// `mach install` left behind and reconnects across reboots. The point of keeping
// them separate is that a machine someone has installed can never be disturbed by
// somebody typing `mach` at a console: the temporary path cannot read, write or
// delete the persistent state, so it cannot disconnect or re-key an installed
// agent.
//
// Its enrollment is marked TEMPORARY on the control plane, and the session
// retires that enrollment when it ends. The marking is what makes an unclean exit
// survivable: a session that is killed outright, or that loses the network before
// it can say anything, leaves a temporary record behind — and a temporary record
// can be taken over by the next run without the operator revoking or deleting
// anything first. Retiring on exit is the tidy path; the marking is the one that
// always works.

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
)

// sessionCtl carries what a temporary session needs to end cleanly: the live
// connection, so an interrupt can tell the control plane to retire this machine,
// and a stop signal, so the reconnect loop stops instead of reconnecting after
// the socket it was reading is closed underneath it.
//
// A nil *sessionCtl is the permanent agent's case, and every method tolerates it,
// so the shared loop does not have to branch on which mode it is in.
type sessionCtl struct {
	mu       sync.Mutex
	conn     *protocol.WSConn
	shutdown bool
	retired  bool
	done     chan struct{}
}

func newSessionCtl() *sessionCtl { return &sessionCtl{done: make(chan struct{})} }

// attach records the live connection so an interrupt can retire on it.
func (c *sessionCtl) attach(conn *protocol.WSConn) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
}

// detach drops it again, so a reconnect does not leave a stale pointer to a
// socket that has already been closed.
func (c *sessionCtl) detach() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.conn = nil
	c.mu.Unlock()
}

// stopped reports whether a shutdown has been requested.
func (c *sessionCtl) stopped() bool {
	if c == nil {
		return false
	}
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// wait sleeps for d, or until a shutdown is requested, and reports which.
func (c *sessionCtl) wait(d time.Duration) (stopped bool) {
	if c == nil {
		time.Sleep(d)
		return false
	}
	select {
	case <-c.done:
		return true
	case <-time.After(d):
		return false
	}
}

// shutDown retires this machine and ends the session.
//
// It only SIGNALS the shutdown; the caller reports what happened on the way out,
// from the one goroutine that owns the exit. Doing the reporting here instead
// raced the exit: closing the socket makes the serve loop return, so the process
// could be gone before this goroutine had printed a word.
//
// Idempotent: the signal handler and a failed connection can both reach it.
func (c *sessionCtl) shutDown() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.shutdown {
		c.mu.Unlock()
		return
	}
	c.shutdown = true
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()

	close(c.done)
	if conn == nil {
		// Between connections: no socket to say it on. The enrollment stays as it
		// is — still temporary, so the next run takes it over directly.
		return
	}
	// Sent on the authenticated connection this session already holds, so the
	// control plane knows which machine is asking — the frame carries no name and
	// cannot name another.
	if err := conn.WriteEnvelope(protocol.Envelope{Type: "retire"}); err == nil {
		c.mu.Lock()
		c.retired = true
		c.mu.Unlock()
	}
	// Closing is what stops the loop: it is parked in a read on this socket.
	conn.Close()
}

// announce prints a one-line trace of a command this session is asked to run, so
// the operator watching the console it was started from can see what is being
// done to the machine. Without it a temporary session sat silent while commands
// arrived, executed and returned.
//
// Only a temporary session traces. That is the whole gate, and it is the right
// one: this mode exists to be watched at a terminal, whereas an installed
// agent's output goes to systemd/launchd's journal, where a line per command is
// noise nobody asked for. The nil receiver is the permanent agent's case, so the
// shared command loop does not have to branch on which mode it is in.
//
// The text is %q-quoted by every caller because it arrives from the control
// plane: a command carrying a newline must not be able to forge a second line of
// this machine's console — the same rule the disconnect log line follows. It is
// a trace, never input: nothing reads it back.
func (c *sessionCtl) announce(format string, args ...any) {
	if c == nil || c.stopped() {
		return
	}
	fmt.Fprintf(os.Stdout, "mach: "+format+"\n", args...)
}

// retiredEnrollment reports whether the retire frame actually went out.
func (c *sessionCtl) retiredEnrollment() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.retired
}

// RunEphemeral enrolls this host for the life of this process and serves.
//
// It never returns except on a terminal frame or an interrupt: the reconnect loop
// is the same one the installed agent uses, because a temporary session should
// still survive a control-plane restart rather than dropping on the first blip.
func RunEphemeral(server, org string) error {
	fmt.Println("mach: TEMPORARY session — nothing is written to disk.")
	fmt.Println("      Ctrl-C ends it and retires this enrollment; running `mach` again enrolls afresh.")
	fmt.Println("      For a connection that survives reboots:  mach install")

	id, err := NewIdentity()
	if err != nil {
		return err
	}
	e2eKey, err := NewE2EKeyPair()
	if err != nil {
		return err
	}
	// temporary=true is recorded on the enrollment, and is what lets this session
	// come back under the same name after an exit that never got to retire it.
	cfg, err := registerQRCore(server, org, id, e2eKey, true)
	if err != nil {
		return err
	}

	// Privilege drop AFTER enrollment, mirroring the order in Run: a session
	// started as root should execute commands as the unprivileged account, but
	// must not drop before it has finished talking to the control plane.
	//
	// The machine's own guardrail is read first, for the same reason it is in
	// Run: a session started as root must read a root-owned policy.txt as root,
	// or the drop turns it into an empty ruleset with nothing said about it. A
	// temporary session runs commands like any other, so the local layer applies
	// to it exactly as it does to an installed agent.
	if err := LoadLocalPolicy(); err != nil {
		return err
	}
	DropPrivileges()

	ctl := newSessionCtl()

	// Ctrl-C retires the enrollment and ends the session. The handler only
	// triggers the shutdown; the farewell is printed below, on the goroutine that
	// returns from this function, so the message cannot lose a race with the exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		ctl.shutDown()
	}()

	fmt.Println()
	fmt.Printf("Holding the live connection as %q. Ctrl-C to end this session.\n", cfg.Name)

	err = serveLoop(cfg, id, e2eKey, ctl)
	if ctl.stopped() {
		// A deliberate stop, not a failure: 0 is what "stop, do not restart"
		// means everywhere else in this codebase, and nothing needs unwinding —
		// this process never wrote anything.
		printSessionEnded(cfg.Name, ctl.retiredEnrollment())
		return nil
	}
	return err
}

// printSessionEnded says what the session did on the way out. It states the one
// thing this mode leaves behind — the enrollment on the control plane — because
// the operator will otherwise meet it as a name conflict next time.
func printSessionEnded(name string, retired bool) {
	fmt.Println()
	fmt.Println("mach: temporary session ended — nothing was written to disk.")
	if retired {
		fmt.Printf("      Retired this enrollment: %q is now revoked on the control plane.\n", name)
		fmt.Println("      Running `mach` again takes that name straight back over.")
		return
	}
	// The frame had nowhere to go — the session was between connections. Say so,
	// and say why it does not matter: this is exactly what the temporary marking
	// exists for.
	fmt.Printf("      Could not reach the control plane to retire %q; it stays as a\n", name)
	fmt.Println("      temporary enrollment, which the next `mach` here takes over directly.")
}
