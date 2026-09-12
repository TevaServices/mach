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

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// RunEphemeral enrolls this host for the life of this process and serves.
//
// It never returns except on a terminal frame or an interrupt: the reconnect loop
// is the same one the installed agent uses, because a temporary session should
// still survive a control-plane restart rather than dropping on the first blip.
func RunEphemeral(server, org string) error {
	fmt.Println("mach: TEMPORARY session — nothing is written to disk.")
	fmt.Println("      Ctrl-C ends it; running `mach` again enrolls this host from scratch.")
	fmt.Println("      For a connection that survives reboots:  mach install")

	id, err := NewIdentity()
	if err != nil {
		return err
	}
	e2eKey, err := NewE2EKeyPair()
	if err != nil {
		return err
	}
	cfg, err := registerQRCore(server, org, id, e2eKey)
	if err != nil {
		return err
	}

	// Privilege drop AFTER enrollment, mirroring the order in Run: a session
	// started as root should execute commands as the unprivileged account, but
	// must not drop before it has finished talking to the control plane.
	DropPrivileges()

	// Ctrl-C ends the session.
	//
	// Exiting from the handler is honest here in a way it would not be for the
	// installed agent: there are no state files to settle and no in-flight write
	// to lose, because this process never wrote anything. Exit 0 rather than the
	// conventional 130 because in this codebase 0 already means "stopped
	// deliberately, do not restart" — the same thing a retirement returns.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println()
		fmt.Println("mach: temporary session ended — nothing was written to disk.")
		// Said plainly, because it is the one thing this mode leaves behind and
		// the operator will otherwise meet it as a name conflict next time.
		fmt.Printf("      The enrollment for %q is still on the control plane (a connection\n", cfg.Name)
		fmt.Printf("      needs a record). Re-run under the same name by revoking it first\n")
		fmt.Printf("      (`mach-server revoke-machine %s`, or Block/Revoke in the web UI);\n", cfg.Name)
		fmt.Printf("      leaving it alone means picking a new name next time.\n")
		os.Exit(0)
	}()

	fmt.Println()
	fmt.Printf("Holding the live connection as %q. Ctrl-C to end this session.\n", cfg.Name)
	return serveLoop(cfg, id, e2eKey)
}
