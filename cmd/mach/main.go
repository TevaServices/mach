// Command mach — the remote-connection binary: agent + console in one.
//
// The control plane is a separate binary (mach-server) that ships as a
// container; it is the only publicly reachable component.
//
// On an admin/ops machine:
//
//	mach                      → first run: one-time setup wizard; after that:
//	                          → live machine list + auto-refresh, `!` for a local shell
//	mach exec <m> <cmd...>    → run a command remotely (exit code = remote exit)
//	mach exec <m> -- <argv>   → no-shell mode: args pass through byte-exact
//	mach console <m>          → interactive line-based remote shell
//	mach audit [m] [n]        → recent command audit log
//
// On a machine to be enrolled as a target:
//
//	mach                      → if not enrolled: QR enrollment, then the
//	                            live connection held in this console
//	                            (Ctrl-C stops it). `mach install` makes it
//	                            a persistent OS service; `mach run` re-runs
//	                            the daemon.
//	mach register [...]       → enrollment only
//
// Nothing else is required: enrollment config, console config, and keys all
// live in one state dir (~/.mach, /var/lib/mach for root, %APPDATA%\mach).
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bcross/mach/internal/agent"
	"github.com/bcross/mach/internal/console"
)

func main() {
	console.InterruptGuard()
	args := os.Args[1:]

	// Explicit subcommands keep working everywhere.
	if len(args) > 0 {
		switch args[0] {
		case "list", "exec", "console", "audit":
			consoleMain(args)
			return
		case "register", "run", "install", "service", "version", "help":
			agentMain(args)
			return
		default:
			usage()
			os.Exit(2)
		}
	}

	// Plain `mach`: boot strap by context.
	bootStrap()
}

func usage() {
	fmt.Fprint(os.Stderr, `mach — remote CLI access to registered machines (agent + console in one binary)

On a machine to wire in:   mach            (enroll via QR, then hold the live connection)
Make it permanent:         mach install    (register the OS service)
On an admin machine:       mach            (first run: setup wizard; then: live fleet status)
Run commands:              mach exec <m> <cmd...>   |   mach exec <m> -- <argv>  (byte-exact)
                           mach console <m>         |   mach list, mach audit [m] [n]
Agent/service:             mach register [--server URL | --api-key K --name N], mach run, mach version

The control plane is a separate binary: mach-server (runs in a container).
`)
}

func bootStrap() {
	stateDir := agent.StateDir()

	// Fresh target machine: enrollment, then the live connection right here
	// in this console. The service (persistence across reboots) is a
	// separate, explicit step: `mach install`.
	if !agent.IsEnrolled(stateDir) {
		agentMain([]string{"register"})
		if !agent.IsEnrolled(stateDir) {
			os.Exit(1)
		}
		fmt.Println("\nEnrolled. Holding the live connection in this console (Ctrl-C to stop).")
		fmt.Println("Make it permanent (auto-start + reconnect after reboots):  mach install")
		agentMain([]string{"run"})
		return
	}

	// Already a target (enrolled, no console config): start the live
	// connection in this console.
	if _, err := console.LoadConfig(); err != nil {
		agentMain([]string{"run"})
		return
	}

	// Admin machine: default fleet UI.
	consoleMain([]string{})
}

func consoleMain(args []string) {
	if len(args) == 0 {
		// Default console UI.
		if _, err := console.LoadConfig(); err != nil {
			if isNotConfigured(err) {
				os.Exit(console.FirstRunWizard())
			}
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			os.Exit(2)
		}
		os.Exit(console.ConsoleDefault())
	}

	cfg, err := console.LoadConfig()
	if err != nil {
		if isNotConfigured(err) && args[0] != "list" {
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			os.Exit(console.FirstRunWizard())
		}
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		os.Exit(2)
	}
	c := console.New(cfg)

	switch args[0] {
	case "list":
		machines, err := c.Machines()
		if err != nil {
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			os.Exit(3)
		}
		if len(machines) == 0 {
			fmt.Println("no machines enrolled")
			return
		}
		for _, m := range machines {
			status := "offline"
			if m.Online {
				status = "online"
			}
			fmt.Printf("%-20s %-8s %-10s %-18s %s\n", m.Name, status, m.OS+"/"+m.Arch, m.Hostname, m.AgentVer)
		}

	case "exec":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: mach exec <machine> <command...>\n       mach exec <machine> -- <argv...>   (no-shell mode: args pass through byte-exact)")
			os.Exit(2)
		}
		rest := args[2:]
		if rest[0] == "--" {
			// No-shell mode: every argument after -- is delivered as its
			// own JSON string and exec'd directly on the machine. Your
			// local shell does the only quoting pass; the remote side
			// never splits or re-parses anything.
			os.Exit(c.ExecArgv(args[1], rest[1:], 0))
		}
		os.Exit(c.Exec(args[1], strings.Join(rest, " "), 0))

	case "console":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: mach console <machine>")
			os.Exit(2)
		}
		os.Exit(c.Console(args[1]))

	case "audit":
		machine := "*"
		limit := 50
		if len(args) >= 2 {
			machine = args[1]
		}
		if len(args) >= 3 {
			if n, err := strconv.Atoi(args[2]); err == nil {
				limit = n
			}
		}
		os.Exit(c.Audit(machine, limit))
	}
}

func isNotConfigured(err error) bool {
	_, ok := err.(console.NotConfiguredError)
	return ok
}

func agentMain(args []string) {
	agent.Route(args)
}