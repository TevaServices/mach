// Command mach — the remote-connection binary: agent + console in one.
//
// The control plane is a separate binary (mach-server) that ships as a
// container; it is the only publicly reachable component.
//
// On an admin/ops machine (console configured — one-time `mach` wizard):
//
//	mach                      → fleet status table (same as `mach list`)
//	mach exec <machine> <cmd> → one-shot; exit code = remote exit
//	mach exec <machine> -- <argv> → no-shell mode: args pass through byte-exact
//	mach console <machine>    → interactive line-based remote shell
//	mach audit [machine] [n]  → recent command audit log
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

	// Admin box (console configured: control plane URL + API key)?
	// Plain `mach` prints the fleet table — same as `mach list`.
	if _, err := console.LoadConfig(); err == nil {
		consoleMain([]string{"list"})
		return
	}

	// Configured target (enrolled)? Plain `mach` re-establishes the
	// machine's live connection in this console.
	if agent.IsEnrolled(stateDir) {
		agentMain([]string{"run"})
		return
	}

	// Nothing configured: this is a fresh machine to wire in. Enroll via
	// QR (one URL prompt), then hold the live connection here. Making it
	// survive reboots is the separate, explicit `mach install`.
	agentMain([]string{"register"})
	if !agent.IsEnrolled(stateDir) {
		os.Exit(1)
	}
	fmt.Println("\nEnrolled. Holding the live connection in this console (Ctrl-C to stop).")
	fmt.Println("Make it permanent (auto-start + reconnect after reboots):  mach install")
	agentMain([]string{"run"})
}

func consoleMain(args []string) {
	if len(args) == 0 {
		// Default console UI: plain fleet status (one shot).
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
			// The E2E column is here, not in a separate command, because it is
			// a property of what you can do to that machine: whether a command
			// sent to it is sealed or readable by the control plane.
			e2e := "e2e=on"
			if m.E2E == "off" {
				e2e = "e2e=off"
			}
			fmt.Printf("%-20s %-8s %-10s %-18s %-8s %s\n", m.Name, status, m.OS+"/"+m.Arch, m.Hostname, e2e, m.AgentVer)
		}

	case "exec":
		// mach exec [--json] [--e2e|--no-e2e] <machine> <command...>
		// mach exec [--json] [--e2e|--no-e2e] <machine> -- <argv...>
		rest := args[1:]
		asJSON := false
		e2e := console.E2EObey
		// Flags stop at the machine name, so nothing in a command can be
		// swallowed as a flag. A bare -- also ends them, for scripts that
		// want to be explicit.
		i := 0
		for i < len(rest) && strings.HasPrefix(rest[i], "--") {
			switch rest[i] {
			case "--json":
				asJSON = true
			case "--e2e":
				e2e = console.E2ERequire
			case "--no-e2e":
				e2e = console.E2EForbid
			case "--":
				// explicit end of flags
			default:
				fmt.Fprintf(os.Stderr, "mach: unknown flag %q\n", rest[i])
				os.Exit(2)
			}
			i++
		}
		rest = rest[i:]
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, `usage: mach exec [--json] [--e2e|--no-e2e] <machine> <command...>
       mach exec [--json] [--e2e|--no-e2e] <machine> -- <argv...>   (no-shell mode: args pass through byte-exact)

  --json     print the result as one JSON object instead of raw output
             (for programs: output is labeled data and the exit status is
             a field, so nothing has to parse a mixed stream)
  --e2e      require end-to-end encryption: fail rather than send the command
             in plaintext (the control plane decides whether it will accept a
             sealed command; without this flag mach obeys its answer)
  --no-e2e   never seal: send plaintext, where the fleet-wide block list can
             read it and the audit log can record the command itself

By default mach obeys the control plane's E2E setting: it seals when the
control plane accepts sealed commands and the machine has a key, and says so
on stderr when it cannot.`)
			os.Exit(2)
		}
		machine, cmdArgs := rest[0], rest[1:]
		if cmdArgs[0] == "--" {
			// No-shell mode: every argument after -- is delivered as its
			// own JSON string and exec'd directly on the machine. Your
			// local shell does the only quoting pass; the remote side
			// never splits or re-parses anything.
			os.Exit(c.ExecArgv(machine, cmdArgs[1:], 0, asJSON, e2e))
		}
		os.Exit(c.Exec(machine, strings.Join(cmdArgs, " "), 0, asJSON, e2e))

	case "console":
		// mach console [--no-e2e] <machine>
		rest := args[1:]
		if len(rest) > 0 && rest[0] == "--e2e" {
			fmt.Fprintln(os.Stderr, "mach: console cannot be end-to-end encrypted: a live session is a relay of\n"+
				"      many small frames, and only a single command/result can be sealed.\n"+
				"      Use `mach exec --e2e <machine> <command>` for a sealed one-shot command.")
			os.Exit(2)
		}
		if len(rest) > 0 && rest[0] == "--no-e2e" {
			rest = rest[1:]
		}
		if len(rest) < 1 {
			fmt.Fprintln(os.Stderr, "usage: mach console <machine>")
			os.Exit(2)
		}
		os.Exit(c.Console(rest[0]))

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
