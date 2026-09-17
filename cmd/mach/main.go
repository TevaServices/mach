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
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bcross/mach/internal/agent"
	"github.com/bcross/mach/internal/console"
)

func main() {
	args := os.Args[1:]

	// Explicit subcommands keep working everywhere. The interrupt guard is
	// installed only for these: the bare path below runs the temporary session,
	// which handles the signal itself so it can say what happened on the way out
	// (and so an abrupt exit does not race that message).
	if len(args) > 0 {
		console.InterruptGuard()
		switch args[0] {
		case "list", "exec", "console", "audit", "trust":
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
Sealed exec (E2E):         mach exec --e2e <m> <cmd...>  (fail rather than send plaintext)
                           mach trust               pinned E2E keys for each machine
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

	// Already installed on this host? Say so rather than starting a second,
	// throwaway identity: an installed machine's enrollment is what its service
	// runs on, and a temporary session here would be a different machine with a
	// different name, competing for the same console.
	if agent.IsEnrolled(stateDir) {
		fmt.Fprintf(os.Stderr, "This host is already enrolled as a permanent agent (%s).\n", stateDir)
		fmt.Fprintln(os.Stderr, "  mach run                 reconnect that agent")
		fmt.Fprintln(os.Stderr, "  mach install             keep it running across reboots")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Plain `mach` is the TEMPORARY session and would enroll this host as a")
		fmt.Fprintln(os.Stderr, "second, separate machine. Delete the enrollment above if that is what you want.")
		os.Exit(2)
	}

	// Nothing installed: plain `mach` is a temporary session. It enrolls over
	// QR (one URL prompt), holds the live connection, and keeps everything in
	// memory — so Ctrl-C ends it and running `mach` again enrolls from scratch.
	// Surviving reboots is the separate, explicit `mach install`.
	if err := agent.RunEphemeral(promptServer(), promptOrg()); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		os.Exit(1)
	}
}

// promptServer asks for the control-plane URL when it is not in the environment.
// Same one-prompt UX as `mach register`, which the temporary session replaces.
func promptServer() string {
	if v := os.Getenv("MACH_SERVER"); v != "" {
		fmt.Printf("Control plane URL [%s]: ", v)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
		return v
	}
	fmt.Print("Control plane URL (e.g. https://mach.example.com): ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	s := strings.TrimSpace(line)
	if s == "" {
		fmt.Fprintln(os.Stderr, "mach: a control plane URL is required (set MACH_SERVER to skip the prompt)")
		os.Exit(2)
	}
	return s
}

// promptOrg asks for the org prefix, defaulting to MACH_ORG.
func promptOrg() string {
	if v := os.Getenv("MACH_ORG"); v != "" {
		fmt.Printf("Org prefix for machine names [%s]: ", v)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
		return v
	}
	fmt.Print("Org prefix for machine names (e.g. bcross): ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	s := strings.TrimSpace(line)
	if s == "" {
		fmt.Fprintln(os.Stderr, "mach: an org prefix is required (set MACH_ORG to skip the prompt)")
		os.Exit(2)
	}
	return s
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
		// A header row, matching the columns printed below. The interactive
		// table in defaultui.go has one and this did not, which left the AGENT
		// column reading as a bare version string with no label. Note the two
		// tables are not the same shape: this one carries the E2E column and
		// that one does not, so the header cannot simply be copied from it.
		fmt.Printf("%-20s %-8s %-10s %-18s %-8s %s\n", "NAME", "STATE", "OS/ARCH", "HOSTNAME", "E2E", "AGENT")
		for _, m := range machines {
			status := "offline"
			if m.Online {
				status = "online"
			}
			// An operator's soft block is marked distinctly from offline: the
			// machine is still connected (or would be), it is commands that are
			// refused. Without this, "online" next to a refused every command is
			// a confusing pair to read.
			if m.Blocked {
				status = "blocked"
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

	case "trust":
		// mach trust                       list pinned E2E keys
		// mach trust <machine>             accept the key the control plane now advertises
		// mach trust --forget <machine>    drop the pin (the next sealed command re-pins)
		rest := args[1:]
		forget := false
		if len(rest) > 0 && rest[0] == "--forget" {
			forget = true
			rest = rest[1:]
		}
		switch {
		case forget && len(rest) == 1:
			existed, err := c.ForgetMachine(rest[0])
			if err != nil {
				fmt.Fprintln(os.Stderr, "mach: "+err.Error())
				os.Exit(3)
			}
			if !existed {
				fmt.Printf("no pin for %s (nothing to forget)\n", rest[0])
				return
			}
			fmt.Printf("forgot the pinned E2E key for %s — the next sealed command will pin again\n", rest[0])
		case forget:
			fmt.Fprintln(os.Stderr, "usage: mach trust --forget <machine>")
			os.Exit(2)
		case len(rest) == 1:
			fingerprint, previous, err := c.TrustMachine(rest[0])
			if err != nil {
				fmt.Fprintln(os.Stderr, "mach: "+err.Error())
				os.Exit(3)
			}
			if previous == "" {
				fmt.Printf("pinned %s -> %s\n", rest[0], fingerprint)
				return
			}
			if previous == fingerprint {
				fmt.Printf("%s is already pinned to %s\n", rest[0], fingerprint)
				return
			}
			// Show both, so the change is visible at the moment it is accepted
			// rather than only in the refusal that prompted it.
			fmt.Printf("re-pinned %s\n  was %s\n  now %s\n", rest[0], previous, fingerprint)
		case len(rest) == 0:
			machines, err := c.PinnedMachines()
			if err != nil {
				fmt.Fprintln(os.Stderr, "mach: "+err.Error())
				os.Exit(3)
			}
			if len(machines) == 0 {
				fmt.Printf("no pinned E2E keys yet (%s)\n", console.PinPath())
				return
			}
			for _, m := range machines {
				fingerprint, pinnedAt, org, _, err := c.PinnedKey(m)
				if err != nil {
					fmt.Fprintln(os.Stderr, "mach: "+err.Error())
					os.Exit(3)
				}
				label := org
				if label == "" {
					label = "-"
				}
				fmt.Printf("%-24s %-20s %-8s %s\n", m, fingerprint, label, pinnedAt)
			}
		default:
			fmt.Fprintln(os.Stderr, "usage: mach trust [<machine>]\n       mach trust --forget <machine>")
			os.Exit(2)
		}

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
