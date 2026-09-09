package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bcross/mach/internal/console"
)

// mach — the console CLI. One binary, three modes:
//   mach list
//   mach exec <machine> <command...>      (one-shot; exit code = remote exit)
//   mach console <machine>                (interactive)
//   mach audit [machine] [limit]
func main() {
	console.InterruptGuard()
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	cfg, err := console.LoadConfig()
	if err != nil {
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

	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mach — fleet console for the mach control plane

  mach list                      list enrolled machines
  mach exec <machine> <cmd...>   run a command remotely (exit code = remote exit)
  mach exec <machine> -- <argv>  no-shell mode: args pass through byte-exact (no quoting issues)
  mach console <machine>         interactive remote shell
  mach audit [machine] [limit]   recent command audit log

Configuration: ~/.mach/console.json → {"server": "https://…", "api_key": "…"}
`)
}