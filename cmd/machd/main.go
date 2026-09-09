package main

import (
	"fmt"
	"os"

	"github.com/bcross/mach/internal/agent"
)

// machd — the agent daemon. One binary, four modes:
//   machd register                  QR pairing enrollment (prints QR + challenge code)
//   machd register --api-key K -n N headless enrollment
//   machd run                       daemon: outbound-only connection, executes commands
//   machd install                   install + start the systemd service
func main() {
	args := os.Args[1:]
	cmd := "help"
	if len(args) > 0 {
		cmd = args[0]
	}

	stateDir := agent.StateDir()

	switch cmd {
	case "register":
		fs := flagSet()
		server := fs.String("server", envOr("MACH_SERVER", ""), "control plane base URL (https://…)")
		apiKey := fs.String("api-key", "", "enroll headlessly with an API key instead of QR")
		name := fs.String("name", "", "machine name (api-key enrollment)")
		_ = fs.Parse(args[1:])
		if *server == "" {
			fmt.Fprintln(os.Stderr, "machd: --server is required (or set MACH_SERVER)")
			os.Exit(2)
		}
		var err error
		switch {
		case *apiKey != "":
			if *name == "" {
				fmt.Fprintln(os.Stderr, "machd: --name is required with --api-key")
				os.Exit(2)
			}
			_, err = agent.RegisterAPIKey(*server, *apiKey, *name, stateDir)
		default:
			_, err = agent.RegisterQR(*server, stateDir)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "machd: "+err.Error())
			os.Exit(1)
		}

	case "run":
		if err := agent.Run(stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "machd: "+err.Error())
			os.Exit(1)
		}

	case "install":
		if err := agent.Install(stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "machd: "+err.Error())
			os.Exit(1)
		}

	case "version":
		fmt.Println("machd " + agent.Version)

	default:
		fmt.Fprint(os.Stderr, `machd — mach agent daemon

  machd register [--server URL]            enroll via QR (scan with phone; approve + name it)
  machd register --api-key K --name N      enroll headlessly
  machd run                                run the daemon (outbound-only connection)
  machd install                            install + start the systemd service
  machd version

Environment: MACH_SERVER, MACH_STATE_DIR
`)
		os.Exit(2)
	}
}