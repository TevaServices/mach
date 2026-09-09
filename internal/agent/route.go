package agent

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Route dispatches the agent subcommands for the unified remote binary.
// The control plane is a separate binary (mach-server) by design.
func Route(args []string) {
	cmd := "help"
	if len(args) > 0 {
		cmd = args[0]
	}
	stateDir := StateDir()

	switch cmd {
	case "register":
		fs := flag.NewFlagSet("register", flag.ContinueOnError)
		server := fs.String("server", envOr("MACH_SERVER", ""), "control plane base URL (https://…)")
		apiKey := fs.String("api-key", "", "enroll headlessly with an API key instead of QR")
		name := fs.String("name", "", "machine name (api-key enrollment)")
		_ = fs.Parse(args[1:])
		if *server == "" {
			// Zero-parameter UX: ask once. (Env MACH_SERVER pre-fills/default.)
			def := envOr("MACH_SERVER", "")
			if def != "" {
				fmt.Printf("Control plane URL [%s]: ", def)
			} else {
				fmt.Print("Control plane URL (e.g. https://mach.example.com): ")
			}
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			*server = strings.TrimSpace(line)
			if *server == "" {
				*server = def
			}
			if *server == "" {
				fmt.Fprintln(os.Stderr, "mach: a control plane URL is required (pass --server or set MACH_SERVER to skip the prompt)")
				os.Exit(2)
			}
		}
		var err error
		switch {
		case *apiKey != "":
			if *name == "" {
				fmt.Fprintln(os.Stderr, "mach: --name is required with --api-key")
				os.Exit(2)
			}
			_, err = RegisterAPIKey(*server, *apiKey, *name, stateDir)
		default:
			_, err = RegisterQR(*server, stateDir)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			os.Exit(1)
		}

	case "run":
		if err := Run(stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			os.Exit(1)
		}

	case "install", "service":
		if err := Install(stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			os.Exit(1)
		}

	case "version":
		fmt.Printf("mach %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)

	default:
		usageAgent()
		os.Exit(2)
	}
}

// IsEnrolled reports whether this machine has completed enrollment.
func IsEnrolled(stateDir string) bool {
	cfg, err := LoadConfig(stateDir)
	return err == nil && cfg != nil && cfg.Name != "" && cfg.Server != ""
}

func usageAgent() {
	fmt.Fprint(os.Stderr, `mach — agent commands (remote-connection binary)

  mach register [--server URL]            enroll via QR (scan with phone; approve + name it)
  mach register --api-key K --name N      enroll headlessly
  mach run                                run the agent daemon (outbound-only connection)
  mach install                            register the agent as an OS service
                                          (linux: systemd / macOS: launchd / windows: Task Scheduler)
  mach version

The control plane is a separate binary: mach-server (serve, add-api-key, remove-machine).
Environment: MACH_SERVER, MACH_STATE_DIR
`)
}