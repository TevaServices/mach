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
		serverURL := fs.String("server", envOr("MACH_SERVER", ""), "control plane base URL (https://…)")
		apiKey := fs.String("api-key", "", "enroll headlessly with an enroll-scoped API key")
		name := fs.String("name", "", "machine name, org-prefixed: <org>-<machine>")
		org := fs.String("org", envOr("MACH_ORG", ""), "org prefix (or MACH_ORG env; prompted if empty)")
		_ = fs.Parse(args[1:])
		if *serverURL == "" {
			// Zero-parameter UX: ask once. (Env MACH_SERVER pre-fills/default.)
			def := envOr("MACH_SERVER", "")
			if def != "" {
				fmt.Printf("Control plane URL [%s]: ", def)
			} else {
				fmt.Print("Control plane URL (e.g. https://mach.example.com): ")
			}
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			*serverURL = strings.TrimSpace(line)
			if *serverURL == "" {
				*serverURL = def
			}
			if *serverURL == "" {
				fmt.Fprintln(os.Stderr, "mach: a control plane URL is required (pass --server or set MACH_SERVER to skip the prompt)")
				os.Exit(2)
			}
		}
		// Infer org from an org-prefixed --name (e.g. bcross-test-01 → bcross).
		if *org == "" && strings.Contains(*name, "-") {
			*org = strings.SplitN(*name, "-", 2)[0]
		}
		if *org == "" {
			fmt.Print("Org prefix for machine names (e.g. bcross): ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			*org = strings.TrimSpace(line)
			if *org == "" {
				fmt.Fprintln(os.Stderr, "mach: an org prefix is required (pass --org/--name or set MACH_ORG)")
				os.Exit(2)
			}
		}
		var err error
		switch {
		case *apiKey != "":
			if *name == "" {
				fmt.Print("Machine name (org-prefixed, e.g. " + *org + "-web-1): ")
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				*name = strings.TrimSpace(line)
			}
			if *name == "" {
				fmt.Fprintln(os.Stderr, "mach: a machine name is required")
				os.Exit(2)
			}
			_, err = RegisterAPIKey(*serverURL, *apiKey, *name, *org, stateDir)
		default:
			_, err = RegisterQR(*serverURL, *org, stateDir)
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

  mach register [--server URL] [--org ORG]          enroll via QR (type challenge code on phone)
  mach register --api-key K --name ORG-machine      enroll headlessly (enroll-scoped key)
  mach run                                          run the agent daemon (outbound-only connection)
  mach install                                      register the agent as an OS service
                                                    (linux: systemd / macOS: launchd / windows: Task Scheduler)
  mach version

Machine names are org-prefixed: <org>-<machine> (unique; conflicts error out).
The control plane is a separate binary: mach-server (serve, add-api-key, revoke-machine).
Environment: MACH_SERVER, MACH_ORG, MACH_STATE_DIR
`)
}
