// Command mach-server — the control plane: public broker/approval service
// and its admin commands. This is the only publicly reachable component
// and ships as a container; it is deliberately separate from the `mach`
// remote-connection binary that runs on target machines and admin boxes.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/bcross/mach/internal/controlplane"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "serve":
		controlplane.Serve()
	case "add-api-key":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: mach-server add-api-key <name> <key>")
			os.Exit(2)
		}
		if err := controlplane.AddAPIKey(args[1], args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "remove-machine":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: mach-server remove-machine <name>")
			os.Exit(2)
		}
		if err := controlplane.RemoveMachine(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "version":
		fmt.Printf("mach-server %s (%s/%s)\n", controlplane.Version, runtime.GOOS, runtime.GOARCH)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mach-server — mach control plane (broker, pairing, audit; the only public component)

  mach-server serve                      run the control plane
                                         (MACH_DB, MACH_LISTEN, MACH_PUBLIC_URL)
  mach-server add-api-key <name> <key>   create a console/agent API key
  mach-server remove-machine <name>      remove an enrolled machine
  mach-server version
`)
}