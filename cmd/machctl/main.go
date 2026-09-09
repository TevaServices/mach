package main

import (
	"fmt"
	"os"

	"github.com/bcross/mach/internal/store"
)

// machctl — one-shot admin tool for the control plane operator (runs inside
// the container or with a direct path to the SQLite DB).
func main() {
	args := os.Args[1:]
	if len(args) >= 1 && args[0] == "serve" {
		serve()
		return
	}
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	dbPath := os.Getenv("MACH_DB")
	if dbPath == "" {
		dbPath = "/data/mach.db"
	}
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "machctl: "+err.Error())
		os.Exit(1)
	}
	defer st.Close()

	switch args[0] {
	case "add-api-key":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: machctl add-api-key <name> <key>")
			os.Exit(2)
		}
		if err := st.CreateAPIKey(args[1], args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "machctl: "+err.Error())
			os.Exit(1)
		}
		fmt.Printf("api key %q created\n", args[1])
	case "remove-machine":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: machctl remove-machine <name>")
			os.Exit(2)
		}
		if err := st.RemoveMachine(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "machctl: "+err.Error())
			os.Exit(1)
		}
		fmt.Printf("machine %q removed\n", args[1])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `machctl — control plane admin + server entrypoint

  machctl serve                                  run the control plane (MACH_DB, MACH_LISTEN, MACH_PUBLIC_URL)
  machctl add-api-key <name> <key>               create a console/agent API key
  machctl remove-machine <name>                  remove an enrolled machine
`)
}