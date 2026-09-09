// Package controlplane runs the mach server and admin commands for the
// mach-server container binary (deliberately separate from the mach
// remote-connection binary).
package controlplane

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bcross/mach/internal/broker"
	"github.com/bcross/mach/internal/server"
	"github.com/bcross/mach/internal/store"
)

// Version matches the agent's version string for now.
var Version = "0.1.0-dev"

func dbPath() string {
	if v := os.Getenv("MACH_DB"); v != "" {
		return v
	}
	return "/data/mach.db"
}

func openStore() (*store.Store, error) {
	return store.Open(dbPath())
}

// Serve runs the control plane (container entrypoint / `mach serve`).
func Serve() {
	listen := os.Getenv("MACH_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	pubURL := os.Getenv("MACH_PUBLIC_URL")
	if pubURL == "" {
		log.Fatal("mach: MACH_PUBLIC_URL is required (e.g. https://mach.example.com)")
	}
	st, err := openStore()
	if err != nil {
		log.Fatalf("mach: open store: %v", err)
	}
	defer st.Close()
	srv := server.New(st, broker.New(), pubURL)
	log.Printf("mach control plane listening on %s (public URL %s)", listen, pubURL)
	if err := http.ListenAndServe(listen, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}

// AddAPIKey creates a console/agent API key.
func AddAPIKey(name, key string) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.CreateAPIKey(name, key); err != nil {
		return err
	}
	fmt.Printf("api key %q created\n", name)
	return nil
}

// RemoveMachine deletes an enrolled machine by name.
func RemoveMachine(name string) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.RemoveMachine(name); err != nil {
		return err
	}
	fmt.Printf("machine %q removed\n", name)
	return nil
}