package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bcross/mach/internal/broker"
	"github.com/bcross/mach/internal/server"
	"github.com/bcross/mach/internal/store"
)

// serve runs the control plane (container entrypoint).
func serve() {
	dbPath := os.Getenv("MACH_DB")
	if dbPath == "" {
		dbPath = "/data/mach.db"
	}
	listen := os.Getenv("MACH_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	pubURL := os.Getenv("MACH_PUBLIC_URL")
	if pubURL == "" {
		log.Fatal("machctl: MACH_PUBLIC_URL is required (e.g. https://mach.example.com)")
	}

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("machctl: open store: %v", err)
	}
	defer st.Close()

	srv := server.New(st, broker.New(), pubURL)
	log.Printf("mach control plane listening on %s (public URL %s)", listen, pubURL)
	if err := http.ListenAndServe(listen, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}

var _ = fmt.Sprintf