//go:build !js || !wasm

// Package main is the browser seal's source, buildable only for js/wasm —
// which is why it lives under cmd/_uiseal (an underscore directory is
// invisible to ./... wildcards, so vet, test and `go build ./...` on every
// other GOOS are not asked to compile a main package that has no main).
//
// Build the artifact the server serves (and commits under
// internal/server/static/mach-seal.wasm) with `mise run wasm`:
//
//	GOOS=js GOARCH=wasm go build -o internal/server/static/mach-seal.wasm ./cmd/_uiseal
//
// The wasm is the ONE seal implementation (internal/e2e) compiled for the
// browser — see the js/wasm file's package comment for the contract, and the
// AGENTS.md note on why a second implementation of a sealed format is how a
// field goes missing on one side and a push fails on a healthy machine.
package main
