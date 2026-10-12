//go:build !js || !wasm

// Package main is the browser seal's source, buildable only for js/wasm —
// which is why it lives under cmd/_uiseal (an underscore directory is
// invisible to ./... wildcards, so vet, test and `go build ./...` on every
// other GOOS are not asked to compile a main package that has no main).
//
// The artifact the server embeds (internal/server/static/mach-seal.wasm) is
// a gitignored BUILD artifact, not committed source: wherever the control
// plane is compiled, `scripts/wasm-ensure.sh` runs first — from a mise
// dependency, from CI's cache step, or from the Docker image's build stage —
// and it is the one home for the flags, the input list and the GOTOOLCHAIN
// pin. `mise run wasm` is the human-facing force rebuild.
//
// The wasm is the ONE seal implementation (internal/e2e) compiled for the
// browser — see the js/wasm file's package comment for the contract, and the
// AGENTS.md note on why a second implementation of a sealed format is how a
// field goes missing on one side and a push fails on a healthy machine.
package main
