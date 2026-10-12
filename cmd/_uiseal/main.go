//go:build js && wasm

// Package main is the browser-side seal, compiled to WebAssembly for the
// control plane's web UI. It is the ONE seal implementation — internal/e2e —
// compiled for js/wasm, not a second implementation of the format: a page
// adding a secret from the admin UI runs the same bytes the agent runs, so a
// version field cannot quietly go missing on one side. Build it with
// `mise run wasm` (script: scripts/wasm-ensure.sh) — the artifact is a
// gitignored build output the server embeds at compile time, never
// committed. (The
// underscore in cmd/_uiseal keeps ./... from vetting or testing a main
// package that only exists for js/wasm; see doc.go on the non-wasm side.)
//
// It exposes two functions the page's secrets.js calls, and nothing else —
// and nothing here ever logs or otherwise exposes a value:
//
//	machSeal(recipientPubHex, name, org, value)
//	  → {sealed: "<base64>", error: ""}
//	machFingerprint(pubHex)
//	  → {fingerprint: "sha256:<16 hex>", error: ""}
//
// The recipient key is the target machine's PUBLIC X25519 key. The value
// exists only inside this invocation's memory and inside the returned
// ciphertext: nothing in this program, the page, or the control plane reads
// it back — the same "output is data, never input" stance the fleet runs on.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"syscall/js"

	"github.com/TevaServices/mach/internal/e2e"
	"github.com/TevaServices/mach/internal/protocol"
)

// sealFn implements machSeal. The value is validated against the same rules
// the agent enforces at storage time (protocol.ValidSecretName /
// protocol.ValidSecretValue — one home, so the browser and the machine cannot
// disagree), then sealed to the machine's key exactly as a console does. The
// reply object carries an error STRING and never a value, for the same reason
// every refusal in the fleet is value-free by construction.
func sealFn(_ js.Value, args []js.Value) any {
	if len(args) != 4 {
		return errResult("machSeal expects (recipientPubHex, name, org, value)")
	}
	pub, err := hex.DecodeString(args[0].String())
	if err != nil {
		return errResult("the machine's E2E key is not valid hex")
	}
	name := args[1].String()
	org := args[2].String()
	value := args[3].String()
	if err := protocol.ValidSecretName(name); err != nil {
		return errResult(err.Error())
	}
	if org == "" {
		return errResult("the machine's org is required in the payload")
	}
	if err := protocol.ValidSecretValue(value); err != nil {
		return errResult(err.Error())
	}
	payload, err := json.Marshal(protocol.SecretPayload{
		Name:  name,
		Org:   org,
		Value: value,
	})
	if err != nil {
		return errResult("could not encode the payload: " + err.Error())
	}
	sealed, err := e2e.Seal(pub, payload)
	if err != nil {
		return errResult("sealing failed: " + err.Error())
	}
	return map[string]any{
		"sealed": base64.StdEncoding.EncodeToString(sealed),
		"error":  "",
	}
}

// fingerprintFn implements machFingerprint: the same short hash rendering the
// console's trust-on-first-use pin file shows (console/pins.go
// KeyFingerprint — sha256 of the key bytes, 16 hex chars, "sha256:" prefix).
// It is a display hash of a PUBLIC key, and the browser pins are compared
// within the page to each other, so the format here must match that function
// only for the operator reading both; the pin decision never crosses a wire.
func fingerprintFn(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return errResult("machFingerprint expects (pubHex)")
	}
	raw, err := hex.DecodeString(args[0].String())
	if err != nil {
		return errResult("the E2E key is not valid hex")
	}
	sum := sha256.Sum256(raw)
	return map[string]any{
		"fingerprint": "sha256:" + hex.EncodeToString(sum[:8]),
		"error":       "",
	}
}

// errResult is the shape every caller gets back on a failure: an error field
// a human can read and nothing else — no value, no key, no payload.
func errResult(msg string) map[string]any {
	return map[string]any{"sealed": "", "error": msg}
}

// main registers the two functions on the global object and parks. The wasm
// instance lives as long as its page; there is nothing else to run.
func main() {
	g := js.Global()
	g.Set("machSeal", js.FuncOf(sealFn))
	g.Set("machFingerprint", js.FuncOf(fingerprintFn))
	select {}
}
