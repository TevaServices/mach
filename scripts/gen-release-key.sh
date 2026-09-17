#!/bin/sh
# Generate the ed25519 signing key used to attest release binaries.
#
# Prints a hex-encoded ed25519 private key on stdout. Use the printed value as
# the MACH_RELEASE_SIGNING_KEY repository secret for the release workflow.
#
# To use it with a control plane instead, write it to a file (mode 600) and
# point MACH_SERVER_KEY at that PATH: the variable names the key FILE, not the
# key, so exporting the hex value itself fails with "control plane key missing —
# run serve once first: open <hex>: no such file or directory". `mach-server
# attest` and `verify-attestation` both load the file that path names.
#
# The last 64 hex characters are the public half — that is what is attached to
# a release as mach-release-signing-key.pub and what a DSSE verifier checks
# against. Keep the private half to yourself; there is no way to recover a
# lost public half from a signature.
#
# A key exists to be pinned: whoever verifies an attestation must know, out of
# band, that this key is the release key — treat the printed value as a secret
# and do not paste it into an issue or a chat.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/keygen.go" <<'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Print(hex.EncodeToString(priv))
}
EOF
exec go run "$tmp/keygen.go"