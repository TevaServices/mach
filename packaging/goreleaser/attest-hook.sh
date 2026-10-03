#!/bin/sh
# attest-hook.sh — goreleaser per-build post hook: attest one client binary.
#
# Usage: attest-hook.sh <binary-path> <version> <os> <arch>
#
# goreleaser invokes this once per built target with the binary's dist path
# ({{.Path}}). It produces dist/<name>.intoto.jsonl next to the binary and
# runs verify-attestation on it: a WARNING there means the build came from a
# modified tree or carries no VCS revision — exit 1 and the release fails
# (the same rule release.yml has always enforced; AGENTS.md invariant 13).
#
# mach-server is the attest tool; build it once per run (marker file under
# the goreleaser dist dir) with the same version stamp so its own `attest`
# never disagrees with the release.
set -eu

BIN="$1"; VER="$2"; OS="$3"; ARCH="$4"

# Dist root: the binary lives in dist/<binary>_<os>_<arch>/<name>;
# hooks run from the repo root.
DIST="$(pwd)/dist"
MARKER="$DIST/.mach-server-$VER.attest-tool"
NAME="$(basename "$BIN")"

if [ ! -x "$MARKER" ]; then
    mkdir -p "$DIST"
    CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X github.com/TevaServices/mach/internal/version.Version=$VER" \
        -o "$MARKER" ./cmd/mach-server
fi

# Attest the exact bytes that were built.
"$MARKER" attest "$BIN" "$VER" --out "$BIN.intoto.jsonl"

# Refuse a dirty/untraceable build: verify-attestation exits 0 with a
# WARNING on those, which must not ship.
out=$("$MARKER" verify-attestation "$BIN.intoto.jsonl" "$BIN") || exit 1
printf '%s\n' "$out"
case "$out" in
    *WARNING*) echo "attest-hook: $NAME — attestation reports a warning (modified tree or missing VCS revision); refusing to ship" >&2; exit 1 ;;
esac
echo "attest-hook: $NAME ($OS/$ARCH) attested and verified: $BIN.intoto.jsonl"