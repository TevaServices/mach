#!/bin/sh
# The browser-side seal (cmd/_uiseal, internal/e2e compiled for js/wasm) is a
# built artifact, NOT committed source: whatever compiles the control plane
# must produce it first, because internal/server embeds it. This script is
# the single home for what that means — the input list, the build flags and
# the GOTOOLCHAIN pin — so CI, Docker and local dev cannot build three
# different seals out of three copies of the recipe.
#
# Modes:
#     wasm-ensure.sh            ensure the artifact exists and matches the
#                               current inputs; rebuild only when the input
#                               hash differs from the recorded stamp
#     wasm-ensure.sh --force    rebuild regardless of the stamp
#     wasm-ensure.sh --hash     print the input hash and exit (no Go needed);
#                               this is what CI keys its artifact cache on,
#                               so "only when the relevant files change" is
#                               decided here and nowhere else
#
# The pin matters because the wasm runtime the page loads (static/wasm_exec.js)
# is vendored FROM A TOOLCHAIN: the GOTOOLCHAIN pin below must be the same
# version that produced wasm_exec.js, and the two move together in one
# commit. Bumping the pin changes this script, which is itself a hash input,
# so the artifact rebuilds the first time anything needs it.
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ART="$REPO/internal/server/static/mach-seal.wasm"
STAMP="$REPO/internal/server/static/.mach-seal.stamp"
LOCKDIR="$REPO/internal/server/static/.mach-seal.lock"

# The seal's inputs. go.mod/go.sum are the module graph (x/crypto versions
# change the binary); the script itself carries the flags and the pin.
PIN=go1.26.6
HASH_INPUTS="scripts/wasm-ensure.sh cmd/_uiseal internal/e2e internal/protocol go.mod go.sum"

die() { echo "wasm-ensure: $*" >&2; exit 1; }

# hash_input prints the hash of the seal's inputs: every hashed file's
# contents, concatenated in sorted-path order. sha256sum exists on Linux and
# in Git-for-Windows' bash; macOS ships shasum.
hash_input() {
	files=$(for p in $HASH_INPUTS; do
		if [ -d "$REPO/$p" ]; then
			(cd "$REPO" && find "$p" -type f -name '*.go') || die "listing $p"
		elif [ -f "$REPO/$p" ]; then
			echo "$p"
		else
			die "hash input $p is missing"
		fi
	done)
	[ -n "$files" ] || die "no hash inputs found"
	(cd "$REPO" && echo "pin=$PIN" && for f in $(printf '%s\n' "$files" | sort); do cat "$f"; done) \
		| hash256
}

hash256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 | cut -d' ' -f1
	else
		die "neither sha256sum nor shasum is available"
	fi
}

is_fresh() {
	[ -f "$ART" ] && [ -f "$STAMP" ] && [ "$(cat "$STAMP" 2>/dev/null || echo x)" = "$(hash_input)" ]
}

build() {
	echo "wasm-ensure: building the browser seal (GOTOOLCHAIN=$PIN)"
	(cd "$REPO" && GOTOOLCHAIN=$PIN CGO_ENABLED=0 GOOS=js GOARCH=wasm \
		go build -trimpath -ldflags "-s -w" \
		-o "internal/server/static/mach-seal.wasm" ./cmd/_uiseal) \
		|| die "build failed"
	hash_input > "$STAMP"
}

case "${1:-}" in
--hash)
	hash_input
	exit 0
	;;
--force)
	build
	echo "wasm-ensure: wrote $ART"
	exit 0
	;;
esac

if is_fresh; then
	echo "wasm-ensure: fresh"
	exit 0
fi

# One artifact, possibly four racing mise dependencies (lint, build, test and
# e2e all ensure it): hold an mkdir lock and re-check when it is ours — the
# builder that finishes first updates the stamp, and the losers then skip
# without rebuilding.
i=0
while ! mkdir "$LOCKDIR" 2>/dev/null; do
	if is_fresh; then
		echo "wasm-ensure: fresh (another build just finished)"
		exit 0
	fi
	i=$((i + 1))
	[ "$i" -gt 240 ] && die "could not acquire the build lock after 60s"
	sleep 0.25
done
# The trap belongs to the holder only: an early exit above must not remove
# somebody else's lock.
trap 'rmdir "$LOCKDIR" 2>/dev/null || true' EXIT
if is_fresh; then
	echo "wasm-ensure: fresh (built while the lock was waited on)"
	exit 0
fi
build
echo "wasm-ensure: wrote $ART"