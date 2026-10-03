#!/bin/sh
# brew-bump.sh — render the tap formula from the goreleaser artifacts and
# push it to TevaServices/homebrew-mach.
#
# Usage: brew-bump.sh <version-with-v> <dist-dir> [<tap-repo-dir>]
#
# Inputs are the artifacts release.yml's goreleaser job staged: the zips
# (mach_<ver>_<os>_<arch>.zip) and checksums.txt. The formula's URLs and
# sha256s come from those — never from a tag guess — so a formula that
# installs is a formula built from the same run that shipped the release.
#
# The tap commit is made as tevaservices-hermes-dev[bot] (the installer
# identity, matching the rest of the pipeline); the push needs content-write
# on the tap (GORELEASER_GH_TOKEN), which the release workflow passes.
set -eu

TAG="${1:?usage: brew-bump.sh <v-tag> <dist-dir> [<tap-checkout>]}"
DIST="${2:?usage: brew-bump.sh <v-tag> <dist-dir> [<tap-checkout>]}"
TAP="${3:-}"

VER="${TAG#v}"
REPO_ROOT="$(pwd)"

[ -f "$DIST/checksums.txt" ] || { echo "brew-bump: no $DIST/checksums.txt" >&2; exit 1; }

# sha256 for one platform from goreleaser's checksums.txt (path field is
# mach_<ver>_<os>_<arch>.zip; goreleaser writes "<sha256>  <path>").
sha_for() {
    awk -v path="$1" 'index($0, path) { print $1; exit }' "$DIST/checksums.txt"
}

LINUX_AMD64=$(sha_for "mach_${VER}_linux_amd64.zip")
LINUX_ARM64=$(sha_for "mach_${VER}_linux_arm64.zip")
DARWIN_AMD64=$(sha_for "mach_${VER}_darwin_amd64.zip")
DARWIN_ARM64=$(sha_for "mach_${VER}_darwin_arm64.zip")

missing=0
for var in "$LINUX_AMD64" "$LINUX_ARM64" "$DARWIN_AMD64" "$DARWIN_ARM64"; do
    [ -n "$var" ] || { echo "brew-bump: missing checksum for one platform in checksums.txt" >&2; missing=1; }
done
[ "$missing" = 0 ] || exit 1

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

sed -e "s/__VER__/$VER/g" \
    -e "s/__V_TAG__/$TAG/g" \
    -e "s/__SHA_LINUX_AMD64__/$LINUX_AMD64/" \
    -e "s/__SHA_LINUX_ARM64__/$LINUX_ARM64/" \
    -e "s/__SHA_DARWIN_AMD64__/$DARWIN_AMD64/" \
    -e "s/__SHA_DARWIN_ARM64__/$DARWIN_ARM64/" \
    "$REPO_ROOT/packaging/homebrew/mach.rb.tmpl" > "$staging/mach.rb"

if [ -z "$TAP" ]; then
    echo "$staging/mach.rb rendered (no tap checkout given; not publishing)"
    cat "$staging/mach.rb"
    exit 0
fi

mkdir -p "$TAP/Formula"
cp "$staging/mach.rb" "$TAP/Formula/mach.rb"
cd "$TAP"
git config user.name "tevaservices-hermes-dev[bot]"
git config user.email "332528159+tevaservices-hermes-dev[bot]@users.noreply.github.com"
git add Formula/mach.rb
if git diff --cached --quiet; then
    echo "brew-bump: formula unchanged"
else
    git commit -m "mach $VER

Signed-off-by: tevaservices-hermes-dev[bot] <332528159+tevaservices-hermes-dev[bot]@users.noreply.github.com>"
    git push origin HEAD
fi
echo "brew-bump: tap updated for $TAG"