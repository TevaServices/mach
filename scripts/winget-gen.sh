#!/bin/sh
# winget-gen.sh — render the winget manifests for a release into dist/winget/.
#
# Usage: winget-gen.sh <v-tag> <dist-dir-with-msi-logs-and-sha-notes>
#
# MSI URLs point at this release's GitHub download. The sha256 notes and the
# verbose install logs come from release.yml's msi job (it computes the
# hash over the artifact it uploads; the log names the installed
# ProductCode, which winget checks). Submission is a HUMAN step — see
# packaging/winget/README.md for the runbook.
set -eu
TAG="${1:?usage: winget-gen.sh <v-tag> <dist-dir>}"
DIST="${2:?usage: winget-gen.sh <v-tag> <dist-dir>}"
VER="${TAG#v}"
BASE="https://github.com/TevaServices/mach/releases/download/$TAG"

sha_of() { awk '{print $NF}' "$DIST/mach-exe-sha256-$1.txt" 2>/dev/null || true; }

# WiX re-mints the ProductCode every build; the msi validation log is where
# the shipped MSI's actual code is recorded. (The installer log lines read
#   Property(S): ProductCode = {GUID}
# — braces are stripped here; the template supplies its own.)
productcode_of() {
    grep -m1 "ProductCode = {" "$DIST/msi-log-$1.txt" 2>/dev/null |
        awk '{print $NF}' | tr -d '{}' || true
}

SHA_X64=$(sha_of x64); SHA_ARM64=$(sha_of arm64)
PC_X64=$(productcode_of x64); PC_ARM64=$(productcode_of arm64)
missing=0
for v in "$SHA_X64" "$SHA_ARM64" "$PC_X64" "$PC_ARM64"; do
    [ -n "$v" ] || { echo "winget-gen: missing sha note or msi log in $DIST" >&2; missing=1; }
done
[ "$missing" = 0 ] || exit 1

mkdir -p "$DIST/winget"
for f in packaging/winget/*.tmpl; do
    out="$DIST/winget/$(basename "${f%.tmpl}")"
    sed -e "s/__VER__/$VER/g" \
        -e "s#__MSI_URL_X64__#$BASE/mach-x64.msi#" \
        -e "s#__MSI_URL_ARM64__#$BASE/mach-arm64.msi#" \
        -e "s/__SHA_X64__/$SHA_X64/" \
        -e "s/__SHA_ARM64__/$SHA_ARM64/" \
        -e "s/__PRODUCTCODE_X64__/$PC_X64/" \
        -e "s/__PRODUCTCODE_ARM64__/$PC_ARM64/" "$f" > "$out"
done
find "$DIST/winget" -type f | sort