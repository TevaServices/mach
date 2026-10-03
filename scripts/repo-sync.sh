#!/bin/sh
# repo-sync.sh — build Linux package-repo metadata from release artifacts.
#
# Input: a directory of *.deb / *.rpm / *.apk (downloaded from a GitHub
# Release by repo-sync.yml). Output: the gh-pages tree layout
# (apt/pool + apt/dists, rpm/ + repodata, apk/x86_64 + APKINDEX).
#
# Layout on gh-pages (see README "Linux package repositories"):
#   apt/pool/main/m/mach/<files>.deb            all debs live here
#   apt/dists/stable/main/binary-<arch>/Packages[.gz]
#   apt/dists/stable/Release
#   rpm/<files>.rpm + rpm/repodata/             one flat repo per arch family? no:
#   rpm/<arch>/...                              (arch comes from the rpm itself)
#   apk/x86_64/*.apk + apk/x86_64/APKINDEX.tar.gz
#
# Signing: intentionally NOT done in this round — no GPG key exists yet.
# The apt Release file carries no checksums signature (consumers use
# [trusted=yes]), rpm repodata is unsigned (gpgcheck=0), APKINDEX unsigned
# (consumers add the repo with --allow-untrusted). When a key exists:
#   - sign apt: gpg --armor --detach-sign -o InRelease dists/stable/Release
#   - sign rpm: gpg --detach-sign repodata/repomd.xml
#   - sign apk: abuild-sign APKINDEX.tar (needs the public key shipped to consumers)
# Each is an additive step; the layout does not change.
set -eu

IN="${1:?usage: repo-sync.sh <dir-with-deb-rpm-apk> <gh-pages-checkout-dir>}"
PAGES="${2:?usage: repo-sync.sh <dir-with-deb-rpm-apk> <gh-pages-checkout-dir>}"

APT="$PAGES/apt"
YUM="$PAGES/rpm"
APK="$PAGES/apk"
mkdir -p "$APT/pool/main/m/mach" "$APT/dists/stable/main" "$YUM" "$APK/x86_64"

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

by_ext() {
    found=0
    for f in "$IN"/*; do
        case "$f" in *."$1") echo "$f"; found=1 ;; esac
    done
    [ "$found" = 1 ] || { echo "repo-sync: no .$1 files in $IN" >&2; return 1; }
}

# Optionally MODE=no-apk: skip the apk section (release.yml runs the apk
# indexing inside an alpine container instead — apk index is an
# alpine-native tool; see scripts/repo-apk.sh).
MODE="${MODE:-all}"

# --- Debian: pool + Packages + Release -------------------------------------
# dpkg-scanpackages indexes every deb under pool/ relative to the apt root.
for f in $(by_ext deb); do cp "$f" "$APT/pool/main/m/mach/"; done
for arch in amd64 arm64; do
    mkdir -p "$APT/dists/stable/main/binary-$arch"
    (cd "$APT" && dpkg-scanpackages --arch "$arch" pool/main/m/mach /dev/null \
        > "dists/stable/main/binary-$arch/Packages")
    gzip -9n -c "$APT/dists/stable/main/binary-$arch/Packages" \
        > "$APT/dists/stable/main/binary-$arch/Packages.gz"
done

# apt Release file: the fields apt requires, plus checksums over everything
# under dists/ (MD5Sum/SHA1/SHA256 sections; apt refuses an apt/https repo
# whose Release lacks the sums of the indexes it fetched).
cd "$APT"
{
    echo "Origin: TevaServices"
    echo "Label: mach"
    echo "Suite: stable"
    echo "Codename: stable"
    echo "Components: main"
    echo "Architectures: amd64 arm64"
    echo "Date: $(date -R -u)"
    echo "Description: mach agent packages"
    echo
    for alg in MD5Sum SHA1 SHA256; do
        echo "$alg:"
        find dists -type f ! -name "Release" | sort | while read -r f; do
            case "$alg" in
                MD5Sum)  sum=$(md5sum  "$f" | cut -d' ' -f1) ;;
                SHA1)    sum=$(sha1sum "$f" | cut -d' ' -f1) ;;
                SHA256)  sum=$(sha256sum "$f" | cut -d' ' -f1) ;;
            esac
            printf ' %s %16s %s\n' "$sum" "$(wc -c < "$f")" "$f"
        done
    done
} > dists/stable/Release
cd - >/dev/null

# --- RPM: one arch-agnostic flat repo ---------------------------------------
# rpms carry their own arch (mach-0.6.5-1.x86_64.rpm, ...aarch64.rpm);
# createrepo_c indexes whatever is in rpm/ and dnf resolves per-arch.
for f in $(by_ext rpm); do cp "$f" "$YUM/."; done
createrepo_c "$YUM"

# --- Alpine: unsigned APKINDEX (consumers add --allow-untrusted for now) ----
# apk index needs apk-tools; repo-sync.yml installs it (static apk binary or
# an alpine container). The index is a tar of APKINDEX descriptors (one per
# package), conventionally gzipped; unsigned indexes work against repos
# added with --allow-untrusted (and -U to skip signature verification).
# Alpine arch convention: x86_64 / aarch64 (the apk name carries it, and the
# APKINDEX records it) — one repo dir per alpine arch, never mixed.
if [ "$MODE" != "no-apk" ]; then
  arches=$(find "$IN" -name '*.apk' | sed -E 's/.*_(x86_64|aarch64)\.apk$/\1/' | sort -u)
  if [ -z "$arches" ]; then echo "repo-sync: no alpine-arch apks found" >&2; exit 1; fi
  for arch in $arches; do
      mkdir -p "$APK/$arch"
      find "$IN" -name "*_${arch}.apk" -exec cp {} "$APK/$arch/" \;
  done
fi

APT_FILES=$(find "$APT" -type f | wc -l)
YUM_FILES=$(find "$YUM" -type f | wc -l)
if [ "$MODE" = "no-apk" ]; then
    echo "repo-sync: apt=$APT_FILES files, yum=$YUM_FILES files (apk handled by repo-apk.sh)"
else
    APK_FILES=$(find "$APK" -type f | wc -l)
    echo "repo-sync: apt=$APT_FILES files, yum=$YUM_FILES files, apk=$APK_FILES files"
fi
