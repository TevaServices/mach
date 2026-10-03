#!/bin/sh
# repo-apk.sh — the APKINDEX half of scripts/repo-sync.sh, for running
# INSIDE an alpine container ('docker run -v <pages>:/w alpine:3.22 sh
# /src/scripts/repo-apk.sh /w'): apk index is an alpine-native tool.
#
# Expects repo-sync.sh (MODE=no-apk copy of the apks) to have already
# placed the .apk files under <pages>/apk/<arch>/.
#
# Index is UNSIGNED this round. apk's local validation of an unsigned
# index refused it even under --allow-untrusted on a bare apk-tools 2.14
# invocation (trust model wants per-repo context); the release workflow
# therefore validates the built repos INSIDE an alpine container, and the
# consumer line stays `apk add --repository <url> --allow-untrusted` until
# signing lands. When a key exists: abuild-sign APKINDEX.tar.gz (public key
# ships to /etc/apk/keys on consumers) — see repo-sync.sh header.
set -eu
PAGES="${1:?usage: repo-apk.sh <pages-root>}"

for d in "$PAGES"/apk/x86_64 "$PAGES"/apk/aarch64; do
    [ -d "$d" ] || continue
    cd "$d"
    ls *.apk >/dev/null 2>&1 || continue
    apk index --allow-untrusted --quiet -o APKINDEX.tar ./*.apk
    gzip -9n APKINDEX.tar -c > APKINDEX.tar.gz.new
    mv APKINDEX.tar.gz.new APKINDEX.tar.gz
    rm APKINDEX.tar
done
echo "repo-apk: indexed $(find "$PAGES/apk" -name '*.apk' | wc -l) packages"