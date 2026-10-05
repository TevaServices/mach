for f in $(by_ext rpm); do cp "$f" "$YUM/."; done
createrepo_c "$YUM"

# createrepo_c finalizes by silently renaming its .repodata/ staging into
# repodata/ — and it has been observed NOT to do that on GitHub's runners,
# three release runs in a row, exit 0, log lines identical to runs that
# finalize correctly in containers at the same version. Two shapes seen:
# v0.12.3 left everything under the hidden .repodata/; v0.12.4 left
# repomd.xml in repodata/ and the named metadata flat beside the rpms.
# Whatever the tool leaves, a consumer reads repodata/repomd.xml plus named
# files in the same dir — make that true, print the evidence, and fail
# loudly if the layout is still wrong.
if [ ! -f "$YUM/repodata/repomd.xml" ] && [ -d "$YUM/.repodata" ]; then
    mv "$YUM/.repodata" "$YUM/repodata"
fi
if [ ! -f "$YUM/repodata/repomd.xml" ]; then
    mkdir -p "$YUM/repodata"
fi
if ! ls "$YUM"/repodata/*primary* >/dev/null 2>&1; then
    # The named metadata is not in repodata/: collect every non-rpm file in
    # the repo root into it (flat-write variant; a second call's .repodata
    # leftovers are removed below, they are staging, not data).
    find "$YUM" -maxdepth 1 -type f ! -name '*.rpm' -exec mv {} "$YUM/repodata/" \;
fi
rm -rf "$YUM/.repodata"
echo "repo-sync: rpm repodata:"
find "$YUM/repodata" -type f | sort
[ -f "$YUM/repodata/repomd.xml" ] || { echo "repo-sync: rpm repomd.xml missing after createrepo_c — the consumer layout is not buildable; failing loudly" >&2; exit 1; }
ls "$YUM"/repodata/*primary* >/dev/null