#!/usr/bin/env bash
# Source-integrity check for the Mbed TLS SDK.
#
# Four questions, all answerable without a compiler:
#
#   1. Do the vendored upstream files still hash to the digests
#      UPSTREAM.sha256 records?
#   2. Is the native file set exactly that set -- no missing, extra or renamed
#      file under src/ or fixtures/?  A plain checksum run cannot see an
#      addition.
#   3. Do UPSTREAM.md and UPSTREAM.sha256 still agree? One records the digests
#      of the files this tree carries, the other states the release those files
#      came from, so what can be compared across the two is the release
#      identity and the digests both of them record - not the tarball digest,
#      which only UPSTREAM.md has. The preserved upstream README is covered
#      twice: `sha256sum -c` re-hashes it in step 1, and step 3a checks that
#      UPSTREAM.md states the digest the manifest records for it.
#   4. Is Mbed TLS's own dual grant still where the records say it is, in the
#      file that carries it and in the three documents that quote it?
#
# This is a provenance gate, not a build gate. Nothing here compiles, links or
# runs a target binary; it is the check that an edit to the canonical native
# source cannot pass as a routine change.
#
# Usage: tools/check-provenance.sh   (run from anywhere in the repository)
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
    echo "$1" >&2
    exit 1
}

# 1. Bytes.
sha256sum -c --quiet UPSTREAM.sha256 || fail "an upstream file no longer matches UPSTREAM.sha256"
echo "every recorded upstream file matches UPSTREAM.sha256"

# 2. File set. `--quiet` above cannot see an addition, so the manifest's own
# path list is compared against what is actually on disk.
expected_tree=$(awk '/^[0-9a-f]{64}  / { print $2 }' UPSTREAM.sha256 | grep -E '^(src|fixtures)/' | LC_ALL=C sort)
actual_tree=$(find src fixtures -type f | LC_ALL=C sort)
if [ "$expected_tree" != "$actual_tree" ]; then
    echo "the native file set differs from the recorded one:" >&2
    diff -u <(echo "$expected_tree") <(echo "$actual_tree") >&2 || true
    echo >&2
    echo "An intentional change to the native source needs an observed failure, a" >&2
    echo "small causal patch, an explicit per-file deviation record in NOTICE.md," >&2
    echo "updated digests here, and a CHANGELOG.md entry in the same change." >&2
    exit 1
fi
echo "the native file set is exactly the recorded one"

# 3a. The release identity, and the digests both records state.
#
# The release digest is read the way UPSTREAM.md records it: as the
# `| sha256 | `...` |` cell of the canonical-source table, not as a bare
# 64-digit line. `awk` rather than `grep -m1` in a pipeline, because a `head`
# that closes the pipe early sends SIGPIPE to grep and `pipefail` turns a
# successful match into a failed pipeline.
#
# It cannot be compared against a digest in UPSTREAM.sha256, and comparing it
# against one that file does not carry would be the weakest thing this gate
# could do: UPSTREAM.sha256 records digests of *vendored files*, and the
# tarball's digest appears in it nowhere (UPSTREAM.md, "Import mechanism").
# What is compared is what the two files do both state: the release they
# belong to, and the digests of the files each of them records. Every value
# below is read out of one file or the other, and a value that cannot be read
# fails this gate rather than passing it.
digest_md=$(awk -F'`' '/^\| sha256 \| `[0-9a-f]{64}` \|/ { print $2; exit }' UPSTREAM.md)
[[ "$digest_md" =~ ^[0-9a-f]{64}$ ]] ||
    fail "UPSTREAM.md records no release sha256 digest in its canonical-source table"

tag_md=$(awk -F'`' '/^\| Tag \| `/ { print $2; exit }' UPSTREAM.md)
[ -n "$tag_md" ] || fail "UPSTREAM.md records no release tag in its canonical-source table"

# UPSTREAM.sha256 names the release in its own header line, inside the last
# parenthetical: "... (Mbed TLS 3.6.7)." Shell parameter expansion rather than
# a pattern that assumes the wording, so the check still works if the words
# around the version change. The full stop is peeled before the parenthesis
# because `%` removes a *suffix*: the line ends `).`, so the `)` is not the
# last character until the `.` is gone.
header_list=$(head -n 1 UPSTREAM.sha256)
release_list=${header_list#*\(}
release_list=${release_list%.}
release_list=${release_list%)}
[[ "$release_list" =~ ^.+[[:space:]][0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    fail "UPSTREAM.sha256 names no product release in its header line"
[ "${tag_md#mbedtls-}" = "${release_list##* }" ] ||
    fail "UPSTREAM.md tags $tag_md but UPSTREAM.sha256 names $release_list"

readme_digest=$(awk '$2 == "README.upstream.md" { print $1; exit }' UPSTREAM.sha256)
[[ "$readme_digest" =~ ^[0-9a-f]{64}$ ]] ||
    fail "UPSTREAM.sha256 records no digest for README.upstream.md"
grep -q -- "$readme_digest" UPSTREAM.md ||
    fail "UPSTREAM.md does not state the digest UPSTREAM.sha256 records for README.upstream.md"
echo "the release and the recorded digests agree: $tag_md ($digest_md)"

# 3b. Mbed TLS's own grant. It lives in src/LICENSE lines 1-2 and in the SPDX
# tag of every core source file; the three records must quote it too.
grep -q 'dual \[Apache-2.0\]' src/LICENSE ||
    fail "the dual Apache-2.0 / GPL-2.0-or-later statement is missing from src/LICENSE"
for file in NOTICE.md README.md FORK-LICENSE.md; do
    grep -q 'Apache-2.0 OR GPL-2.0-or-later' "$file" ||
        fail "the upstream dual-licence identifier is missing from $file"
done
# The bundled third-party material is Apache-2.0 only and must not be
# restated as part of the dual grant. everest's own notice is the witness.
grep -q 'Licensed under the Apache 2.0 License' src/3rdparty/everest/library/Hacl_Curve25519.c ||
    fail "Everest's Apache-2.0 notice is missing from its generated source"
grep -q 'Copyright (c) INRIA and Microsoft Corporation' NOTICE.md ||
    fail "NOTICE.md does not name the Everest copyright holders"
echo "the upstream dual grant and the bundled Apache-2.0 material are both present"

# 3c. The fixtures are upstream's own test certificates, so their provenance is
#     a matter of record: the file names are fixed and must not be swapped for
#     something this package generated without a matching NOTICE.md entry, and
#     the digest each record states for one has to be the same digest.
for fixture in test-ca.crt server2.crt server2.key; do
    [ -f "fixtures/$fixture" ] || fail "the handshake fixture fixtures/$fixture is missing"
    grep -q "fixtures/$fixture" UPSTREAM.sha256 ||
        fail "fixtures/$fixture is not digested in UPSTREAM.sha256"
    grep -q "fixtures/$fixture" UPSTREAM.md ||
        fail "fixtures/$fixture has no provenance record in UPSTREAM.md"
    # The same path in both records, and the digests have to be one digest: the
    # manifest's entry is what step 1 re-hashes, and UPSTREAM.md's table cell is
    # what a reader compares against it.
    digest_recorded=$(awk -v path="fixtures/$fixture" '$2 == path { print $1; exit }' UPSTREAM.sha256)
    digest_stated=$(awk -F'`' -v path="fixtures/$fixture" 'index($0, "| `" path "`") == 1 { print $4; exit }' UPSTREAM.md)
    [[ "$digest_recorded" =~ ^[0-9a-f]{64}$ ]] ||
        fail "UPSTREAM.sha256 records no sha256 digest for fixtures/$fixture"
    [ "$digest_recorded" = "$digest_stated" ] ||
        fail "UPSTREAM.md and UPSTREAM.sha256 disagree about the sha256 of fixtures/$fixture"
done
echo "the handshake fixtures are recorded and digested"

echo "provenance checks passed"