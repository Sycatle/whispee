#!/usr/bin/env bash
#
# Verifies a release of the desktop app.
#
# # Who this script is for
#
# Whoever **receives** the binary, not whoever produced it. So it asks for no private key and
# depends only on `openssl`: it must run on a machine that has nothing of this project beyond
# the public key and the published files.
#
# # What it establishes
#
# That the release was signed by the holder of the matching private key, and that the files have
# not changed since. Nothing more.
#
# # What it does not establish
#
# * **That this public key is the right one.** This is trust on first use, exactly like account
#   registration: nothing proves the first key you meet is legitimate. The key lives in the
#   repository, so whoever controls the repository can replace it along with the binary. The only
#   real protection is comparing its fingerprint out of band — the same gesture as the account
#   fingerprint check the app already asks for.
# * **That the binary matches the code.** That is established by rebuilding it from the commit
#   named in `BUILD-INFO`, with the same tool versions, and comparing hashes. The signature
#   authenticates the publisher; only the rebuild authenticates the code.
#
# # Usage
#
#   scripts/verify-release.sh [directory] [public-key]
#
# Defaults: `release/artefacts` and `release/whispee.pub`.
set -euo pipefail

artifacts="${1:-release/artefacts}"
public_key="${2:-release/whispee.pub}"

for file in "$artifacts/SHA256SUMS" "$artifacts/SHA256SUMS.sig" "$public_key"; do
    if [[ ! -r "$file" ]]; then
        echo "error: missing or unreadable file: $file" >&2
        exit 1
    fi
done

# The signature first, the hashes second. The other way round would validate hashes that anyone
# could have rewritten along with the binary: the hash file is only worth the signature covering
# it.
if ! openssl pkeyutl -verify -rawin -pubin -inkey "$public_key" \
    -in "$artifacts/SHA256SUMS" -sigfile "$artifacts/SHA256SUMS.sig" >/dev/null 2>&1; then
    echo "FAILED: the signature does not match this public key" >&2
    echo "this release was not produced by the holder of the expected key" >&2
    exit 1
fi
echo "✓ valid signature"

if ! (cd "$artifacts" && sha256sum --quiet --check SHA256SUMS); then
    echo "FAILED: a file does not match its signed hash" >&2
    exit 1
fi
echo "✓ hashes match"

echo
echo "declared build environment:"
sed 's/^/    /' "$artifacts/BUILD-INFO"
echo
echo "To establish that this binary matches the code, rebuild it from the commit above with the"
echo "same tool versions, then compare the hashes."
