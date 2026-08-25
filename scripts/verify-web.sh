#!/usr/bin/env bash
#
# Checks what a deployment actually serves against what a commit produces.
#
# # What this answers, and what it does not
#
# It answers: "are the files this server is handing me the ones that commit built?" It does not
# answer "is this server honest", and cannot — a server willing to serve one build to the world
# and another to one person will pass this check for everybody who runs it and fail only for the
# person it is attacking, who is the person not running it.
#
# That is the ceiling of this approach, and it is why the browser extension exists: the same
# comparison, run continuously, by the reader rather than about them. This script is the version a
# human can run today, and the thing the extension automates.
#
# # Where the manifest must come from
#
# **Not from the deployment being checked.** A server that serves both the code and the list of
# hashes for that code certifies itself, which is exactly the defect this whole mechanism exists
# to remove — and the same defect `docs/THREAT-MODEL.md` records for the transparency log being
# signed by the server it watches.
#
# So the manifest is a local file, fetched from a GitHub release:
#
#   gh release download v0.1.0 --pattern WEB-SHA256SUMS
#   gh attestation verify WEB-SHA256SUMS --repo Sycatle/whispee
#
# The second line is the one that matters. It checks that this manifest came out of the
# repository's own workflow, on a commit, and not out of somebody's laptop.
#
# # Usage
#
#   scripts/verify-web.sh https://your.deployment WEB-SHA256SUMS
set -euo pipefail

origin="${1:-}"
manifest="${2:-}"

if [[ -z "$origin" || -z "$manifest" ]]; then
    echo "usage: scripts/verify-web.sh <origin> <manifest>" >&2
    echo "  scripts/verify-web.sh https://whispee.example WEB-SHA256SUMS" >&2
    exit 2
fi

if [[ ! -r "$manifest" ]]; then
    echo "error: cannot read $manifest" >&2
    exit 1
fi

origin="${origin%/}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

checked=0
missing=0
altered=0

# Read the manifest rather than crawl the site: what is being asked is "does the server have these
# bytes at these paths", and a crawl would only ever find the files the server chose to link. A
# file served at a path the manifest does not list is invisible here — see the note at the end.
while read -r expected path; do
    [[ -z "$path" ]] && continue

    if ! curl -fsSL --max-time 30 "$origin/$path" -o "$work/fetched" 2>/dev/null; then
        echo "MISSING   $path"
        missing=$((missing + 1))
        continue
    fi

    actual="$(sha256sum "$work/fetched" | cut -d' ' -f1)"

    if [[ "$actual" != "$expected" ]]; then
        echo "ALTERED   $path"
        echo "          expected $expected"
        echo "          served   $actual"
        altered=$((altered + 1))
        continue
    fi

    checked=$((checked + 1))
done < "$manifest"

echo
echo "$checked file(s) matched, $altered altered, $missing missing"

if (( altered > 0 || missing > 0 )); then
    echo
    echo "This deployment is not serving the build that manifest describes." >&2
    exit 1
fi

echo
echo "Every file this manifest lists is served byte for byte."
echo
# Stated on success rather than buried in the header, because success is the moment somebody is
# most likely to over-read the result.
echo "What that does not establish: that the manifest is genuine — check it with"
echo "\`gh attestation verify\`, against the repository, not against this server — and that the"
echo "server serves the same thing to somebody else. A file at a path the manifest does not list"
echo "is not covered by this check at all."
