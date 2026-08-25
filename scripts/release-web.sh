#!/usr/bin/env bash
#
# Builds the web client and lists what it produced, hash by hash.
#
# # What this is for
#
# The client tells its user, in a banner, that the server "could deliver a version that
# exfiltrates your keys". That is true of every web application and no browser API fixes it. What
# does help is a list of hashes published somewhere the delivering server does not control: then a
# reader — or an extension — can compare the bytes their browser received against the bytes this
# commit produces, and a substitution stops being invisible.
#
# This script produces that list. `.github/workflows/release.yml` runs it on a tag and publishes
# the result with a GitHub attestation, which is what makes the manifest independent of whoever
# runs the deployment. `scripts/verify-web.sh` is the other end.
#
# # Why the manifest describes every deployment at once
#
# Because the bundle no longer carries any deployment's configuration. The API is reached on the
# page's own origin and the Content-Security-Policy says `'self'`, so two instances of the same
# commit serve byte-identical files — measured, and the reason `apps/web/src/lib/api.ts` and
# `csp.ts` are written the way they are. Before that, a manifest could only ever have described
# one instance, which would have made this whole mechanism a service to the official deployment
# and to nobody else.
#
# The exception is `VITE_MEDIA_URL`: a deployment configuring calls names a media origin in its
# policy and its `index.html` stops matching. That trade is in `docs/THREAT-MODEL.md`, and this
# script deliberately builds **without** it — the published manifest describes the build a
# verifier can reproduce, not the one a particular operator chose.
#
# # Why `SOURCE_DATE_EPOCH`
#
# For the same reason `release.sh` exports it: the commit's own date is the same for everybody who
# rebuilds this commit, where the current time is different for each of them. Vite embeds no
# timestamp today, so this changes nothing measurable — it is here so that the day a dependency
# starts embedding one, it embeds the same one everywhere.
#
# # Usage
#
#   scripts/release-web.sh [output-directory]
#
# Default output is `release/web`. Nothing here is signed: the attestation happens in CI, where
# the signing identity is the workflow rather than a key somebody carries.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

output="${1:-$root/release/web}"

# A manifest whose content matches no commit is not verifiable: nobody would know what to rebuild
# in order to compare. Same refusal as `release.sh`, for the same reason, and it is the one check
# that cannot be added later — by then the artefact exists.
if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: the working tree has uncommitted changes" >&2
    echo "a manifest must match exactly one commit" >&2
    exit 1
fi

commit="$(git rev-parse HEAD)"

SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
export SOURCE_DATE_EPOCH

echo "→ building the client"
# `--frozen-lockfile` because a manifest built from a resolved-on-the-fly dependency tree
# describes a build nobody else can reproduce.
(cd apps/web && pnpm install --frozen-lockfile && pnpm run build)

rm -rf "$output"
mkdir -p "$output"

echo "→ hashing $(find apps/web/dist -type f | wc -l) files"

# Paths relative to the served root, so a verifier can turn each line straight into a URL. Sorted
# by `LC_ALL=C` so the file is byte-identical wherever it is produced — a manifest that differs
# only in line order would defeat its own purpose.
(
    cd apps/web/dist
    find . -type f -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 sha256sum \
        | sed 's#  \./#  #'
) > "$output/WEB-SHA256SUMS"

# What produced it. Not decoration: two of these lines are the first thing to compare when a
# rebuild does not match, and the toolchain versions are what a verifier has to install.
cat > "$output/BUILD-INFO" <<INFO
commit=$commit
source_date_epoch=$SOURCE_DATE_EPOCH
node=$(node --version)
pnpm=$(pnpm --version)
files=$(wc -l < "$output/WEB-SHA256SUMS")
INFO

echo
echo "manifest ready in ${output#"$root"/}:"
ls -1 "$output"
echo
echo "check a live deployment against it with:"
echo "  scripts/verify-web.sh https://your.deployment ${output#"$root"/}/WEB-SHA256SUMS"
