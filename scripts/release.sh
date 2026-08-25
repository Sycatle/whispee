#!/usr/bin/env bash
#
# Builds a verifiable release of the desktop app, and signs it.
#
# # Reproducible first, signed second
#
# A signature says "someone holding this key produced this file". It does not say "this file
# matches this code". For a project whose thesis is that users should not have to take the
# operator's word for it, the order matters: a reproducible binary is verified by rebuilding it,
# trusting no one. The signature then only authenticates the release.
#
# # Why the prefixes are computed and not written into `.cargo/config.toml`
#
# Without `--remap-path-prefix`, the binary embeds the absolute path of the build directory —
# 217 occurrences, measured before this script. Two honest builds of the same commit, on two
# machines, then produce two different hashes.
#
# Hard-coding them into a committed config file would reproduce the very flaw they fix: they
# would only hold for the machine of whoever wrote them. So they are derived here from
# `git rev-parse` and `CARGO_HOME`.
#
# Both prefixes matter. The repository one erases our own code's paths; the registry one erases
# the dependencies', which live under `CARGO_HOME` and vary per user. Forgetting the second
# leaves reproducibility quietly false: it holds on one machine and breaks elsewhere — that is,
# at the only moment it is useful.
#
# # Usage
#
#   scripts/release.sh /path/to/private-key.pem
#   RELEASE_KEY=/path/to/private-key.pem scripts/release.sh
#
# The private key is never read from the repository and never enters it. To create one:
#
#   openssl genpkey -algorithm ed25519 -out private-key.pem
#   openssl pkey -in private-key.pem -pubout -out release/whispee.pub
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

key="${1:-${RELEASE_KEY:-}}"
if [[ -z "$key" ]]; then
    echo "error: missing private key path (argument or RELEASE_KEY)" >&2
    echo "see the header of this script to produce one" >&2
    exit 1
fi
if [[ ! -r "$key" ]]; then
    echo "error: unreadable private key: $key" >&2
    exit 1
fi

# A release whose content matches no commit is not verifiable: nobody would know what to rebuild
# to compare it. That is the kind of mistake only noticed after distribution, so refuse before.
if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: the working tree has uncommitted changes" >&2
    echo "a release must match exactly one commit" >&2
    exit 1
fi

commit="$(git rev-parse HEAD)"

# Neutralises build timestamps. The commit date rather than the current time: it is the same for
# everyone who rebuilds this commit.
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
export SOURCE_DATE_EPOCH

cargo_home="${CARGO_HOME:-$HOME/.cargo}"

# The sysroot matters as much as the other two. Panic messages from `core` and `alloc` carry the
# standard library's path, which lives under the home directory: without this third prefix, 26
# absolute paths remained in the binary — against 217 with no remap at all. Few enough to go
# unnoticed on review, enough for two users to get different hashes.
sysroot="$(rustc --print sysroot)"

export RUSTFLAGS="--remap-path-prefix=$root=/build"
RUSTFLAGS+=" --remap-path-prefix=$cargo_home/registry=/cargo-registry"
RUSTFLAGS+=" --remap-path-prefix=$sysroot=/rust-sysroot"

output="$root/release/artefacts"
rm -rf "$output"
mkdir -p "$output"

echo "→ building the front end"
(cd apps/web && pnpm install --frozen-lockfile && pnpm run build)

echo "→ building the binary"
cargo build -p desktop --release

# `whispee`, because that is what `apps/desktop/Cargo.toml` names the binary — the crate is called
# `desktop` and its artefact is not. This line said `target/release/desktop` while it was.
cp target/release/whispee "$output/whispee"

# Tool versions are part of the release, not of the documentation. Reproducibility holds **for a
# given environment**: a different `rustc` or `pnpm` produces a different binary without anything
# being compromised. Without this file, a verifier cannot tell tampering from a mere toolchain
# mismatch — and learns to ignore the failure.
cat > "$output/BUILD-INFO" <<INFO
commit=$commit
source_date_epoch=$SOURCE_DATE_EPOCH
rustc=$(rustc --version)
cargo=$(cargo --version)
node=$(node --version)
pnpm=$(pnpm --version)
INFO

echo "→ hashes and signature"
(cd "$output" && sha256sum whispee BUILD-INFO > SHA256SUMS)

# The signature covers `SHA256SUMS`, not the binary: a single signed file then covers the whole
# release, `BUILD-INFO` included. Signing the binary alone would leave the toolchain versions
# editable without the signature noticing.
openssl pkeyutl -sign -rawin -inkey "$key" \
    -in "$output/SHA256SUMS" -out "$output/SHA256SUMS.sig"

echo
echo "release ready in release/artefacts:"
ls -1 "$output"
echo
echo "verify it with: scripts/verify-release.sh"
