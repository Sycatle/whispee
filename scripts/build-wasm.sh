#!/usr/bin/env bash
#
# Builds `crates/crypto-wasm` into the directory given as `$1`.
#
# # Why this is a script and not two command lines
#
# It used to be two: one in `apps/web/package.json` as `pnpm run wasm`, which produces the
# artefacts that get committed, and one in `scripts/verify-wasm.sh`, which rebuilds them to check
# that the committed copies match. Two copies of a build command that must agree byte for byte is
# a defect waiting for one of them to be edited alone.
#
# # Why RUSTFLAGS, and what it fixes
#
# Rust puts the source path of a panic into the binary. Unremapped, that means the shipped
# `.wasm` carries the absolute paths of whoever built it — `/home/somebody/.cargo/registry/...`
# and the rustup sysroot — so two people, or a person and a CI runner, cannot produce the same
# bytes no matter what is pinned. The byte-exact comparison in `verify-wasm.sh` therefore only
# ever passed on the machine that generated the artefact, and it took a working CI to say so: the
# committed binary even carried strings from two different toolchains, one of them from before
# `rust-toolchain.toml` pinned the channel, because an incremental `target/` had kept them.
#
# `--remap-path-prefix` rewrites those three roots to fixed names, which makes the output depend
# on the source and the pinned toolchain rather than on the directory it was built in. Verified
# by building the same commit from two directories with different names and comparing.
#
# `trim-paths` would be the tidy way to say this and is not stabilised in Cargo 1.95.0.
#
# The remapped names are arbitrary; they only have to be identical everywhere. Changing one
# changes every byte of the output, so it invalidates the committed artefacts on purpose.
set -euo pipefail

out="${1:?usage: build-wasm.sh <out-dir>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
sysroot="$(rustc --print sysroot)"

RUSTFLAGS="--remap-path-prefix=$cargo_home/registry=/registry \
--remap-path-prefix=$sysroot=/rust \
--remap-path-prefix=$root=/build" \
  wasm-pack build --target web --release --out-dir "$out" "$root/crates/crypto-wasm"
