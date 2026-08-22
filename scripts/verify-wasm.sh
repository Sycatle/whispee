#!/usr/bin/env bash
#
# Checks that the committed WebAssembly artefacts match `crates/crypto-wasm`.
#
# # Why this script has to exist
#
# `apps/web/public/crypto_wasm_bg.wasm` and `apps/web/src/lib/generated/crypto_wasm.{js,d.ts}`
# are **committed binaries**. Every target loads them: the web bundle, the Tauri desktop binary,
# and the Android APK — `android.yml` says so itself, and adds that changing `crates/crypto-wasm`
# without regenerating them does not change the APK.
#
# So without this check, a correctness fix in the cryptography can be reviewed, merged and
# released without ever reaching a single user, and nothing anywhere would say so. The converse
# is worse: a modified `.wasm` committed on its own passes every other check in the repository,
# because no other check reads it.
#
# # Why a byte-exact comparison is legitimate here
#
# It was measured before being asserted, and measured on one machine, which was the flaw. With
# the toolchain pinned by `rust-toolchain.toml` and the wasm-bindgen version pinned by
# `Cargo.lock`, the build reproduces all three files bit for bit **only if the paths are also
# pinned** — Rust writes the source path of a panic into the binary, so an unremapped build
# carries `/home/whoever/.cargo/...` and no two machines agree. That is what `build-wasm.sh`
# remaps, and why the build lives there rather than here.
#
# Until the first CI run that got this far, this check had only ever passed on the machine that
# generated the artefact, and read as a property of the project rather than of that machine. If
# reproducibility stops holding again, this script is still the thing that says so — and a
# WebAssembly module that stops being reproducible is worth knowing about, given what
# `docs/BUILD.md` claims about verifiable releases.
#
# # What it does not prove
#
# That the source is correct, or that the toolchain is honest. It proves one thing: what is
# shipped is what the repository says it is. Same scope as `verify-release.sh`, one layer down.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

echo "Rebuilding crypto-wasm into $scratch ..."
"$root/scripts/build-wasm.sh" "$scratch/pkg" >/dev/null

# The committed glue carries the `patch-wasm-glue.mjs` edit, so the fresh copy must carry it too
# before the two can be compared. Running the patch here also keeps it honest: it exits non-zero
# when a wasm-bindgen bump has moved the pattern it rewrites.
mkdir -p "$scratch/apply/src/lib/generated"
cp "$scratch/pkg/crypto_wasm.js" "$scratch/apply/src/lib/generated/crypto_wasm.js"
( cd "$scratch/apply" && node "$root/apps/web/scripts/patch-wasm-glue.mjs" )

status=0
compare() {
  if cmp -s "$1" "$2"; then
    echo "  ok        $3"
  else
    echo "  MISMATCH  $3"
    status=1
    diagnose "$1" "$2"
  fi
}

# A mismatch used to report only that one had happened, and the advice below could do no better
# than list three things that might have moved. On a CI runner, where nobody can open the two
# files, that is a dead end: the rebuilt copy lives in a scratch directory that is deleted when
# the job ends.
#
# So say what differs. Sizes first, because a few kilobytes apart and byte-identical-but-for-a-
# few-strings are different problems, then the strings each side has and the other does not —
# which is how the absolute build paths were found. Capped, because these are megabyte files and
# a log is not a diff viewer.
diagnose() {
  echo "            rebuilt   $(wc -c <"$1") bytes"
  echo "            committed $(wc -c <"$2") bytes"
  command -v strings >/dev/null || return 0
  diff <(strings -n 8 "$1" | sort -u) <(strings -n 8 "$2" | sort -u) \
    | grep -E '^[<>]' | head -20 | sed 's/^/            /' || true
}

echo "Comparing against the committed artefacts:"
compare "$scratch/pkg/crypto_wasm_bg.wasm" \
        "$root/apps/web/public/crypto_wasm_bg.wasm" \
        "apps/web/public/crypto_wasm_bg.wasm"
compare "$scratch/apply/src/lib/generated/crypto_wasm.js" \
        "$root/apps/web/src/lib/generated/crypto_wasm.js" \
        "apps/web/src/lib/generated/crypto_wasm.js"
compare "$scratch/pkg/crypto_wasm.d.ts" \
        "$root/apps/web/src/lib/generated/crypto_wasm.d.ts" \
        "apps/web/src/lib/generated/crypto_wasm.d.ts"

if [ "$status" -ne 0 ]; then
  cat >&2 <<'EOF'

The committed WebAssembly does not match crates/crypto-wasm.

If you changed the crate, regenerate and commit the artefacts in the same commit:

    cd apps/web && pnpm run wasm

If you did not change the crate, something else moved: the pinned toolchain in
rust-toolchain.toml, the wasm-bindgen version in Cargo.lock, or the artefacts themselves.
EOF
fi

exit "$status"
