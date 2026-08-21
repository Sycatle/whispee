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
# It was measured before being asserted: with the toolchain pinned by `rust-toolchain.toml` and
# the wasm-bindgen version pinned by `Cargo.lock`, `wasm-pack build --release` reproduces all
# three files bit for bit. If that ever stops holding, this script is the thing that says so —
# and a WebAssembly module that stops being reproducible is itself worth knowing about, given
# what `docs/BUILD.md` claims about verifiable releases.
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
wasm-pack build --target web --release --out-dir "$scratch/pkg" "$root/crates/crypto-wasm" >/dev/null

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
  fi
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
