# Building and running Whispee

This document collects every prerequisite and every command in one place: server, web,
desktop, tests, release, mobile. It is for someone who has just cloned the repository and
wants something running.

Whispee is a learning and demonstration project, with no external audit. See
[`../README.md`](../README.md) for what that means before you deploy anything.

## Prerequisites

Versions are the ones actually in use — the recorded ones come from `release/artefacts/BUILD-INFO`,
written by the last reproducible build.

| Tool | Version in use | Needed for |
|---|---|---|
| Rust | `rustc` 1.95.0, `cargo` 1.95.0 — edition 2024, resolver 3 | Everything Rust: crates, server, desktop |
| Node | 22 (22.21.0 recorded) | Web build, and the test harness (`node --test`) |
| pnpm | 11 (11.22.0 recorded) | `apps/web` only; enable it with `corepack enable` |
| wasm-pack | any recent release | Compiling `crypto-wasm`; it bundles the `wasm-opt` this project passes flags to |
| Docker + Compose | — | The development database |
| PostgreSQL | 17 (`postgres:17-alpine`), host port **55432** | Provided by `docker compose` |
| OpenSSL CLI | — | Signing and verifying a release |
| Tauri CLI 2 | `cargo install tauri-cli --version "^2" --locked` | **Mobile only.** Desktop builds do not use it |
| JDK | 21 (Temurin) | Android |
| Android SDK + NDK | NDK `27.2.12479018` | Android |
| Rust target | `aarch64-linux-android` | Android |
| Xcode + macOS | latest stable | iOS |
| Rust targets | `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios` | iOS |

Host port 55432 avoids colliding with a system Postgres (5432) or a local Supabase (54322).

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `DATABASE_URL` | none — the server refuses to start without it | Postgres connection string |
| `SERVER_ADDR` | `127.0.0.1:8787` | Listen address |
| `ALLOWED_ORIGINS` | `http://127.0.0.1:5173,http://localhost:5173,tauri://localhost,http://tauri.localhost` | CORS allow-list |
| `THROTTLE_PER_MINUTE` | `60` | Per-address limit on the four routes that cannot be authenticated |
| `CLAIM_QUOTA_PER_MINUTE` | `5` | Per caller-target pair limit on KeyPackage consumption |
| `VITE_API_URL` | `http://127.0.0.1:8787` | **Build-time**, web side. See below |

The two Tauri origins are in the default rather than only in the documentation: the operating
system imposes them — `tauri://localhost` on Linux and macOS, `http://tauri.localhost` on
Windows and Android — and forgetting them produces a "Failed to fetch" the browser emits
before sending anything, so the server never sees it.

`.env.example` holds the first two. The server reads them from its process environment and
does not load `.env` itself:

```sh
cp .env.example .env
set -a && . ./.env && set +a
```

## Server

```sh
docker compose up -d              # PostgreSQL 17, host port 55432
./scripts/dev-server.sh           # listens on 127.0.0.1:8787
```

`dev-server.sh` loads `.env` — falling back to `.env.example`, since a fresh worktree has no
`.env` at all — and points `DATABASE_URL` at a database named after the branch checked out:
`feat/audio-calls` gets `whispee_feat_audio_calls`, created on first run. `main` keeps the
default `whispee`, so a plain checkout is unaffected.

That split exists because migrations are per branch and the container is not. Two branches in
flight each add an `0018_`, the first one run leaves its version row behind, and sqlx then
refuses to start the other — `Migrate(VersionMissing(18))`, the database being ahead of the code
in a direction the code cannot undo. The only recovery was to drop the volume, which destroys
every other checkout's data along with the offending row.

`cargo run -p server` still works when `DATABASE_URL` is already exported; the script only
arranges the environment before it.

Migrations in `crates/server/migrations/` are applied by the process at startup, along with
creating the transparency log's signing key on first run and backfilling accounts that predate
the log.

**Editing an existing migration changes its sqlx checksum**, and a database that already ran
the old version will refuse the new one. There is no in-place fix; the database has to be
recreated:

```sh
docker exec whispee_pg dropdb -U whispee whispee_<branch>   # this branch only
docker compose down -v && docker compose up -d              # every branch
```

Prefer the first: with a database per branch, only the branch whose migration changed needs
recreating, and `dev-server.sh` recreates it on the next run. The second is the blunt version.
The `-v` matters there — without it the volume survives and so does the old checksum — but it
takes every other checkout's database with it, which is a thing to do knowingly rather than out
of habit.

This is not hypothetical maintenance advice: two migrations were renamed to
`0009_partitioning.sql` and `0010_replay_protection.sql`, so any database created before that
rename needs exactly this.

## Web client

```sh
cd apps/web
pnpm install
pnpm run wasm                     # see below — this is not just a compile
pnpm run build                    # tsc --noEmit, then vite build
pnpm run preview
pnpm run dev                      # dev server on port 5173
```

### What `pnpm run wasm` actually does

Four steps, and the last two are the reason it is a script rather than a documented
`wasm-pack` invocation:

1. `wasm-pack build --target web --release --out-dir pkg ../../crates/crypto-wasm`
2. copies `crypto_wasm_bg.wasm` into `apps/web/public/`
3. copies `crypto_wasm.js` and `crypto_wasm.d.ts` into `apps/web/src/lib/generated/`
4. runs `node scripts/patch-wasm-glue.mjs`, which replaces wasm-bindgen's default fallback
   `new URL('crypto_wasm_bg.wasm', import.meta.url)` with a thrown error

That fallback path is never taken — `loadCrypto()` always passes an explicit URL — but
bundlers analyse it statically and fail to resolve a file that lives in `public/` rather than
beside the module. The patch replaces it with a message instead of deleting it, so that
calling `init()` with no argument one day fails clearly. If wasm-bindgen changes its glue and
the pattern is no longer found, the script **exits non-zero and breaks the build**, which is
the point: a patch that has silently stopped applying is worse than no patch.

The compiled `.wasm` and the patched glue are **committed**. That is deliberate: the Android
APK contains the module as a versioned artefact under `apps/web/`, so changing
`crates/crypto-wasm` without regenerating does not change the APK.

The binary is about 1.5 MB raw, 512 KB gzipped. Serve it compressed and with a long cache: it
is a direct user cost on every first load.

### `VITE_API_URL` drives two things

It sets the API origin **and** the Content-Security-Policy, which is computed at build time by
`csp()` in `apps/web/vite.config.ts` rather than written into `index.html`. A hard-coded policy
and a configurable origin diverge on the first deployment, and the symptom is a "Failed to
fetch" the browser emits before sending anything — the server sees nothing and the message
does not name the cause.

`connect-src` carries **both** origins, `http(s)://` and `ws(s)://`: the second is not derived
from the first, and keeping only one cuts half the client without the other half reporting it.

Two settings in `vite.config.ts` must not be undone. `build.modulePreload.polyfill` is `false`
because Vite otherwise injects a small inline script — reintroducing exactly the inline script
whose absence lets the CSP say `script-src 'self'` instead of using a nonce, which is stricter,
not looser. And `chunkSizeWarningLimit` is raised because the WASM module would otherwise drown
the warnings that matter.

## Desktop

```sh
cd apps/web && pnpm run build     # produces dist/, which Tauri packages
cargo run -p desktop --release
```

With hot reload, for working on the interface:

```sh
cd apps/web && pnpm run dev       # serves on 5173, which devUrl expects
cargo run -p desktop --no-default-features
```

**The `custom-protocol` feature decides where the interface comes from, not the build
profile.** With it, the webview reads the files packaged in the binary; without it, it fetches
`devUrl` and shows "Connection refused" if nothing is listening on 5173. The `tauri build` CLI
normally adds the feature; this project does not use that CLI for desktop, so
`apps/desktop/Cargo.toml` declares it **on by default** — against `create-tauri-app`'s
convention, because the common case here is running the application, not editing its
interface.

**A path trap in `tauri.conf.json`**, which has cost one build: `frontendDist` is resolved from
the configuration file, so from `apps/desktop`, while `beforeBuildCommand` and
`beforeDevCommand` run from `apps/`. The two are not written with the same prefix. JSON takes
no comments, so it is recorded here. A plain `cargo build` never runs those commands, so the
mistake only shows through the Tauri CLI — that is, in CI.

## Tests

```sh
cargo test --release                        # mandatory in release; see below
cargo clippy --all-targets
wasm-pack test --node crates/crypto-wasm    # tests inside the WASM environment
cd apps/web && pnpm test                    # node --experimental-strip-types --test
cd apps/web && pnpm run typecheck           # tsc --noEmit
```

The server's integration tests need the database up (`docker compose up -d`) and
`DATABASE_URL` set.

### ⚠️ `cargo test --release` is mandatory

OpenMLS 0.8.1 runs a `debug_assert!(false)` before returning the decryption error
(`framing/private_message_in.rs:136`). In a **debug** build, a message altered in transit
therefore panics the process instead of being cleanly rejected: a remotely triggerable
denial of service, reachable by flipping one byte.

In release, `debug_assert!` disappears and the error propagates normally. The test
`ciphertext_altere_rejete` is skipped in debug and only means anything in release.

**Never deploy a debug build of this code.**

### What CI runs, and what it still does not

`test.yml` runs the Rust suite against a real Postgres, clippy, the client's types and tests,
and `scripts/verify-wasm.sh` — which rebuilds `crates/crypto-wasm` and compares it byte for
byte to the artefacts committed under `apps/web/`. It triggers on pull requests and on pushes
to `main`, not on every push to `dev`: the spend lands on the moment a change is proposed.

What it still does not do is **build for mobile**. `android.yml` and `ios.yml` remain manual or
`main`-only, because a macOS runner costs roughly ten times the minutes of a Linux one. So a
pull request tells you the code is correct; it does not tell you the APK links.

## Release

```sh
scripts/release.sh /path/to/private-key.pem   # builds, hashes, signs
scripts/verify-release.sh                     # verifies, with no private key
```

`release.sh` refuses to run on a dirty working tree — a release whose content matches no commit
is not verifiable, since nobody would know what to rebuild. It then:

- exports `SOURCE_DATE_EPOCH` from the commit date, not the current time, so everyone
  rebuilding that commit gets the same value;
- sets three `--remap-path-prefix` flags — repository, Cargo registry, and `rustc` sysroot —
  computed from `git rev-parse` and `CARGO_HOME` rather than frozen into a versioned config
  file, because hard-coding them would reproduce the defect they fix by only being right on one
  machine. Without them the binary contained 217 absolute paths; without the sysroot one, 26
  remained, which is few enough to pass review and enough to give two people different hashes;
- builds `apps/web` and then `cargo build -p desktop --release`;
- writes `BUILD-INFO` with the commit and the exact `rustc`, `cargo`, `node` and `pnpm`
  versions;
- writes `SHA256SUMS` and signs **that file**, not the binary — one signature then covers the
  whole release, `BUILD-INFO` included.

**Reproducible first, signed second.** A signature says "somebody holding this key produced
this file"; it does not say "this file corresponds to this code". The order matters for a
project whose whole thesis is that a user should not have to take the operator's word.

Ed25519 through `openssl`, rather than GPG or minisign: this project already verifies Ed25519
signatures everywhere — attestations, revocations, rotations, log heads. One primitive for one
question.

### How a third party verifies

```sh
scripts/verify-release.sh [directory] [public-key]
# defaults: release/artefacts and release/whispee.pub
```

It needs only `openssl`, the published files and [`../release/whispee.pub`](../release/whispee.pub);
it must run on a machine that has nothing else of this project. It checks the signature
**first** and the hashes second — the reverse would validate a hash file anyone could have
rewritten alongside the binary. It then prints the declared build environment.

What it establishes: the release was signed by the holder of the matching private key, and the
files have not changed since. Nothing more. To establish that the binary matches the code,
rebuild it from the commit named in `BUILD-INFO`, with the same tool versions, and compare the
hashes.

To generate a signing key — it never enters the repository:

```sh
openssl genpkey -algorithm ed25519 -out private-key.pem
openssl pkey -in private-key.pem -pubout -out release/whispee.pub
```

Reproducibility holds **for a given environment**. A different `rustc` or `pnpm` produces a
different binary with nothing compromised, which is why `BUILD-INFO` is published beside the
hashes. It has been verified between two successive builds on the same machine;
reproducibility across different machines has not been measured.

## Mobile

**These builds have only ever run in CI. None of them has been run locally**, for lack of an
Android NDK and a macOS machine on the development host. The commands below are the ones the
workflows execute; treat them as documented, not as tested outside GitHub Actions.

```sh
cd apps/desktop
cargo tauri android init                              # regenerates gen/android
cargo tauri android build --debug --apk --target aarch64
cargo tauri ios init                                  # regenerates gen/apple, macOS only
cargo tauri ios build --debug --target aarch64-sim
```

`VITE_API_URL` must be set for both: it is frozen into the bundle **and** into the CSP.
Missing, it produces a client pointing at the phone's own loopback — that is, at nothing.

The native projects under `apps/desktop/gen/` are **regenerated on every build rather than
versioned**: a generated project that drifts from its source is a source of silent errors.
One consequence: the Android camera permission, needed by `getUserMedia` for pairing-QR
scanning, is patched into the manifest by a workflow step, since any manual edit would be
erased by the next `android init`.

### What runs, and when

| Trigger | What runs | Cost |
|---|---|---|
| Push to `dev` | nothing | — |
| Push to `main` | Android build, if `apps/` or `Cargo.lock` changed | Ubuntu runner |
| Manual dispatch | Android or iOS, your choice | depends on the target |

Manual dispatch is the normal way to get a mobile binary. **iOS never runs automatically**: a
macOS runner minute is billed ten times a Linux one, which makes it the decisive expense.
Concurrent builds cancel each other (`cancel-in-progress`): a push that follows another makes
the earlier one moot, and letting it finish would pay a runner for an artefact nobody takes.

Android builds a **single architecture**, `aarch64`, and that is an economy measure: Tauri
compiles native Rust per architecture, so the four default targets quadruple the compilation
of the whole dependency tree — enough to approach a runner's timeout once the cache was
invalidated. iOS builds unsigned, for the simulator, so it produces nothing installable on a
real device; that needs an Apple developer account, a provisioning profile and a certificate.

## See also

- [`./ARCHITECTURE.md`](./ARCHITECTURE.md) — what the crates are and how a message travels
- [`./ROADMAP.md`](./ROADMAP.md) — what is finished, what is half-finished, what will not be done
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — how to propose a change
- [`../SECURITY.md`](../SECURITY.md) — how to report a vulnerability
