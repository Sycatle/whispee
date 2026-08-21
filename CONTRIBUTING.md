# Contributing to Whispee

This document is for anyone sending a patch. It is short on etiquette and long on
invariants, because the etiquette is obvious and the invariants are not: two of them will
silently destroy a security property if you break them, and nothing in the build will tell
you.

Start with [README.md](README.md) for what Whispee is, and [docs/BUILD.md](docs/BUILD.md)
for getting every target to compile.

## Branches, and why nothing builds automatically

`dev` is the working branch. `main` is integration. Branch from `dev`, open the pull request
against `dev`, and let integration into `main` happen separately.

**Nothing is built on `dev`.** Triggering a build on every push there would spend most of the
GitHub Actions quota on intermediate states nobody installs. Work is validated locally, with
`cargo test --release`.

| Trigger | What runs | Cost |
|---|---|---|
| Push to `dev` | nothing | — |
| Push to `main` | Android build, if `apps/` or `Cargo.lock` changed | Ubuntu runner |
| Manual dispatch | Android or iOS, your choice | depends on the target |

Manual dispatch is the normal way to get a mobile binary. **iOS never runs automatically**: a
macOS runner costs roughly ten times the minutes of a Linux one, which makes it the deciding
line item. Concurrent builds cancel each other (`concurrency` with `cancel-in-progress`) — a
push that follows another makes the earlier one moot, and letting it finish would pay a runner
for an artefact nobody will take.

The tests themselves are a separate matter, and they do run: `test.yml` triggers on every pull
request against `dev` or `main`. What stays off `dev` is the **builds** — that is what the quota
argument is about, and it does not carry over to a job that answers whether the change is
correct. Run `cargo test --release` locally anyway; waiting on a runner to learn something a
laptop answers in a minute is its own waste.

## Two things that get a pull request rejected on sight

### 1. `crypto-core` must never depend on `ratchet-lab`

`crates/ratchet-lab` is a teaching reimplementation of X3DH and the Double Ratchet. It exists
to understand the protocol by writing it. It is not reviewed as production code and never will
be.

The absence of a `ratchet-lab` dependency in `crates/crypto-core/Cargo.toml` is the guarantee
that no hand-rolled cryptography drifts onto the path a real user executes. It is an
invariant, not a preference. A patch that adds that edge — directly, transitively, behind a
feature flag, or "just for a test" — is rejected without further discussion. If you need
something from `ratchet-lab` in production code, the answer is to write it properly in
`crypto-core`, not to reach across.

The same holds for any crate a user runs: `crypto-wasm`, `server`, `apps/desktop`.

### 2. `cargo test --release`, always — never a debug build

OpenMLS 0.8.1 executes a `debug_assert!(false)` before returning its decryption error
(`framing/private_message_in.rs:136`). In a **debug** build, a message altered in transit
therefore panics the process instead of being rejected cleanly. That is a denial of service
any remote party can trigger by flipping one byte.

In release, `debug_assert!` disappears and the error propagates normally. The test
`ciphertext_altere_rejete` is skipped in debug for exactly this reason and only means anything
in release — so a green `cargo test` in debug is not evidence of anything.

**Never deploy, and never benchmark against, a debug build of this code.**

## Running the tests

```sh
cargo test --release                        # the whole workspace; release is mandatory, see above
cargo clippy --all-targets
wasm-pack test --node crates/crypto-wasm    # the WASM environment has its own failure modes
```

The server tests need the development database:

```sh
docker compose up -d
cargo test -p server --release
```

If you edit an existing SQL migration you change its sqlx checksum, and a database that
already ran the old one will refuse to start. Recreate it:

```sh
docker compose down -v && docker compose up -d
```

Client-side:

```sh
cd apps/web
pnpm run typecheck
pnpm test
```

Note what this harness cannot reach: `node --test` has no DOM, so neither IndexedDB nor the
Tauri IPC is covered. Anything touching native storage or migration is verified by hand, and a
patch there should say in its description how it was exercised.

## Commits

[Conventional Commits](https://www.conventionalcommits.org). The history already follows it,
so match what is there:

```
feat(web): pair by scanning a square instead of retyping 64 characters
fix(desktop): declare the biometric plugin for every target
docs: record what each lot actually left behind
```

Scopes in use: `web`, `desktop`, `server`, `crypto-core`, `crypto-wasm`, `attest`,
`transparency`, `ratchet-lab`. Types in use: `feat`, `fix`, `refactor`, `test`, `docs`,
`chore`.

Write the subject as what the change does for someone using or reading the code, not as a
restatement of the diff. One logical change per commit.

## Comments argue the *why*

This is the house style and the reason the codebase can be read at all. A comment that
restates the code is noise and gets removed. A comment that explains **why this decision and
not the obvious alternative** is the point.

The pattern used throughout is: **decision → why → what it does not solve.** The third part is
not optional. Almost every security mechanism here buys one property and leaves a neighbouring
one open, and a comment that names only the win teaches the next reader something false.

```rust
// The nonce is indispensable and cannot be replaced by the signature itself: Ed25519 is
// deterministic, so two identical requests in the same second carry the same signature —
// one may be a replay while the other is legitimate. Claiming two KeyPackages back to back
// is enough to produce the case.
```

The same applies to pull request descriptions, and to the documentation. If your change
weakens a property, **say so in the text and add it to the limitations table** in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). A limitation that is written down is a known
cost; one that is left out is a lie with a delay on it.

## Pull requests

Explain the decision, not the diff — the diff is right there. Say what you ran, since CI will
not run it for you. If the change touches a security property, say which one, in which
direction, and what it does not solve.

Security bugs do not go here: see [SECURITY.md](SECURITY.md) for private reporting.
Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Finally: no licence has been chosen for this repository yet, so there is nothing for you to
agree to and nothing granting rights to redistribute. That is stated in the README and it is
worth knowing before you spend time here.
