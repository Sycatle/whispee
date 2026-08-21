<!--
Explain the decision, not the diff — the diff is right there. There is no CI that runs
the tests on this repository, so what you ran locally is the only evidence there is.
-->

## What this changes, and why this rather than the obvious alternative

## What it does not solve

<!--
Required, and not a formality. Almost every mechanism here buys one property and leaves
a neighbouring one open. Naming only the win teaches the next reader something false.
-->

## Security impact

- [ ] No security or privacy property is affected.
- [ ] A property is affected. Which one, in which direction, and what compensates:

<!--
If a property is weakened, it must also be added to the limitations table in
docs/THREAT-MODEL.md. A limitation that is written down is a known cost; one left out is
a lie with a delay on it.
-->

## Invariants

- [ ] `crypto-core` does not depend on `ratchet-lab`, directly, transitively, behind a
      feature flag, or in a test. Nor does any other crate a user executes.
- [ ] No behaviour was added that only works in a debug build.

## What was run

- [ ] `cargo test --release` <!-- release is mandatory: OpenMLS 0.8.1 debug_assert!s make a debug run unsound, and a debug build is a remotely triggerable DoS -->
- [ ] `cargo clippy --all-targets`
- [ ] `wasm-pack test --node crates/crypto-wasm` (if crypto or WASM changed)
- [ ] `cargo test -p server --release` with `docker compose up -d` (if the server changed)
- [ ] `pnpm run typecheck` and `pnpm test` in `apps/web` (if the client changed)
- [ ] Verified by hand: <!-- required for anything touching IndexedDB, native storage, migration or the Tauri IPC — the node --test harness has no DOM and cannot reach them -->

## Migrations

- [ ] No SQL migration was added or edited.
- [ ] A migration was added or edited. Editing one changes its sqlx checksum, so an
      existing database must be recreated with `docker compose down -v && docker compose up -d`.
      Reviewers need to know.

## Checklist

- [ ] Targets `dev`, not `main`.
- [ ] Conventional Commits, one logical change per commit.
- [ ] Comments argue the *why*, in the pattern decision → why → what it does not solve.
- [ ] Documentation updated if a decision or a limitation changed.
