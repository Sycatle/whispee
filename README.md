# Whispee

Whispee is an end-to-end encrypted messenger — web, desktop and mobile from one Rust
crypto core, one Axum server, one React client. What makes it unusual is not the feature
list: it is built on **MLS (RFC 9420)** rather than the Signal protocol, and every design
decision in it is argued in writing, including the ones that turned out badly.

## ⚠️ Status: a learning and demonstration project

**This project is not meant to protect real users, and certainly not users at risk.** It has
received no external audit and will not receive one. An E2EE protocol that is correct on
paper fails in practice on details only an audit surfaces. For communications that actually
matter: **use Signal.**

## Inspired by

WhatsApp, Signal and Telegram. Whispee reimplements the ideas those applications made
ordinary — end-to-end encryption, multi-device accounts, groups, metadata that does not leak
more than it must — on top of MLS instead of the Signal protocol. The comparisons made
throughout the documentation are threat-model comparisons, not claims of parity. Whispee is
not their equal and does not try to be.

## What works today

| Area | State |
|---|---|
| 1-to-1 and group messaging | MLS over OpenMLS 0.8.1; a 1-to-1 is a group of two |
| Multi-device accounts | Every device is a group member, attested by the account key |
| Groups, roles, removal | One admin, moderators; roles carried in a group-context extension |
| Device revocation, account rotation | Signed certificates the other members verify themselves |
| Key transparency | RFC 6962 append-only Merkle log, with client-side gossip |
| Metadata defences | Length padding in doubling steps, sealed sender via a group post MAC |
| Signalling | Delivery and read receipts, typing, presence, reactions — each disableable |
| Attachments | Per-file AES-256-GCM key, carried inside the MLS message |
| Local lock | Argon2id (64 MiB, 3 passes), unlock key → master key indirection |
| History vault | On by default, encrypted under a key derived from the recovery phrase |
| Web, desktop | Vite 7 + React 19; Tauri 2 wraps the same build |
| Reproducible, signed releases | `scripts/release.sh`, `scripts/verify-release.sh` |

## What does not work

- **Push notifications are half-built.** The server records tokens and decides who to wake,
  and then sends nothing. There is no FCM or APNs provider, no configuration, no device-side
  token registration and no user-facing setting. It is inert without configuration, and a
  self-hosted deployment that talks to neither Apple nor Google stays fully functional.
- **Biometric unlock has never been executed.** The code exists; not one line of it has run.
  There is no Android NDK and no physical device on the development machine, so even the
  compilation of its dependency is unconfirmed.
- **The mobile builds are the only thing still validated by hand.** `test.yml` now runs the
  Rust and client suites, clippy, and the check that the committed WebAssembly matches
  `crates/crypto-wasm`. `android.yml` and `ios.yml` stay manual or `main`-only to save Actions
  quota, so no mobile artefact is produced on a pull request.
- Mobile builds, backups, account deletion, post-quantum protection: see
  [docs/ROADMAP.md](docs/ROADMAP.md) and the known-limitations table in
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Quickstart

Requires Rust 1.95 or later (edition 2024), Node 22, pnpm 11, `wasm-pack`, and Docker.

```sh
# 1. Database — PostgreSQL 17 on host port 55432, chosen to avoid a system
#    Postgres (5432) or a local Supabase (54322).
docker compose up -d

# 2. Configuration. The committed defaults point at that container.
cp .env.example .env

# 3. Server — listens on 127.0.0.1:8787.
cargo run -p server

# 4. Client, in a second terminal.
cd apps/web
pnpm install
pnpm run wasm        # builds crypto-core to WASM and copies it into public/
pnpm run dev         # http://localhost:5173
```

Tests are run in release, always:

```sh
cargo test --release
```

OpenMLS 0.8.1 runs a `debug_assert!(false)` before returning its decryption error. In a debug
build, one altered byte in transit panics the process instead of being rejected — a remotely
triggerable denial of service. Never ship a debug build. The reasoning is in
[CONTRIBUTING.md](CONTRIBUTING.md).

For the desktop application, the Tauri path traps, the mobile targets, release signing and
everything else: [docs/BUILD.md](docs/BUILD.md).

## Documentation

Every design decision is written down, with what it costs and what it does not solve.

| Document | What it holds |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The crates, the apps, the server, and why the crypto core is single |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Wire-level detail: attestations, signature domains, sealed sender, the transparency log |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | What the adversary is assumed to do, and the full known-limitations table |
| [docs/SECURITY-PROPERTIES.md](docs/SECURITY-PROPERTIES.md) | The properties claimed, the ones deliberately not claimed, and the tests that pin them |
| [docs/BUILD.md](docs/BUILD.md) | Building every target, reproducible releases, verification |
| [docs/ROADMAP.md](docs/ROADMAP.md) | What is planned, what is half-done, and what has been ruled out |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Branches, the invariants a patch must not break, tests, commit style |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability, and the honest limits of the response |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |

## Licence

**No licence has been chosen yet.** `Cargo.toml` still declares `license = "UNLICENSED"` and
`publish = false`.

Until a licence is chosen, this repository is **not legally open source**. Publishing source
code grants no rights: with no licence, default copyright applies, and nobody has permission
to use, copy, modify or redistribute it. You may read it. Anything else is not permitted yet.

This will be resolved. Until it is, the honest statement is the one above rather than a badge
implying otherwise.
