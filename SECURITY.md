# Security policy

This document says how to report a vulnerability in Whispee, and what the project can
honestly promise in return. It is for anyone who finds a flaw in the code, and for anyone
deciding whether to trust Whispee with something real.

## Read this first

**Whispee has never been audited.** Not by a firm, not by an independent cryptographer, not
by anyone. It is a learning and demonstration project. An E2EE protocol that is correct on
paper fails in practice on details that only an audit surfaces, and none of those details
have been checked here.

**If you need real security, use [Signal](https://signal.org).** That is not modesty; it is
the accurate recommendation. Signal is audited, deployed at scale, and maintained by people
whose full-time job it is. Whispee is none of those things.

## Scope

In scope — a report about any of these is welcome:

| Component | What it is |
|---|---|
| `crates/crypto-core` | The only production crypto path (OpenMLS 0.8.1) |
| `crates/crypto-wasm` | The wasm-bindgen bindings the web and desktop clients call |
| `crates/attest` | Canonical device-attestation format and signature domains |
| `crates/transparency` | The RFC 6962 append-only key log |
| `crates/server` | The Axum + PostgreSQL delivery service, its authentication and its rate limits |
| `apps/web` | The React client, its CSP, its storage and its local lock |
| `apps/desktop` | The Tauri 2 application (desktop, Android, iOS) |
| `scripts/release.sh`, `scripts/verify-release.sh` | Reproducible build and release verification |

**Out of scope: `crates/ratchet-lab`.** It is a teaching reimplementation of X3DH and the
Double Ratchet, written to understand the protocol by writing it. It is **never** imported by
`crypto-core` or by any code a user executes, and it is explicitly not for production. Bugs
in it are interesting but they are not vulnerabilities, because nothing depends on it. A
report that `crypto-core` has started depending on it, however, is very much in scope — that
is a broken invariant, not a bug.

Also out of scope, because they are documented rather than accidental: everything already
listed in the known-limitations table of [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). A
compromised endpoint reads decrypted messages. The server knows who is in which group. The
web client's JavaScript is served by the server on every load. These are stated positions,
not oversights. If you think one of them is stated wrongly, that is worth reporting.

## Reporting

**Use GitHub's private vulnerability reporting for this repository:**

<https://github.com/Sycatle/whispee/security/advisories/new>

or the *Report a vulnerability* button under the repository's **Security** tab.

There is deliberately no security contact address here. The project has none, and inventing
one would produce a channel nobody reads. Private advisories go to the maintainer and stay
private until an advisory is published.

Please do not open a public issue for a security bug. Everything else — build problems,
questions, design disagreements — belongs in a normal issue.

A useful report contains: what the flaw is, which component, how to reach it, and what an
attacker gains. A proof of concept helps and is not required. If your report depends on a
threat-model assumption, say which one; several apparent flaws here are consequences of
choices that are written down.

## What to expect

- **Best effort, and nothing more.** Whispee has a single maintainer working on it in spare
  time. There is no on-call rotation, no response-time commitment and no service level.
- **No bounty.** There is no money. There is no budget for one.
- **Acknowledgement when the report is read**, which may take days or weeks.
- **Credit in the advisory** if you want it, and none if you would rather not.
- **A fix, or a written refusal.** If something will not be fixed — because it is inherent to
  the design, or because fixing it costs more than the project has — that gets said plainly
  and added to the limitations table rather than left silent.
- **No embargo demands.** You disclosed privately as a courtesy; you keep the right to
  disclose publicly. Telling us when you intend to is appreciated.

## Supported versions

There are no releases and no version branches. `main` is the only thing that gets fixed.
Anything built from an older commit is unsupported.

## Two things the code will not compromise on

They are the ones most likely to look like a bug to a newcomer, so they are stated here as
well as in [CONTRIBUTING.md](CONTRIBUTING.md):

1. **`crypto-core` must never depend on `ratchet-lab`.** That dependency edge is the
   guarantee that no hand-rolled cryptography drifts onto the real execution path.
2. **Never build, test or ship this in debug.** OpenMLS 0.8.1 executes a `debug_assert!(false)`
   before returning its decryption error. In debug, altering a single byte in transit panics
   the process instead of being rejected: a remotely triggerable denial of service.
