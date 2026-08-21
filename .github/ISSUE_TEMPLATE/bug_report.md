---
name: Bug report
about: Something behaves differently from what the documentation says it does
title: ''
labels: bug
assignees: ''
---

<!--
Do NOT use this template for a security vulnerability. Report those privately:
https://github.com/Sycatle/whispee/security/advisories/new — see SECURITY.md.

Before filing: several surprising behaviours here are deliberate and written down.
Check the known-limitations table in docs/THREAT-MODEL.md first. If the behaviour is
listed there, an issue arguing the trade-off is welcome — say so explicitly.
-->

## What happened

## What you expected, and where that expectation comes from

<!-- Quote the README, a doc page, or a code comment if one says otherwise. -->

## Steps to reproduce

1.
2.
3.

## Build profile

<!--
Required. `cargo test` and `cargo run` in DEBUG are unsupported: OpenMLS 0.8.1 runs a
`debug_assert!(false)` before returning its decryption error, so an altered message
panics instead of being rejected. If you were in debug, reproduce in release before
filing — many reports resolve here.
-->

- [ ] release (`--release`)
- [ ] debug — reproduced in release too? yes / no

## Component

<!-- crypto-core, crypto-wasm, attest, transparency, server, apps/web, apps/desktop, scripts -->

## Environment

- Commit:
- OS:
- `rustc --version`:
- Node / pnpm (if client-side):
- Browser or target (web / desktop / Android / iOS):

## Logs, backtraces, screenshots

<!-- Redact anything derived from a real recovery phrase or account key. -->
