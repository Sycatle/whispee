# Recovery escrow: a way back that is not a piece of paper

**Status.** Built.

**Date.** 2026-08-22.

## The defect

There is one way back into an account with no device left, and it is the twelve words.

`Onboarding.tsx` offers three doors and only the third answers "everything is gone": `pair` needs
a device you still have, `create` makes a different account, and `restore` needs the phrase. The
phrase is generated once (`crypto-core/src/account.rs:70` — *"This is the only moment the phrase
exists"*), shown once, and never recoverable from anywhere.

That is a good security property and a bad product. The phrase ends up in a drawer, in a password
manager the user also loses, in a photograph, or nowhere — and "nowhere" is the common case. An
account whose only backup is a piece of paper somebody has to still own in ten years is an account
most people will eventually lose, and pretending otherwise is how the loss gets blamed on them.

**What is wanted is a secret you can choose and remember**, or one your platform holds for you.
What that means technically is not negotiable and has to be said before anything else.

## The decision, and what it costs

**The server holds the account seed, encrypted under a key derived from a secret the user
carries.** Two kinds of secret, each standalone, each sealing the seed independently:

| Factor | Key material | What it costs |
|---|---|---|
| `password` | Argon2id(password), 256 MiB, t=4 | **Offline-attackable by whoever holds the database** |
| `passkey` | 32 bytes from WebAuthn PRF | Nothing to guess; the authenticator can be lost |

The password factor is the one that needs arguing, so it gets argued.

In an end-to-end encrypted system a "password login" cannot be a server-side check. There is
nothing for the server to hand back that it is allowed to hold in the clear. The only construction
that works is escrow: seal the root secret client-side, store the ciphertext, unseal it client-side
on recovery. Which means **the ciphertext exists**, and whoever obtains it — the operator, a SQL
dump, an old backup tape — can grind the password offline with no rate limit and no clock.

Argon2id at 256 MiB makes each attempt expensive. It does not make a guessable password safe.

**Measured**: 1.1 s per evaluation in the shipped WebAssembly build, on a desktop. That number is
what the password floor was chosen from rather than the reverse — a hundred cores make ninety
guesses a second, so `ESCROW_POLICY`'s 10^14 is about thirty thousand years of that machine, and
a six-word drawn passphrase (66 bits) is out of reach entirely. A floor picked without measuring
would be a number with no argument under it.

And the blast radius is larger than the account. `vault_key = HKDF(seed, "wac-vault-v1")`
(`account.rs:196`), so winning that attack also opens every row of `vault_entries` —
retroactively, and the vault is on by default. `docs/THREAT-MODEL.md` already states that price
for the phrase; this extends it from *"if the phrase leaks"* to *"if the password is guessed"*.

**Hence: opt-in, off by default, with the trade stated above the field rather than beneath it.**

There is no construction that removes this. OPAQUE moves what the server learns during the
exchange and leaves the envelope offline-attackable by the same holder. What genuinely closes it
is a hardware enclave rate-limiting guesses — Signal's SVR — which is a deployment requirement
this project cannot impose on a self-hoster.

The passkey factor is not a lesser version of the same thing; it is the one that has no such cost.
Its key is uniform, so a stolen database yields nothing about it, ever. It is offered *first* on
the recovery screen for that reason, and it does not carry the password's red banner, because
repeating a warning where it does not apply teaches the reader to skip it where it does.

## The constraint that shapes everything: finding the blob

A device recovering an account holds nothing — no device key, no seed, no signature to offer. The
route serving the ciphertext is therefore **unauthenticated**, and it is the fifth such route in a
server that had four and justified each one in a comment.

Indexing escrows by handle would publish everyone's ciphertext to everyone, and take the offline
attack from *"the operator"* to *"anybody with a script"*. That is not an acceptable trade for
convenience.

**Resolution: the row is named by a value only its owner can compute.** One expensive derivation
yields two independent keys:

```
password:  salt   = SHA-256("wac-escrow-salt-v1" ‖ handle)
           okm    = Argon2id(password, salt, m=256 MiB, t=4, p=1) → 64 bytes
           lookup = HKDF(okm, info="wac-escrow-lookup-v1")
           seal   = HKDF(okm, info="wac-escrow-seal-v1")

passkey:   prf    = WebAuthn PRF(salt = "wac-escrow-prf-v1")   → 32 bytes
           lookup = HKDF(prf, info="wac-escrow-lookup-v1")
           seal   = HKDF(prf, info="wac-escrow-seal-v1")
```

The server stores `SHA-256(lookup)` and serves a row only on an exact match. The pre-image never
leaves the client. Asking for a blob already requires knowing the password.

Two properties fall out, and are worth writing down rather than discovering:

- **No enumeration oracle.** A wrong password and an account with no escrow are the same 404. The
  server is not being discreet; it holds a hash and compares it, and genuinely cannot tell them
  apart.
- **No attempt counter is possible.** A failed lookup names no account, so there is nothing to
  lock after N tries. The bound is per-address (`throttle::Recovery`, three a minute) and only
  that. This is weaker than a per-account counter and it is the price of not being enumerable.

### Why the salt is not random

It cannot be. Reading the stored parameters requires the lookup key; computing the lookup key
requires the salt. A random salt held server-side is a circular dependency.

So the salt is derived from the handle: unique per account — no single rainbow table covers two
users — but precomputable against one *named* target. What that target rests on is Argon2id's
memory cost, which is the honest statement rather than the comfortable one.

The cost parameters are constants in the client for the same reason. `Params` records what was
used at sealing time so a later build can recognise an older escrow; it is inside the seal's AAD
and checked against a floor, so a server that rewrites it produces a decryption failure rather
than a cheaper derivation.

### What the seal binds

`AAD = account_id ‖ 0x00 ‖ kind ‖ params`.

The account id stops a hostile server serving one account's ciphertext under another's lookup —
which is also why `Session.restoreFromEscrow` verifies nothing: getting that far already proves
the id and the seed were sealed together. The kind stops a passkey escrow being presented as a
password one. The parameters stop a silent downgrade.

## Three consequences that only appear when you write it down

**A rename kills the password escrow.** The handle is the salt, so after a rename the owner's
password produces a different lookup and a different key: the row stops answering and never opens
again. Leaving it is the worst of both — a ciphertext of the seed, useless to its owner and still
grindable by whoever takes the database. `Session.renameHandle` therefore deletes it. Re-sealing
is impossible there: it needs the password, which the session has never held and must not start
holding to make a rename tidier. The passkey factor is untouched; nothing in it knows the handle.

**A rotation must destroy the escrow, in the same transaction.** Rotation is the answer to a
stolen device, and a stolen device holds the seed. An escrow left behind is the abandoned key
still sitting on the server, openable by a password the thief may have watched being typed.
`rotate_account` deletes it beside the KeyPackage cleanup.

**Replacing a password is a delete-then-insert, not an upsert.** The lookup moves with the secret,
so an upsert keyed on `lookup` leaves the previous row alive — a password its owner believes they
have changed, still opening the account. `UNIQUE (account, kind)` plus an explicit delete is what
makes replacement mean replacement. The surviving `ON CONFLICT (lookup) DO NOTHING` covers a
lookup belonging to *another* account, which is answered with a 409 rather than an overwrite.

## Inventory

| Where | What it is |
|---|---|
| `crypto-core/src/escrow.rs` | Derivation, sealing, `Params`, `generate_passphrase` |
| `crypto-wasm/src/lib.rs` | `RecoveryFactor` handle; the sealing key never reaches JavaScript |
| `server/migrations/0018_recovery_escrow.sql` | One table, keyed by the lookup hash |
| `server/src/routes.rs` | `set` / `list` / `forget` signed; `claim` open; rotation deletes |
| `server/src/throttle.rs` | `Recovery`, three a minute, the narrowest quota in the server |
| `web/lib/escrow.ts`, `lib/passkey.ts` | The two factors, and the WebAuthn PRF ceremony |
| `web/lib/session.ts` | `restoreFromEscrow`, the three settings methods, the rename cleanup |
| `web/components/Recover.tsx` | The fourth door on the first screen |
| `web/components/Recovery.tsx` | The settings panel that makes the trade refusable |
| `web/lib/password.ts` | `ESCROW_POLICY` — 16 characters, 10^14 guesses |

## What this does not solve

- **The offline attack.** It is the mechanism, not a gap in it. Without an enclave, nothing
  closes it.
- **The account is worth its weakest enabled factor.** Setting both does not add strength: a weak
  password annuls the passkey's full entropy. The screen says so.
- **Passkeys are origin-bound and web-only.** PRF needs a stable RP ID; a self-hosted deployment
  on another domain does not inherit them, and the Tauri webviews do not reliably provide the
  extension. The password and the phrase cover those cases.
- **Recovery still does not restore MLS membership.** Same limit as `restoreFromPhrase`, and the
  same one `THREAT-MODEL.md` calls orphan history. What comes back is the account and the vault.
- **Nothing locks after N attempts**, by construction — see above.
- **A password strong enough to survive an offline attack is not much easier to remember than the
  twelve words it replaces.** That is why the screen offers to draw six words rather than
  pretending an invented password will do. The real gain is that it is *chosen*, so it gets
  remembered, where a phrase handed to somebody gets filed and lost.

## Verification

Properties a test holds without a network (`crypto-core`, 14 unit tests):

- `open(seal(seed))` returns the seed; a different secret, a different account id, a swapped
  kind or altered parameters each fail.
- Two handles with the same password produce unrelated lookups.
- The lookup value is not the sealing key.
- Parameters below the floor are refused **before** Argon2 runs.
- The word list is 2048 long, so the modulo in `generate_passphrase` is unbiased.

Properties that need the server (`server/tests/recovery.rs`, 10 integration tests):

- A wrong secret and an absent escrow return the identical status.
- Replacing a factor leaves no second one behind.
- A stranger's device cannot forget this account's escrow.
- **After a rotation, the escrow is gone.**
- The recovery quota bites at the third attempt.
