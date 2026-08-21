# Account identity: an anchor that is not a name

**Status.** Built. See the section at the end for what changed on the way.

**Date.** 2026-08-21.

## The defect

A handle is the identity. Not a label on one — the identity itself, in four places:

- `crates/crypto-core/src/identity.rs:63` — `BasicCredential::new(name.as_bytes())`. The MLS
  credential *is* the handle, in the clear, in every group.
- `crates/crypto-core/src/roles.rs:57` — `admin: String`, compared against a handle. Group
  authority is a string match.
- `crates/server/src/routes.rs:421` — device ids are `handle:name`, split on the first colon.
- `crates/attest/src/lib.rs` — `DeviceClaim`, `RevocationClaim` and `RotationClaim` all sign over
  the handle. Every attestation an account makes is bound to the name it had at the time.

So renaming is not an `UPDATE`. It is a new credential in every conversation, and MLS does exactly
what it is built to do: it reports an identity change. The fingerprint-changed banner rises
everywhere, for a cosmetic edit. `apps/web/src/lib/handle.ts` says as much, and is right.

That is the whole reason handles cannot be renamed today, and it is why sign-up now asks for a
name and *derives* `@bob4821` from it — a workaround that makes the first question answerable
without making the handle any less permanent.

## The decision

**An account is identified by the fingerprint of its genesis identity key.**

Not a server-assigned number. The distinction is the entire security argument: a server that
*mints* ids can forge one, reassign one, or serve two people two different answers. A server that
merely *lists* ids can do none of those, because the id is checkable against key material the
verifier already holds.

The material exists. `crates/crypto-core/src/account.rs:105` derives an Ed25519 identity key from
the recovery seed; `:121` fingerprints it as `sha256(identity_key)[..16]`, 128 bits, grouped in
blocks of four hex characters. It already spans every device of the account, it is already what
device attestations are signed with, and it is already the value users are asked to compare out of
band. It is the anchor; it was simply never used as the name.

The credential carries this id. `roles.rs` compares ids. Device ids become `id:name`. Attestation
claims bind the id instead of the handle.

**The handle becomes an alias**: unique, server-enforced, renameable, and not an identity.

### Rotation, which nearly breaks this

`Account::rotate` (`account.rs:163`) exists: the old key signs a claim naming its successor. So
the fingerprint of the *current* identity key is not stable, and an id derived from it would move
on rotation — reintroducing the problem this design removes, in a rarer and more confusing form.

The id is therefore the fingerprint of the **genesis** key, and the rotation chain is the evidence
linking it to whatever key is current. A verifier walks the chain: each link is a
`RotationClaim` signed by the key it supersedes, exactly as `verify_rotation` already checks it.
The anchor never moves; the key underneath it may.

The chain has to be *published and append-only*, or a server that withholds a link can convince a
peer that a rotated account is a stranger. That is a new object with a new integrity requirement,
and it is the largest single piece of work this design implies. The transparency log
(`apps/web/src/lib/transparency.ts`, `proofstrip.ts`) is the machinery it should ride on rather
than a second one built beside it.

### What the server becomes

A directory. `@bob → id`, and nothing else about identity.

It can refuse to answer, answer late, or answer with the wrong id. It cannot make the wrong id
*verify*: the fingerprint is over the key, the key is in the credential, and the comparison is
local. Which is to say the failure mode of a lying directory is the failure mode the product
already has and already answers — an out-of-band fingerprint comparison — rather than a new one.

This is why the split-view attack on names does not need a detection mechanism here. There are not
two claims to compare between members; there is one value that verifies against key material or
does not.

## The reframing this forces

**A renameable handle is not an identity. It is a nickname with a lock on it.**

Two consequences, and both are rules rather than preferences.

**The displayed handle is never re-fetched from the server.** It travels as a claim by its owner,
inside MLS, the way a display name travels today through `TYPE_PROFILE`. The server may refuse to
serve an alias; it must not be able to fabricate one inside a group. A handle read back from a
directory at render time would hand the server the power this design just took away, at the one
moment nobody is checking.

**The handle joins the category `compactNameOf` already governs.** It is shown alone where the
stakes are low, and never alone where they are high. `apps/web/src/lib/naming.ts` already
implements the ambiguity rule for display names; a renameable handle is subject to the same one,
with the difference that uniqueness is enforced at a moment in time rather than never.

## Three rules that only appear when you write it down

**Handles are never recycled.** If `@bob` is released and re-registered, every stale reference —
a bookmark, a screenshot, a mention in an old message — now names somebody else. That is an
impersonation nobody had to mount; it arrives on its own. Tombstone the row. Quarantine is a
compromise that protects only the inattentive.

**A rename route is a registration route wearing a hat.** It needs the rate limits of
`create_account`, plus a per-account cooldown — otherwise renaming is the tool that escapes a
block — and a lifetime cap.

**A rename is an event in the thread, not a silent state change.** The machinery exists:
`TYPE_MEMBERSHIP` in `apps/web/src/lib/content.ts` carries membership verbs and is displayed,
archived and counted. It needs one more verb and one more catalogue entry in `lib/i18n.ts`.

## The one open decision

An id is 128 bits — 32 hex characters in eight blocks. It is comparable in a verification panel
and unusable inline, so anywhere the id must be *seen* next to a name, a prefix is shown.

**A truncated fingerprint is grindable.** An attacker generates account keys until the first *n*
characters match their target's. At 32 bits this is minutes on a laptop. At 64 bits it is
expensive. At 128 there is nothing to grind and nothing to show.

This number is the only genuine trade-off in the design, and it must be chosen deliberately rather
than inherited from whatever fits a column. The recommendation is **64 bits (16 hex, four blocks)**
for any inline anchor, with the full 128 in the verification panel — and the honest statement, in
`docs/THREAT-MODEL.md`, that the inline form is a convenience and the panel is the proof.

## Inventory

Roughly ordered by depth, and deliberately not estimated in time.

| Where | What changes |
|---|---|
| `crypto-core/identity.rs` | Credential carries the id; genesis key retained for the anchor |
| `crypto-core/account.rs` | `attest`/`revoke`/`rotate` claims bind the id, not the handle |
| `attest/lib.rs` | `DeviceClaim`, `RevocationClaim`, `RotationClaim` field swap |
| `crypto-core/roles.rs` | `admin`/`moderators` hold ids; roster format changes |
| `server/routes.rs` | Device id prefix is the id; alias table; rename route; rate limits |
| `server` schema | Accounts keyed by id; handles a separate table with tombstones |
| Rotation chain | Published, append-only, verifiable — see above; the largest piece |
| `web/lib/session.ts` | Peers and accounts keyed by id; handle becomes display state |
| `web/lib/naming.ts` | Handle treated as a claim, subject to the ambiguity rule |
| `web/lib/mention.ts` | Mentions encode the id — see below |
| `web/lib/content.ts` | A rename verb on `TYPE_MEMBERSHIP` |
| `web/components/Onboarding.tsx` | The handle stops being permanent; the copy saying so goes |

**No migration.** The database is disposable at this stage of development, so this is a clean cut
rather than a dual-read path. That is worth a great deal and it is worth doing *now* for exactly
that reason: every account created after this design lands is an account that has to be migrated
if it lands later.

### Mentions, and a decision to reopen

`apps/web/src/lib/mention.ts` encodes a mention as the literal text `@charlie8295`. The argument
for it is written at the top of that file: a display name is self-asserted, not unique, and
editable, so a mention carrying one is orphaned by the next rename.

**A renameable handle falls into the same category.** The decision is correct while handles are
permanent and must be reopened the day they are not: mentions would carry the id and resolve to
the current handle at render, which is the design already in place one level up.

The compatibility cost is real and should be stated rather than discovered: a client from before
this change renders an opaque id where it used to render `@bob`.

## What this does not solve

- **First contact is still a leap of faith.** A directory that lies about `@bob` hands you a
  stranger's id, and only an out-of-band comparison catches it. This design does not make that
  better; it makes sure renaming does not make it worse.
- **A stolen seed still wins the race.** `attest::RotationClaim`'s own documentation says it: the
  thief holds the same key and can rotate first, and nothing in the protocol distinguishes the
  owner from the bearer. Anchoring on the genesis key does not change that — the chain is valid
  either way. The fingerprint-changed alert on the other side remains the only recourse.
- **The handle enumeration oracle stays.** Account creation is open, so a 409 tells an
  unauthenticated caller that a handle is taken, and a rename route adds a second door to the same
  room. Closing it means proof of work or authenticated creation, which is a different change.
- **Nothing here is about display names.** They stay what they are: unverified claims, governed by
  `naming.ts`, and now joined by the handle in that category rather than standing apart from it.

## Verification

The properties worth pinning are the ones a test can hold without a network:

- An id verifies against the credential it was read from, and fails against any other key.
- A rotation chain of length *n* resolves to the same anchor as the same chain truncated and
  re-extended; a chain with a missing link fails rather than resolving to the wrong anchor.
- A tombstoned handle is never re-issued, including after the account holding it is deleted.
- `roles.rs` grants nothing to a handle that matches an admin's *former* alias.
- A rename produces exactly one notice per conversation, and none in a conversation the renamer
  is not in.

---

## What changed on the way

Three things this document did not foresee, recorded because a spec that pretends it was right is
a spec nobody will trust the next time.

**The handle was signed into every attestation**, not merely carried by the credential.
`DeviceClaim`, `RevocationClaim` and `RotationClaim` all had it as field zero, so every
attestation an account had ever made was bound to whatever it was called at the time. The domains
moved to `v2` as a result — field zero changed meaning, and a thirty-two character handle is a
legal handle that reads exactly like an id, so nothing but the label could tell the two apart.

**The handle had to gain a channel of its own.** The spec said the displayed handle must never be
re-fetched from the server, and stopped there — it did not follow the consequence, which is that
once the credential carries an id, *nobody in a room knows the handle at all*. `TYPE_HANDLE` (11)
now carries it as a claim over MLS, believed exactly as much as a display name. An account whose
claim has not arrived is shown the first 64 bits of its id.

**`VERSION` was not the migration door it looked like.** It guards the native path only: the web
client reads its state back from IndexedDB with a plain `get` and compares nothing. The states
that had to be refused were precisely the ones with no version to read, so the check is on the
*shape* — a device id whose prefix is not 32 hexadecimal characters is from before. Absent had to
mean old, not unknown.

And one defect found by pressing the button rather than by reading the code: the rename cooldown
measured how long the account had held its current name, which refused the **first** rename,
because a handle claimed at sign-up is minutes old. The rule was always about frequency, and the
first change has no previous one.
