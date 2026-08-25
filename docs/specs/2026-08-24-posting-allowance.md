# A personal posting allowance that does not name the poster

**Status.** Specified.

**Date.** 2026-08-24.

**Depends on** [`2026-08-24-storage-quota.md`](./2026-08-24-storage-quota.md), which bounds the
storage whose owner is authenticated. This spec bounds the storage whose owner deliberately is
not.

## The defect

Every account must be bounded in what it posts. `post_envelope` (`routes.rs:2311`) has two paths,
and the one that matters carries no identity: an anonymous post is authenticated by a MAC under
the group's posting key (`x-group-mac`, `0007_sealed_sender.sql`), which every member holds. The
server learns that *a member* posted, never which one. That is sealed sender, and it is a claimed
property of this protocol in four documents.

So the account behind a post cannot be charged. Two cheap answers exist and both are wrong:

- **Record the sender.** It makes the quota trivial and deletes the property.
- **Charge only the signed path.** Sealed posts would then be free, so the bound would be dodged
  by the default path. A limit that looks set and bounds nothing is worse than an absent one,
  because it stops the question being asked again.

## The decision

**The account is charged when it acquires the right to post, not when it posts.** The client buys
byte tokens with an authenticated request; it spends them anonymously. The server counts what it
issued — which is per account, and is the quota — and cannot link a spent token to its issuance.

This is Privacy Pass, and it is a body of cryptography rather than a column.

### The primitive: a VOPRF, privately verifiable

RFC 9497, ristretto255-SHA512. The server both issues and verifies, so the public verifiability of
RSA blind signatures (RFC 9474) buys nothing here and costs 256 bytes per token against 32.
`curve25519-dalek` is already in the tree through `ed25519-dalek`.

**The primitive is taken from the `voprf` crate, not written here.** `crates/ratchet-lab` exists
because reimplementing a protocol teaches something; this is the opposite case — a blinding factor
mishandled leaks the link the whole construction exists to break, and that failure is silent.

The exchange, in the three steps a reader needs:

1. The client draws a random 16-byte nonce, blinds `H(nonce)` with a random scalar, and sends the
   blinded element with an authenticated request.
2. The server evaluates it under the secret key of the requested denomination and returns the
   result. It sees a uniformly random group element and learns nothing about the nonce.
3. The client unblinds. The token is `(nonce, output)`. The server can recompute `output` from
   `nonce` with its key — that is the verification — but nothing ties this nonce to that issuance.

### Denominations are the padding buckets

`apps/web/src/lib/padding.ts` already puts every envelope in a doubling bucket from 256 bytes, and
`MAX_ENVELOPE_BYTES` is one mebibyte: **thirteen buckets**, exactly. One issuance key per bucket,
so a post spends **one token**, not the two hundred and fifty-six a fixed 4 KiB unit would cost at
the ceiling.

The denomination is visible when the token is spent, and it reveals nothing new: the padded size
of the envelope is a number the server reads off the request anyway.

### Spending, and double spending

A sealed post carries one more header: the nonce, the bucket, and the unblinded output. The server
recomputes the output under that bucket's key, compares it in constant time, and inserts the nonce
into a nullifier table — **inside the transaction that inserts the envelope**, so a token cannot
be spent by two concurrent posts and cannot be consumed by a post that then fails.

`posting_nonces` is the precedent this follows: same shape, same purge discipline, same reason.

### Epochs, which is what keeps the nullifier table finite

Issuance keys rotate every thirty days. A token is valid only in the epoch it was issued in, and
the nullifier table is purged one epoch after that one closes — a table that grew forever would
reintroduce, in a new place, the unbounded store this whole effort is about.

Expiry also stops hoarding. Without it an account would accumulate a year of allowance and pour it
out in one afternoon, which is the exact shape of the abuse the allowance exists to prevent.

### The allowance itself

`256 MiB` per account per epoch by default, read from the environment, alongside the storage
ceiling of the companion spec — the two numbers are read together or not at all. Issuance debits
`posting_allowance(account, epoch, bytes)` by the denomination times the number of tokens asked
for, in the same statement that checks it, in the form the companion spec already argues:

```sql
UPDATE posting_allowance
   SET bytes = bytes + $1
 WHERE account = $2 AND epoch = $3 AND bytes + $1 <= $4
```

Zero rows affected means the allowance is spent: 507, and the client says so rather than retrying.

### Why an allowance and not an occupancy

Because a storage quota needs a credit as well as a debit, and there is nobody to credit. When
`purge_once` deletes an envelope, the bytes should return to whoever posted it — and the whole
point of this design is that the server does not know. So the bound on envelopes is a **rate over
a long window** rather than a live occupancy.

That is not a concession, it is the right shape here: `0012_retention.sql` deletes an envelope
once it is thirty days old and five hundred sequences behind. An allowance measured over thirty
days *is* an occupancy bound in the steady state, and it is bounded by the same clock the purge
already runs on.

### The signed path pays directly

A post on the authenticated path needs no token: the account is known, so it debits
`posting_allowance` for the same number of bytes at the moment it posts. Otherwise the fallback
would be the bypass, and the fallback is what a client uses whenever the posting key has not
reached it yet.

### Clients must hold a reserve

**A token issued and spent seconds later, in a group of two, is linkable by timing alone.** The
cryptography breaks the link; the clock rebuilds it. So the client fetches tokens in batches
ahead of need — a batch when the reserve falls below a quarter, never on the path of a message
being sent — and this is a requirement of the design rather than an optimisation of it.

Tokens are bearer values: whoever holds them can post with them. They live with the rest of the
local state, under the master key, and are lost with the device. A device wiped mid-epoch loses
the tokens it held; the allowance they were bought from does not come back until the epoch turns.
Said plainly, that is the cost of a token nobody can trace back to its buyer.

## What this does not solve

- **The server still paces.** It learns how many bytes each account is entitled to post and when
  it asks for them. Sealed sender protects against a server that observes, not against one that
  paces — the same sentence already written about push notifications in `docs/ROADMAP.md`, and it
  is no less true here.
- **Refusing issuance is targeted censorship, and it is visible.** A server that stops issuing to
  one account silences it. Nothing cryptographic answers that; what answers it is that the client
  can say which account was refused, out loud.
- **The issuance key is a quota secret, not a confidentiality secret.** Whoever steals it mints
  free tokens and bypasses the allowance. No message becomes readable, no sender becomes known.
  Rotation every thirty days bounds the damage in time.
- **The allowance is per account, shared across its devices.** Ten devices do not get ten
  allowances — which is the opposite of what `throttle.rs` does with rate limits, on purpose: a
  rate limit bounds a rate per signing key, this bounds a volume per person.
- **An epoch boundary is a cliff.** An account that exhausts its allowance on day two waits
  twenty-eight days. A sliding window would be kinder and would make the nullifier table unbounded
  again; the cliff is the price of the finite table, and the client must show the date rather than
  fail blankly.

## Verification

Properties a test holds without a network (`crypto-core`):

- A token unblinded by the client verifies under the server's key; one produced under a different
  denomination's key does not.
- Blinding is randomised: two issuances of the same nonce produce unrelated blinded elements.
- The nonce cannot be recovered from the blinded element.

Properties that need the server (`crates/server/tests/`, requires PostgreSQL):

- A post with a valid token is accepted; the same token replayed is refused, and the second post
  stores nothing.
- Two concurrent posts spending the same token: one succeeds, one is refused.
- A token from a closed epoch is refused.
- Issuance debits the allowance by denomination times quantity, and the request that would cross
  the ceiling is refused with 507 having issued nothing.
- A post on the signed path debits the allowance without a token, and is refused with 507 when the
  allowance is spent.
- The nullifier table is emptied of an epoch's nonces once that epoch is two epochs old, and not
  before.
