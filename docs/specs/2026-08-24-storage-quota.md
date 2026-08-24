# A stored-bytes quota, because a rate limit never was one

**Status.** Specified.

**Date.** 2026-08-24.

## The defect

`crates/server/src/throttle.rs` says it three times, in its own words, and has said it since it
was written:

> **What this does not do is stop a disk from filling.** Nothing keyed on time can […] The bound
> that actually closes it is a stored-bytes quota per account, which this server does not have.
> Saying the rate limit solves storage would be the comfortable lie.

Nothing has closed it since, and one thing made it worse. `0012_retention.sql` turned `envelopes`
from an unbounded store into a steady state — an envelope is deleted once it is both older than
thirty days and five hundred sequences behind its group's head — and that purge is only
acceptable because the content survives in `vault_entries`. Which is therefore **deliberately
never purged**. The debt did not get paid; it moved into the table that now has no exit at all,
held back by ten writes a minute per device, which is to say by nothing over a year.

Ten writes a minute, two hundred entries a write, at the 256-byte minimum the padding imposes, is
roughly seven hundred megabytes a day and per device. A rate limit turns "fill the disk this
afternoon" into "fill the disk over a fortnight". A fortnight is not a bound.

## The decision

**Two counters, each held where the data allows it to be held honestly, checked and debited in
the same statement as the write they measure.**

| What is stored | Charged to | Where the counter lives |
|---|---|---|
| `vault_entries.payload` | the owning account | `account_storage.bytes` |
| `attachments.payload` | the account that uploaded it | `account_storage.bytes` |
| `envelopes.payload` | the group | `groups.stored_bytes` |

### Why envelopes are charged to the group and not to the account

Because charging them to an account is not a design choice available here. `post_envelope`
(`routes.rs:2311`) takes two paths, and the sealed one — the `X-Group-Mac` header — carries no
device id at all. That is the entire point of sealed sender: the server learns that a member
posted, never which one. Billing an envelope to an account would mean recording the sender of
every post, which is precisely the register this protocol removed.

The alternative that looks cheap and is worse: charge only the *signed* posts. Sealed posts would
then be free, so the quota would be dodged by using the feature everybody uses by default. A
limit that appears set and bounds nothing is worse than an absent one, because it stops the
question from being asked again.

The group is what the server already knows, already counts (`groups.next_seq`), and already
updates in the transaction that inserts the envelope. Charging the group adds no observation.

### Why attachments are charged to the account, and what that costs

An upload is signed, so the caller is known at request time. Today `attachments` holds only
`group_id`: the server *learns* who uploaded and does not *record* it. Charging the uploader
means adding an `account` column, which turns a transient observation into a durable register of
**who put which file into which group**.

That is a new metadata leak and it goes in the limitations table of `docs/THREAT-MODEL.md`, in
those words. It is accepted because the alternative — charging the group — makes the heaviest
write the server accepts (twenty-five mebibytes, `MAX_ATTACHMENT_BYTES`) free at the point of
decision: one member could exhaust a shared ceiling for everybody, and the server would hold
nothing letting an operator say who did it. Between a leak that is written down and an
attribution that cannot be made at all, this takes the leak.

## The mechanism

### Check and debit are one statement

```sql
UPDATE account_storage
   SET bytes = bytes + $1
 WHERE account = $2 AND bytes + $1 <= $3
```

Zero rows affected means the ceiling is reached: the transaction rolls back and nothing is
inserted. There is no read-then-write, because between the read and the write two concurrent
uploads both pass, and a quota that fails under concurrency is a quota an attacker meets by
opening two connections. `groups.stored_bytes` takes the same form.

The debit happens in the transaction that inserts the rows, so a failed insert cannot leave the
counter charged for bytes that were never stored.

### Refusal is 507, not 429

`ApiError::InsufficientStorage`, distinct from `TooManyRequests`. The distinction is the same one
`Gone` already draws against `NotFound`: 429 means *retry later* and that is true of a rate
limit; 507 means *retrying changes nothing*, which is true of a full vault. Answering 429 would
tell a client to come back forever, and it would.

Nothing is evicted to make room. FIFO eviction on the vault would keep writes succeeding by
deleting the oldest history silently, and `0012_retention.sql` already argues the opposite case
at length — a loss that is made *visible* beats a loss that is made rare. The owner is told the
vault is full and decides.

### Decrements are where this design rots

The failure mode of a maintained counter is drift, and it drifts one way: a delete that forgets to
decrement leaves an account refused writes for bytes that no longer exist. Every deletion path is
therefore part of this change, not a follow-up to it:

- `purge_once` deletes envelopes and attachments; each `DELETE` becomes `DELETE … RETURNING
  octet_length(payload)`, and the sum is subtracted in the same transaction.
- Dropping a group cascades its row, and its counter with it.
- Deleting an account cascades `account_storage`.

Coverage points at exactly this: an integration test that replays writes, purges and deletions,
then compares both counters against `SUM(octet_length(payload))` computed from the tables. Drift
becomes a failing test rather than an incident nobody can reconstruct.

### Ceilings, and where they are set

`256 MiB` per account and `1 GiB` per group by default, read from the environment, with the
defaults as documented constants next to those of `throttle.rs` — it is the same subject and
belongs in the same place. The strict end of the range was chosen deliberately: it closes the
abuse window to a few hours, and real use is measured in tens of megabytes a year, so the
ceiling is one a legitimate account does not reach and an attacker meets on the first day.

Migration `0019` creates the table, adds the columns, and **backfills both counters from the rows
already stored**. A deployment upgrading mid-life starts with a true occupancy rather than with
zero, which would hand every existing account a fresh ceiling on top of what it already holds.

### The client is told

The 507 reaches the screen instead of being retried. Vault synchronisation stops, and the
"History backup" setting says the vault is full. Without that, the ceiling would be a silent
failure — the client would keep uploading, the server would keep refusing, and the user would
believe their history was being archived when it had stopped being.

## What this does not solve

- **A member can exhaust their group's ceiling for everybody.** Charging envelopes to the group is
  what keeps sealed sender intact, and the cost is that the ceiling is shared: one flooding member
  denies writes to members who wrote nothing. Bounded by the fact that flooding requires already
  being a member, and by the per-device rate limit that stays in front of it. There is no fix for
  it that does not name the sender.
- **The counter bounds storage, not fairness.** An account near its ceiling and an account that
  has written once are treated identically until the ceiling is met.
- **It does not make the disk unfillable, only fillable by a bounded number of accounts.** N
  accounts times 256 MiB is still N times 256 MiB, and registration is what bounds N — a different
  mechanism, not in this change.
- **`throttle.rs` must stop saying the bound is missing.** Three passages announce a quota that
  does not exist. Leaving them would make the documentation false in the other direction, which is
  the failure this project treats as the serious one.

## Verification

Properties a test holds (`crates/server/tests/`, requires PostgreSQL):

- A write that would cross the ceiling is refused with 507, and stores nothing — the row count is
  unchanged after the refusal.
- A write that fits is stored and the counter moves by exactly the bytes stored.
- Two concurrent writes that individually fit and jointly do not: one succeeds, one is refused,
  and the counter never exceeds the ceiling.
- A purge that deletes envelopes lowers the group counter by the bytes deleted.
- Deleting an account removes its counter; dropping a group removes its own.
- After a replay of writes, purges and deletions, both counters equal the `SUM` recomputed from
  the tables.
- The backfill in `0019` produces the same values as that `SUM` on a database populated before the
  migration.
