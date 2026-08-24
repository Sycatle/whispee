# A stored-bytes quota, because a rate limit never was one

**Status.** Specified.

**Date.** 2026-08-24.

**Scope.** Durable storage whose owner is authenticated at the moment it is written: the history
vault and attachments. Envelopes are bounded by a personal allowance too, and it cannot work the
same way — see [`2026-08-24-posting-allowance.md`](./2026-08-24-posting-allowance.md), which this
spec deliberately does not wait for.

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

**One counter per account, checked and debited in the same statement as the write it measures,
and credited back when the bytes leave.**

| What is stored | Charged to | Reclaimed when |
|---|---|---|
| `vault_entries.payload` | the owning account | the account is deleted (the vault is never purged) |
| `attachments.payload` | the account that uploaded it | `purge_once` deletes the attachment |

The counter lives in `account_storage(account, bytes)`, keyed on `accounts(id)` with
`ON DELETE CASCADE`.

### Why the subject is the account and not the group

Because the account is what the two writes in scope prove. A vault entry is fetched and stored
under `caller_account` already; an upload is signed, so its author is known at the moment it is
accepted. Charging a group instead would mean one member's flood denies writes to members who
wrote nothing, and would leave the operator holding nothing that says who did it.

The same reasoning is what puts envelopes in a separate spec rather than in this table. A sealed
post carries no device id — that is the whole point of sealed sender — so the account behind it
cannot be charged without recording the sender of every post. The answer is anonymous byte tokens,
which is a body of cryptography and not a column.

### Why attachments are charged to the account, and what that costs

Today `attachments` holds only `group_id`: the server *learns* who uploaded and does not *record*
it. Charging the uploader means adding an `account` column, which turns a transient observation
into a durable register of **who put which file into which group**.

That is a new metadata leak and it goes in the limitations table of `docs/THREAT-MODEL.md`, in
those words. It is accepted because the alternative leaves the heaviest write the server accepts
— twenty-five mebibytes, `MAX_ATTACHMENT_BYTES` — outside any personal bound, which is the defect
this spec exists to close.

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
opening two connections.

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

### Credits are where this design rots

The failure mode of a maintained counter is drift, and it drifts one way: a delete that forgets to
decrement leaves an account refused writes for bytes that no longer exist. Every deletion path is
therefore part of this change, not a follow-up to it:

- `purge_once` deletes aged attachments; its `DELETE` becomes `DELETE … RETURNING account,
  octet_length(payload)`, and the totals are subtracted per account in the same transaction.
- A group deleted by cascade takes its attachments with it, and those bytes are credited by the
  same path rather than by the cascade — a cascade cannot run application logic, so the
  attachments of a group being dropped are deleted explicitly first.
- Deleting an account cascades `account_storage` away, so nothing is left to credit.

Coverage points at exactly this: an integration test that replays writes, purges and deletions,
then compares the counter against `SUM(octet_length(payload))` recomputed from both tables. Drift
becomes a failing test rather than an incident nobody can reconstruct.

### The ceiling, and where it is set

`256 MiB` per account by default, read from the environment, with the default as a documented
constant next to those of `throttle.rs` — it is the same subject and belongs in the same place.
The strict end of the range was chosen deliberately: it closes the abuse window to a few hours,
and real use is measured in tens of megabytes a year, so the ceiling is one a legitimate account
does not reach and an attacker meets on the first day.

Migration `0019` creates the table, adds the column, and **backfills the counter from the rows
already stored**. A deployment upgrading mid-life starts with a true occupancy rather than with
zero, which would hand every existing account a fresh ceiling on top of what it already holds.

The backfill has one hole it cannot fill: attachments uploaded before the migration have no
`account`, because nothing recorded it. They are charged to nobody — the column is nullable and
null means *predates the quota*. Retrofitting an owner would mean inventing one. Those rows age
out under the existing retention rule within thirty days, after which the hole closes by itself.

### The client is told

The 507 reaches the screen instead of being retried. Vault synchronisation stops, and the
"History backup" setting says the vault is full. Without that, the ceiling would be a silent
failure — the client would keep uploading, the server would keep refusing, and the user would
believe their history was being archived when it had stopped being.

## What this does not solve

- **Envelopes are not bounded per account by this change.** They stay in the steady state
  `0012_retention.sql` produced, held by the rate limit alone, until the posting allowance ships.
- **The counter bounds storage, not fairness.** An account near its ceiling and an account that
  has written once are treated identically until the ceiling is met.
- **It does not make the disk unfillable, only fillable by a bounded number of accounts.** N
  accounts times 256 MiB is still N times 256 MiB, and registration is what bounds N — a different
  mechanism, not in this change.
- **`throttle.rs` must stop saying the bound is missing.** Three passages announce a quota that
  does not exist. Leaving them would make the documentation false in the other direction, which is
  the failure this project treats as the serious one. Two of them are answered here; the passage
  about `envelopes` is answered by the posting allowance and stays true until then.

## Verification

Properties a test holds (`crates/server/tests/`, requires PostgreSQL):

- A vault write that would cross the ceiling is refused with 507 and stores nothing — the row
  count is unchanged after the refusal.
- An attachment upload that would cross the ceiling is refused the same way.
- A write that fits is stored and the counter moves by exactly the bytes stored.
- Two concurrent writes that individually fit and jointly do not: one succeeds, one is refused,
  and the counter never exceeds the ceiling.
- A purge that deletes attachments lowers the counter of the account that uploaded them, and
  leaves other accounts' counters untouched.
- Deleting an account removes its counter.
- After a replay of writes, purges and deletions, the counter equals the `SUM` recomputed from
  `vault_entries` and `attachments`.
- The backfill in `0019` produces the same values as that `SUM` on a database populated before the
  migration.
