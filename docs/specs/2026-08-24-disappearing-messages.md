# Disappearing messages: a room that does not remember everything

**Status.** Specified.

**Date.** 2026-08-24.

**Touches** [`2026-08-24-storage-quota.md`](./2026-08-24-storage-quota.md) at exactly one point: the
vault deletion this introduces has to credit the storage counter, or that spec's reconciliation
test fails. Nowhere else.

## The defect

A conversation in this application keeps everything, for ever, by default. The history vault is on
unless it is switched off, `vault_entries` is deliberately never purged, and a message therefore
outlives every reason anybody had for writing it.

That is a decision the product never actually made. It fell out of two other ones — forward
secrecy is real, so the vault exists to give history back; the vault must not be purged, so
deleting envelopes stays acceptable — and their combination says something neither of them
intended: *nothing you write here goes away*.

`ConversationFlags.ephemeralMs` already exists in `session-types.ts:448`, declared, documented as
unenforceable, and implemented nowhere. It is a local preference, which is the wrong shape: a
lifetime one side sets and the other cannot see is a note to oneself, not a property of the
conversation.

## The decision

**Seven days by default, as a group policy carried in the MLS group context, deleted client-side
from a clock every member can check.**

### Where the policy lives

A group context extension, `0xF101`, next to the `0xF100` the roster already occupies in RFC
9420's private-use range. Its body is one unsigned integer: the lifetime in seconds, `0` meaning
off. Absent means off — the same reading `roles.rs` gives its own absent extension, and what lets
groups created before this keep working.

Every conversation this client creates sets it to **604 800**.

Carrying it in the group context rather than in a message is what makes it a property of the room:
it is authenticated by MLS, every member reads the same value, and changing it is a commit each
member validates rather than a claim one client makes. A local preference could not say "this
disappears in seven days" about anybody's copy but its own.

### Who may change it

Admin and moderators — the rank that already adds and removes members. Changing what the room
keeps is the same kind of act as changing who is in it, and `roles.rs` already draws that line and
enforces it in `crypto-core`: a commit that changes the extension without the rank is **rejected by
the other members**, not merely hidden in an interface. In a 1-to-1 there is no roster, the group
is flat, and either side may set it.

Every change posts a notice in the thread, as a new `Content` kind beside `membership`:
`{ kind: "expiry"; seconds: number }`. Membership already works this way and the reason carries
over — a room whose memory silently grows from seven days to a year has changed in the way that
matters, and the change belongs in the history rather than in a menu somebody may never open.

### The clock, and the lie it allows

The deadline is computed from `sentAt`, which already travels inside the MLS message and whose own
documentation states the important half: **declared, not proven**. Any member can put what they
like in their own.

So each recipient computes:

    expiry = min(sentAt, first seen locally) + lifetime

A member can therefore make their own message die sooner, which was never forbidden, and cannot
make it live longer, which is the attack. No clock is trusted across the wire and none needs to be.

Control traffic carries no `sentAt` and is not subject to expiry: it is not history, and expiring a
membership notice would leave a thread describing a room nobody joined.

### The vault loses

A conversation with a lifetime set is **never archived**, and turning the lifetime on **deletes
what was already deposited** for that group. Anything else would make the feature a display: an
archive the server keeps for ever, of messages the interface says are gone, is the exact shape of
the lie this project refuses elsewhere.

That needs a delete route for one group's vault, which does not exist today, and it must credit
`account_storage` — see the companion spec, whose reconciliation test is what will catch it if it
does not.

What it costs, and the screen has to say it: **an ephemeral conversation does not survive the loss
of every device.** Not the expired part of it — all of it, including this morning's messages. The
vault is what brings history back to a new device, and this switches the vault off for that room.

### Turning it on is not retroactive

Only messages sent after the change expire. History already on a member's device stays, and no
moderator gains a button that erases a group's memory on everybody's machine at once.

The vault deletion above is the one exception, and the two are consistent rather than contradictory:
what a member holds is theirs and is left alone; what the *server* holds on their behalf is what
the policy is about.

## What this does not do

- **It is not enforced on the other side, and the interface must say so above the control rather
  than beneath it.** Screenshots exist. A modified client keeps whatever it likes. What the feature
  actually buys is that a message does not end up in an archive sitting on a server for the rest of
  time — and that part is true.
- **The server keeps the ciphertext for up to thirty days.** It never learns the lifetime: the
  extension lives inside the group context, which the server does not hold, and telling it would
  hand it a metadata that sorts careful rooms from careless ones. So `envelopes` keeps its own
  retention, unreadable, and each client drops on arrival anything already past its expiry. A device
  back from ten days offline does not see the expired messages reappear — it never sees them at all,
  which is the price of the common deadline.
- **A message never delivered is a message lost, not a message deleted.** The deadline runs from the
  sending, so somebody away for longer than the lifetime comes back to a gap. That is the cost of
  "disappears at one moment for everybody", and the alternative — each device on its own clock — buys
  the unread case by giving up the common instant.
- **It changes what the product is, by default.** With seven days on every new conversation and the
  vault off for those rooms, an ordinary account no longer carries its history to a new device. That
  is closer to Signal than to WhatsApp, it is a defensible product, and it has to be stated on the
  screen where the account is created rather than discovered on the day a phone is lost.
- **`ephemeralMs` goes.** Leaving a local flag that promises the same thing and enforces nothing
  beside a group policy that does would make two features out of one, and the wrong one would be the
  easier to find.

## Verification

Properties a test holds without a network (`crypto-core`):

- The extension round-trips through encoding and decoding, and an absent extension reads as off.
- A commit changing the lifetime is accepted from the admin and from a moderator, and **refused
  from an ordinary member** — refused at validation, not hidden in an interface.
- A flat group (no roster) accepts the change from either side.

Properties a test holds in the client suite:

- A message whose `sentAt` is in the future expires on the recipient's clock, not on the sender's:
  the clamp holds.
- A message already past its expiry when it arrives is never inserted into the view.
- Control traffic without `sentAt` is never expired.
- Turning the lifetime on leaves existing messages in place and stops future archiving.

Properties that need the server:

- Deleting a group's vault removes exactly that group's entries for that account, and none of
  another account's.
- The deletion credits `account_storage` by the bytes removed, and the counter still reconciles with
  the tables afterwards.
