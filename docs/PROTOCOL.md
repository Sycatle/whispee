# Protocol

This is the wire-level reference for Whispee: the exact bytes that are signed, MACed, hashed and
framed between a client and the server. It is for anyone reading the code, reimplementing a
client, or auditing a claim made elsewhere in the documentation.

Whispee is a **learning and demonstration project**. It has had no external audit and will not get
one. For communications that actually matter, use Signal. See [`../README.md`](../README.md) for
the full status disclaimer, [`./THREAT-MODEL.md`](./THREAT-MODEL.md) for who this is meant to
resist, and [`./SECURITY-PROPERTIES.md`](./SECURITY-PROPERTIES.md) for what it claims to achieve
and where each claim stops.

The group layer is MLS (RFC 9420), through OpenMLS 0.8.1 in `crates/crypto-core`. MLS defines
neither the Delivery Service nor the Authentication Service: everything in this document is the
part Whispee had to build around it.

---

## 1. Device authentication

Every device registers an Ed25519 **authentication public key**. There is no password and no
session token: the database holds only public keys, so a database leak grants access to no
account.

### 1.1 The auth key is not the MLS signature key

A device carries two Ed25519 keys, and they are deliberately distinct:

| Key | Used for |
|---|---|
| authentication key | signing HTTP requests and the gateway handshake |
| MLS signature key | signing MLS handshake and application messages |

Reusing one key across two protocols is a classic mistake: as soon as the two message formats
overlap, a signature produced under one becomes a valid signature under the other. Both keys are
attested together (§7), so they cannot be recombined across devices either.

### 1.2 The canonical signed request

`crates/server/src/auth.rs` defines what is signed. The payload is the concatenation, separated by
`\n`:

```
method   ‖ "\n" ‖
path     ‖ "\n" ‖          -- path and query
timestamp‖ "\n" ‖          -- Unix seconds, decimal ASCII
nonce    ‖ "\n" ‖          -- 16 raw bytes
SHA256(body)
```

The method and the path are inside the message: without them, a signature valid for `GET /stock`
would replay on `POST /envelopes`. The body enters by its digest rather than by value, which
avoids holding it in memory twice.

Four headers carry the rest:

| Header | Contents |
|---|---|
| `x-device-id` | the device identifier, qualified by the account id (`d52c15be…:desktop`) |
| `x-timestamp` | Unix seconds, matching the signed value |
| `x-nonce` | base64 of the 16-byte nonce |
| `x-signature` | base64 of the Ed25519 signature |

### 1.3 The nonce, and why Ed25519 makes it mandatory

Each request carries a 16-byte random nonce, covered by the signature and remembered on first
presentation. Replaying it is refused.

**The nonce cannot be replaced by the signature itself.** Ed25519 is deterministic: two identical
requests in the same second produce the *same* signature. One of them may be a replay while the
other is legitimate, and nothing in the signature distinguishes them. Claiming two KeyPackages
back to back is enough to produce the case. Because the nonce is inside the signed message, a
third party cannot make a captured request look fresh by changing the header alone.

Sixteen random bytes: against a sixty-second window the odds of a device redrawing a remembered
nonce are negligible, and a collision would cost a plain refusal, not a vulnerability.

### 1.4 Clock tolerance, and the memory it bounds

`MAX_CLOCK_SKEW` is **60 seconds**. A request whose timestamp falls outside that window is
refused regardless of its signature.

That window is also what bounds the nonce memory: beyond it the timestamp rejects the request
anyway, so `request_nonces` (migration `0010_replay_protection.sql`) is purged past the window.
The table is `UNLOGGED`, which is a deliberate trade and carries a limitation the migration text
can no longer state — sqlx freezes a migration's checksum once applied. PostgreSQL empties an
`UNLOGGED` table after a crash. The remembered nonces are then lost and a captured request becomes
replayable until the end of its tolerance window. The property is not "no replay is possible"; it
is "no replay as long as the database has not collapsed".

### 1.5 Unauthenticated routes

Five routes cannot be authenticated by definition — account creation, device registration, pairing
deposit, pairing pickup, and the recovery claim. They carry a per-address rate limit, `THROTTLE_PER_MINUTE` (60 by
default). Account creation is what justifies it: it writes into the transparency log, whose
entries cannot be taken back without breaking the consistency proofs.

KeyPackage consumption carries its own separate bound, counted **per caller-target pair** and set
by `CLAIM_QUOTA_PER_MINUTE` (5 by default). That route irreversibly consumes one of the target's
welcome keys, and any authenticated device may aim at anyone: without a bound, any account could
drain a chosen victim's stock and leave them unreachable for any new conversation. The pair, not
the caller alone — opening conversations with many correspondents is legitimate, hammering a
single one is not.

The recovery claim (`POST /v1/recovery/claim`, § 11) carries a third bound of its own,
`RECOVERY_QUOTA_PER_MINUTE` — **three a minute per address**, the narrowest quota in the server.
Every other limit here bounds how fast a table grows; this one bounds how fast a password can be
guessed, and it is the only online bound that exists, because a failed claim names no account and
so cannot be counted against one. A compile-time assertion keeps it below every write quota.

All these counters live **in memory, hence per instance**: two instances offer twice the quota and a
restart resets them. An address is not an identity either. This is a speed bump, not a barrier.
The server reads only the socket address and never `X-Forwarded-For`, which anyone can forge.

---

## 2. Signature domains

Every signed or MACed message in this project begins with a domain label, followed by
length-prefixed fields (`u16` big-endian length, then the bytes). `crates/attest/src/lib.rs` holds
the single implementation; `crates/transparency` adds one more for tree heads.

| Domain | Signed or MACed by | Covers |
|---|---|---|
| `wac-attest-v2` | account identity key | `account`, `device_id`, `auth_key`, `mls_key` |
| `wac-revoke-v2` | account identity key | `account`, `device_id`, `revoked_at` |
| `wac-rotate-v2` | **previous** account identity key | `account`, `new_identity_key`, `rotated_at` |
| `wac-post-v1` | group posting key (HMAC) | `group_id`, `nonce`, `SHA256(body)` |
| `wac-signal-mac-v1` | group posting key (HMAC) | `group_id`, `nonce`, `SHA256(body)` |
| `wac-gateway-v1` | device authentication key | `device_id`, server challenge |
| `wac-sth-v1` | transparency log key | tree `size`, `root`, `timestamp` |

The recovery escrow (§ 11) adds four labels that are **derivation** domains rather than signature
domains — they separate keys, not messages, and so are not in the table above:
`wac-escrow-salt-v1`, `wac-escrow-lookup-v1`, `wac-escrow-seal-v1`, `wac-escrow-prf-v1`.

### 2.1 What domain separation buys

Each label makes a message of one kind unreadable as a message of another kind:

- `wac-attest-v2` vs `wac-revoke-v2`: without the split, an attestation legitimately obtained for
  a device could be presented as a revocation certificate for that same device — letting anyone
  get any attested device evicted.
- `wac-rotate-v2`: a signature produced to revoke a device must not be usable to change the
  account key, which would amount to taking the account over.
- `wac-post-v1` vs the three above: this one is a **symmetric MAC whose key the server holds**,
  where the others are signatures the server cannot produce. Conflating the domains would let
  whoever holds the posting key forge anything elsewhere.
- `wac-post-v1` vs `wac-signal-mac-v1`: the key is the same, the domain is not. Signal MACs are
  deliberately *not* replay-protected — a stale typing indicator has no effect — so a captured
  signal MAC must not be presentable as the MAC of an envelope post. The body formats differ
  enough for that attack to fail today, which is exactly the kind of reasoning that stops being
  true at the first change to the format.
- `wac-gateway-v1`: the handshake signature proves possession of the same key that signs HTTP
  requests. Without a separate domain, any captured HTTP signature would open a session, and the
  challenge nonce — whose whole purpose is to make that impossible — would be pointless.

The version suffix lets a format evolve without an old signature remaining acceptable under the
new rules.

### 2.2 Length prefixing

Every variable-length field is preceded by its `u16` length. Without those prefixes,
`account="ab", device_id="c"` and `account="a", device_id="bc"` serialise to identical bytes: an
attestation obtained for one would hold for the other. The `two_different_splits_do_not_collide`
test pins that down. A field longer than `u16::MAX` is refused rather than truncated, since silent
truncation would make two distinct entries indistinguishable. The fixed-width timestamps go
through the same prefixing — an exception to the format would be an opportunity to diverge for
nothing.

---

## 3. Sealed sender

Envelopes used to carry the sending device's signature. The server never needed to know **who**
posts — only that the poster is a member, so as not to be an open mailbox. Those are two different
things and the second one suffices.

### 3.1 The posting MAC

Each group carries a 32-byte **posting key**, shared by its members and known to the server.
Posting an envelope requires:

```
HMAC(posting key, "wac-post-v1" ‖ len‖group_id ‖ len‖nonce ‖ len‖SHA256(body))
```

Each component is there for a reason:

- **`group_id`** stops a captured post from being replayed into a different group.
- **`nonce`** (16 bytes) makes each post unique. Without it, an intercepted MAC stays valid
  forever, since the message depends on no timestamp.
- **`SHA256(body)`** binds the MAC to this exact envelope. The digest rather than the body: an
  attacker able to alter the envelope afterwards would otherwise post anything under a legitimate
  MAC.

The request carrying this MAC is **not signed** by any device key. That is the point.

### 3.2 Nonce uniqueness is a primary key, not a check

`posting_nonces (group_id, nonce)` is a `PRIMARY KEY` (migration `0007_sealed_sender.sql`), with a
`CHECK` that the nonce is exactly 16 bytes. Uniqueness is enforced by the constraint and not by
application code, because a `SELECT` followed by an `INSERT` leaves a concurrency window in which
the same nonce is accepted twice.

### 3.3 How the posting key reaches members

The group creator draws the key at random (32 bytes from the platform CSPRNG) and hands it to the
server at group creation. It reaches the other members **through MLS**, as a control message of
kind `posting-key` inside the ordinary encrypted channel — never through the server as a
distributor. Asking the server to distribute the key would be asking it to hand out the means of
not talking to it.

The column is nullable: groups created before sealed sender keep signed posting. Making it
mandatory would have silenced every ongoing conversation.

### 3.4 What sealed sender does not hide

The IP address, the timing, and which group was posted to. And because the server holds the key,
**it can post noise itself**: it cannot produce a valid MLS message, so nothing it writes will
decrypt, but it can pollute. That is the price of a symmetric MAC. Zero-knowledge tokens would
avoid it, at the cost of machinery out of proportion with this project.

### 3.5 The ephemeral signal channel

Typing indicators use the same MAC construction under `wac-signal-mac-v1`, and a different
encryption path: AES-256-GCM under the epoch's **export secret**
(`export_secret(..., "wac-signal-key-v1", 32)`), never the MLS application ratchet.

| | Durable channel | Ephemeral channel |
|---|---|---|
| Carries | messages, receipts, reactions, replies, call invitations and conclusions | typing, call frames |
| Encryption | MLS application ratchet | AES-256-GCM under the epoch export secret |
| Server storage | `envelopes` | **none** — relayed in memory, never the disk |
| Losing one | recovered by the cursor | no consequence |

Signal frames are capped at `MAX_SIGNAL_BYTES` = 4096 bytes. No "stopped typing" signal is ever
emitted: an end signal could be lost and would leave the indicator lit forever. It expires
locally, three seconds after the last signal, or immediately when a message from the author
arrives.

The export secret changes at every commit, so a removed member loses the typing channel at the
same instant they lose the messages — post-compromise security applies here for free.

### 3.6 Calls, and how they are split across the two channels

A call needs both channels, and the split follows the missing sender authentication above rather
than any notion of importance.

**The invitation is not in the ephemeral channel.** "Alice is calling you" is a claim about *who*
is speaking, and a key that belongs to the group cannot support one: any member could ring a group
under somebody else's name. It travels as an ordinary MLS message — `content.ts`, type byte 13 —
where the protocol authenticates its author. Three events share that byte: `invite`, `ended`
carrying a duration in seconds, and `missed`. A refusal and a call nobody heard are deliberately
the same event on the wire; telling the caller they were turned down rather than merely unheard is
an admission the protocol has no reason to extract from a device.

Two consequences come free. The call log and the missed call are messages, so they are ordered,
archived and re-read like any other. And an invitation is an envelope, so `push::wake_detached`
fires on it exactly as it does on a text — **without the server learning that this one was a
call.**

**Everything around the invitation is ephemeral**: `ringing`, `accepted`, `declined`, `left`,
`muted`, `unmuted`, `alive`, under type byte 1 of the signal format. None is load-bearing. Who is
actually in a call is whoever the media layer reports; these only let the interface react before
it can know, and a forged one changes nothing that matters. Both ends run their own ring timeout
(30 s) and their own silence timeout (15 s), because a frame saying "stop ringing" can be lost and
a phone that then rang forever is the one failure a user cannot work around.

### 3.7 The media path

The audio does not go through this server. It goes through a media server, which terminates the
transport encryption — that is what lets it route one stream to five listeners without holding
five conversations — and is therefore **encrypted a second time before it gets there**, frame by
frame, in the browser.

That second key is `export_secret(..., "wac-call-key-v1", call_id, 32)`, derived by every member
from the current epoch. Nothing is exchanged to obtain it, so neither server is ever in possession
of one and neither can be asked for one. The call id sits in the exporter's context so that two
calls in one epoch do not share a key — replaying one call's audio into another would otherwise
decrypt. And because it is an epoch secret, a member removed mid-call loses the audio at the same
commit that costs them the messages; the client re-derives it on a timer and hands it to the media
layer, so the property is acted on rather than merely true.

`POST /v1/groups/{group_id}/call/token` mints admission. It is authenticated by the **group MAC**,
like a signal and an anonymous post and for the same reason. The room is named
`SHA256("wac-call-room-v1" ‖ group_id ‖ call_id)`, so the media server learns neither which
conversation a room belongs to nor that two rooms belong to the same one. The participant identity
is derived from the call key, so members recognise each other while the media server sees an
opaque string that changes every call — and, being derived from a group key, it is recognisable
rather than unforgeable: a member can take another member's identity, the same forgery § 3.5
already documents.

The route answers **503** when the deployment holds no media credentials. Not 404: a missing route
invites a retry, a refused feature tells the client to hide the call button.

**What a call costs that a message does not.** This server sees that somebody is joining a call,
when, and towards which group; the media server sees who shares a room with whom, and for how
long. Sealed sender does not survive the media path — an RTP stream carries a stable identity for
the length of a call. See `docs/THREAT-MODEL.md` § 4ter.

---

## 4. Content framing

The MLS plaintext is an opaque byte string; deciding whether it holds text, an attachment
descriptor or a receipt is the application's job. `apps/web/src/lib/content.ts` does it with a
single leading type byte:

```
0  text            UTF-8
1  attachment      JSON descriptor: id, key, iv, name, mime, size
2  gossip          u32 BE size ‖ 32-byte root
3  posting key     32 bytes
4  receipt         u8 state ‖ u64 BE seq
5  reaction        u64 BE target ‖ UTF-8 emoji
6  reply           u64 BE target ‖ UTF-8 text
7  stamped         u64 BE milliseconds ‖ <any of the above>
8  profile         u64 BE milliseconds ‖ UTF-8 display name (≤ 64 bytes)
9  reserved        the friend system, not built
10 membership      u8 event ‖ UTF-8 account  (joined | removed | left)
11 handle          u64 BE milliseconds ‖ UTF-8 handle (≤ 32 bytes)
12 signals         12-byte nonce ‖ AES-256-GCM (u64 BE ms ‖ u8 bitfield ‖ UTF-8 JSON?)
```

Types 2, 3, 4, 8, 11 and 12 are **protocol traffic**: they ride the encrypted channel because that is
precisely what is wanted — a path the server carries without being able to read it — but they are
not messages. `isControl` names them in one place, so a new control type does not have to be
remembered on send *and* on receive.

An unknown type is refused rather than skipped. Those bytes were authenticated by MLS, so they do
come from a member, but a member can send anything; a lenient reading here would become an
interpretation difference between clients. One message fails to display and the thread carries on.

### 4.1 The stamp is a wrapper, and it is declared

Type 7 wraps another encoded content instead of adding eight bytes to each of the six layouts
above: one format to review rather than six, and whatever gains a type byte later is stamped
without touching it. Unwrapping is **one level deep** — a wrapper inside a wrapper is not
something a correct sender produces, and unwrapping recursively would let a member nest a few
thousand of them and spend the client's stack on it.

The time is **declared by the sender**. It travels inside the MLS message, so the server neither
learns it nor can alter it — and any member of the group can put whatever they like in their own.
It is an annotation on the thread, never its order: ordering stays `seq`, which the server assigns
and no member controls. In a 1-to-1 there is exactly one other person who could lie about it, and
they could equally lie in the text.

Type 8 carries its own time instead of being wrapped, which is what lets it be control traffic and
still be ordered — see §4.2. Control traffic is otherwise never stamped: it is not displayed, so
the eight bytes buy nothing. Neither is
anything written before type 7 existed. Both decode to a message with no time, and the client
shows an empty slot rather than a guess — dating a week-old message to "now" because it arrived
during a catch-up is a worse answer than none.

### 4.2 The display name is asserted, not established

An **account id** cannot change: it is the fingerprint of the account's genesis identity key, the
identity bytes inside the MLS credential, the subject of every attestation the account has signed,
and the prefix of each of its device ids. Type 8 is how an account puts a mutable, human name in
front of that anchor without touching it.

The **handle** used to be that anchor and no longer is — see §7.1. It is now a claim like the
display name, and travels the same way, as type 11.

It goes through MLS and nowhere else. A column on the server would be a cleartext object per
account, stored and served by the party the rest of this document assumes is hostile, and it would
turn the existing account-existence oracle into one that answers with a human name. It is equally
not in the credential: the credential **is** the identity binding, so a rename there would present
to every peer as a changed identity and raise the fingerprint banner.

The name is announced once per group per epoch, alongside gossip and the posting key. The epoch is
the right unit rather than the session because it moves when the roster does, so somebody who
joins later receives the name without anyone having to notice they arrived.

Like the stamp, the time is **declared by the sender**, and a member can date theirs far ahead to
pin their name against later updates. Receivers clamp it to their own clock plus a small skew
before applying last-writer-wins. What no clamp can fix is the claim itself: type 8 says that this
member calls themselves this, and nothing more. Two members can claim one name, and the one who
wants to be mistaken for somebody is the one who will. Clients therefore keep the handle on screen
beside the name, and fall back to the handle outright wherever there is no room for both.

### 4.3 The handle travels the same way, and for a sharper reason

Type 11 carries `u64 BE milliseconds ‖ UTF-8 handle`, with the same shape, the same clamp and the
same last-writer-wins as type 8.

It has to travel at all because the credential stopped carrying it. When the handle *was* the
credential's subject, every member of a group already held it, authenticated, without anyone
sending anything; the credential names an account id now, and a handle is a label nobody in the
room would otherwise know.

**It is not read back from the server**, and that restraint is the point rather than a preference.
The server holds the directory that maps handles to accounts and is free to lie in it. What stops
the lie from mattering is that an account id is checkable against key material inside the
credential — but a *handle* fetched at render time is checkable against nothing, and fetching it
would hand the server a fresh opportunity to say who somebody is on every screen, forever.

### 4.4 The settings and preferences travel too, and are sealed a second time

Type 12 has the shape of types 8 and 11 — control, self-ordered, last-writer-wins on a clamped
timestamp, for the reason those two give: `seq` is per conversation and these are per account, so
two rooms would disagree about which change came last. It differs in one respect, and the
difference is the whole design.

**The body is encrypted again, under a key only the sender's own devices hold.** That key is
`HKDF-SHA256(seed, "wac-device-sync-v1")`, derived like the vault key and independent of it. Peers
carry the message and cannot open it; they learn that *a* preference moved, never which.

That second seal is not decoration. The settings say whether an account emits read receipts and
typing indicators, and knowing that somebody turned their read receipts off is precisely the lever
the setting exists to remove — a peer who can see the switch can ask for it to be flipped back.

The reason it travels at all is that these settings are a property of the account and used to be a
property of the device. Acknowledgement runs per session, so an account that refused read receipts
on one device kept sending them from another, with nothing on screen saying so. There is no
server-side repair available: the server cannot see a receipt, which is the point of receipts
being ordinary envelopes under sealed sender, so it can enforce nothing about them. What it can do
is carry an opaque message between devices that already share every conversation.

`presence` rides along for the screen only. The server is what records presence, so
`accounts.presence_optout` remains the truth for it; the flag in this message keeps a second
device from *displaying* a switch its account has already flipped. A device restored from the
recovery phrase has no conversation and therefore no channel at all, which is why
`GET /v1/accounts/{account}/devices` returns `presence_optout` — to its owner and to nobody else.

### 4.5 The contact policy is enforced, not merely stored

`accounts.contact_policy` holds `open`, `known` or `closed`, set through `POST /v1/contact-policy`
by the signing device — never by naming an account, so nobody can close somebody else's door — and
read back on `GET /v1/accounts/{account}/devices`, to its owner alone.

It is applied in `add_members`, before any row is written. Being added to a group *is* a row in
`group_members`, so the server is the only party that can decline it. That is what separates this
from the local block list, which lets the envelope arrive and declines to read it.

**The refusal is deliberately indistinguishable.** A closed account answers `403` with the same
body a non-member already receives when it tries to add to a group it is not in. A reply naming
the reason would make the setting an oracle: anybody could learn anybody's policy by trying, which
is a fact about a person published by the mechanism meant to protect them.

**`known` means "already shares a group", and the group being created does not count.** The route
inserts the caller before the check runs, so counting the group under construction would find the
caller inside it and admit everybody — the setting would enforce nothing while appearing to work.
It also does not mean *verified*: that comparison happens out of band between two people and never
reaches the server, and teaching it would hand it a finer map of who trusts whom than it holds.

**An account always reaches its own devices**, whatever its policy. They are added to every
conversation on every poll, and a policy that applied to itself would break an account the moment
it paired a second device.

**It is not retroactive.** `closed` refuses new additions and removes nobody from a group they are
already in. No column could do otherwise: the membership that matters is the MLS tree, which this
server cannot read.

#### The rest of the preferences, appended

After the nine fixed bytes comes optional UTF-8 JSON, inside the same seal: the per-conversation
flags (pinned, archived, muted, ephemeral), the petnames, the blocks, and the two account-wide
switches for notification naming and the vault. Nothing after the head is a message from a device
running the older build — a valid message with no preferences in it, which is not the same as a
message asking to clear them.

**Each entry carries its own timestamp, and removals are stamped rather than merely absent.** That
is the part worth stating in a protocol document, because the obvious alternative is wrong in a way
nothing reports: one timestamp over a *map* means that blocking one person on a laptop and another
on a phone loses one of the two blocks, and that an unblock loses to the device that still holds
the block. The stamp map is therefore also the tombstone set — a key stamped and absent from the
values *is* the record of a removal — and it is persisted, because a tombstone lost at the next
start lets a third device re-assert what was removed.

What travels is a full snapshot, not a delta: a device that was off for a week is caught up by one
message rather than by a chain of them it never received. It is bounded at sixteen kilobytes and
refused rather than truncated past that, since half a preference set reads as a decision to clear
the half that fell off.

What deliberately does **not** travel: the interface language and the local search coverage, which
are facts about a machine rather than an account, and the recent-emoji list and skin tone, which
are account facts that change on nearly every message — syncing them would spend an envelope per
conversation on somebody reaching for a thumbs-up.

So the handle is believed exactly as much as a display name: a member may claim one they do not
hold. That buys them nothing the display name did not already offer, and the ambiguity rule above
applies unchanged. Uniqueness is a property the server enforces at registration, not a property a
client can verify at read time, and this document does not pretend otherwise. A member whose claim
has not arrived is shown the first 64 bits of their account id instead.

---

## 5. Padding

Content is encrypted; its **length** is not. Length alone separates "ok" from a sentence, spots a
pasted password, and recognises a boilerplate message. Over a sustained conversation the sequence
of lengths is a signature.

`apps/web/src/lib/padding.ts` pads each message body to a **doubling bucket starting at 256
bytes**: 256, 512, 1024, 2048, … The first bucket sits above the overwhelming majority of written
messages, so they all come out the same size. Doubling bounds the waste below 100 % and leaves the
server nothing but an order of magnitude.

The end of the real content is marked with **`0x80` followed by zeros** — ISO/IEC 7816-4. Padding
with zeros alone would be ambiguous: content legitimately ending in a zero byte would be
indistinguishable from its padding and would be truncated on removal. The marker resolves that for
one byte.

The marker is **always** appended, even when the body length already lands exactly on a bucket
boundary — otherwise removal could not tell whether the last byte belongs to the content. Concretely,
the bucket is chosen for `len(body) + 1`.

Removal raises on malformed padding rather than guessing. Those bytes were authenticated by MLS,
so they do come from a member — but a member can send anything, by mistake or on purpose, and a
lenient reading here would become an interpretation difference between clients.

Attachments go through the same buckets, applied to the plaintext before AES-GCM. Their ceiling is
the server's 25 MiB request limit, so the doubling stops at 16 MiB and everything above pads into
one final bucket sixteen bytes below the limit — the GCM tag — with the client's own maximum one
byte below that, for the marker. Above 16 MiB the padding therefore costs a great deal: a 17 MiB
file goes out as nearly 25. What the cap fails to hide is that it is the client's cap: the top
bucket identifies the version as much as it conceals the file.

---

## 6. Group roles

A group is an MLS group of more than two members; a 1-to-1 conversation stays **flat**, with no
roles, because a hierarchy there would mean nothing.

### 6.1 MLS provides no authorization

RFC 9420 describes who can *prove* what, not who is *allowed* to do what. Any member can commit
any add or removal and the protocol will accept it. "Only admins may remove" is an application
rule, and nothing in MLS enforces it.

### 6.2 The `0xF100` group context extension

The roster lives in a **group context extension**, type `0xF100`, inside RFC 9420's private-use
range `0xF000`–`0xFFFF`, so no standardised extension will ever collide with it. Being in the
group context means it is authenticated and hashed into every commit: all members agree on it by
construction, and an old roster cannot be replayed.

Putting the roster in an application message instead would have left it replayable and
unauthenticated — a member could rebroadcast an old roster in which they were admin.

The roster names **account ids**, not signature keys. An id covers every device of an account, so
adding a phone needs no roster change and an admin is admin from any of their devices. It is also
what the MLS credential already carries, so there is no extra binding to establish.

### 6.3 `RequiredCapabilities`

MLS requires every group context extension to appear in the group's required capabilities, and
here that constraint is useful rather than a formality: it stops a client that **cannot read the
roster** from joining an administered group. Without it, such a client would join, apply an empty
policy, accept commits the others refuse — and fork the group with nothing to signal it.

### 6.4 Admin and moderators

One admin, exactly one. Several admins of equal rank have no tie-breaker: two of them can demote
each other or contradict each other on the group's membership, and nothing in the protocol says
which is right. A single root removes the question.

| Operation | Who |
|---|---|
| Add or remove an ordinary member | admin, moderator |
| Remove a moderator | admin |
| Appoint, revoke, hand over | admin |
| Remove the admin | nobody |

No roster is **not** an empty roster: it means a flat group where everyone can do everything. That
covers 1-to-1 conversations and groups created before this extension existed.

Enforcement belongs to the clients. The policy is a pure function, tested in isolation, precisely
because every client must apply it identically: a client that accepts a commit the others refuse
produces no error, it produces a silent fork.

Removal takes an account with **all its devices**; the unit is never the device. Leaving is a
*request*, not a fact: RFC 9420 forbids removing yourself in a commit you generate, since that
commit is signed under the epoch secret it produces — the very epoch its sender has just been
excluded from. Another member must pick it up.

---

## 7. Device attestation

### 7.1 What an account signs over

An account is an Ed25519 identity key (AIK) derived from a twelve-word BIP-39 phrase. No phone
number and no email address anywhere.

**The account is named by that key, not by a handle.** Its id is `SHA256(genesis identity key)`
truncated to 16 bytes and written as 32 lowercase hexadecimal characters. The id is *derived*,
never assigned, and the difference carries the whole design: a server that mints ids can forge one,
reassign one, or serve two people two different answers about one name, while a server that merely
lists them can do none of those — the id is a hash of a key that is inside the credential the
verifier is already checking.

**Genesis and not current.** Rotation moves the identity key, so an id derived from the live key
would move with it. The anchor is the first key the account ever had; §7.3 describes the published
chain that ties it to whatever key is current.

The handle is an alias: unique among live handles, releasable, renameable, and **never re-issued**.
It matches `^[a-z0-9_]{3,32}$`, enforced by the server at registration and by a CHECK on the
column. Retiring rather than freeing a name is not tidiness: every stale reference to `@bob` — a
bookmark, a screenshot, a mention in a message written last year — would otherwise name whoever
claimed it next, and that is an impersonation nobody has to mount. It arrives on its own, on a
schedule the attacker picks by waiting.

What the format does not fix: `rn` still reads as `m`, and `_` is still a separator the eye skips.
It removes the wide classes of confusion, not the narrow ones.

Each device carries a signature by the account over `(account, device_id, auth_key, mls_key)`,
length-prefixed, under domain `wac-attest-v2`. Both keys are attested **together**, not
separately: separating them would let someone recombine one device's attested authentication key
with another device's MLS key.

The domains are at v2 because field zero used to be the handle and is now the id, and the two are
not distinguishable by shape — a thirty-two character handle is legal and reads as an id. The
version in the label exists for exactly this, and this is the first time it has been spent.

The client re-verifies every attestation on receipt. It never relies on the server's verification,
since the server is precisely what is under suspicion — server-side verification only rejects
early what is unusable anyway.

### 7.2 The asymmetry

The gain is one asymmetry, and it is the whole point: **the server can withhold a device, never
add one.**

Without attestations, a server composing the device list freely would only have to add a device it
controls to Bob's list to be invited into every conversation he has. No cryptography would be
broken — the message stays end-to-end encrypted, one of the ends simply happens to be the server.
That is the attack WhatsApp was accused of in 2019.

The test `a_ghost_device_injected_in_sql_does_not_pass_client_verification` embodies the attacker
rather than simulating one: it inserts the device straight into the database, bypassing the
endpoint. The server serves it; the client rejects it.

What remains is **omission**: the server can still leave a genuine device out of the list, or
withhold a genuine revocation. The victim notices that a device receives nothing — censorship,
noisy but real.

The displayed fingerprint is `SHA256(identity key)`, truncated to 16 bytes and grouped in
hex quads. It covers the account key alone, so it does **not** change when a correspondent adds a
phone. A fingerprint that changed on every legitimate event would be ignored within weeks; device
additions are signalled separately.

Device identifiers are qualified by the account id (`d52c15be…:desktop`) and the server enforces
that: otherwise the namespace would be global and the first arrival would seize "desktop" for
everyone. The prefix used to be the handle, which meant every device id an account ever issued was
tied to whatever it was called at the time — one of the reasons a handle could not be renamed.

The **displayed** short form of an id is its first 64 bits, grouped in quads. A truncated
fingerprint is grindable: an attacker generates account keys until the leading characters match
their target's. At 32 bits that is minutes on a laptop; at 64 it is out of reach of anyone
attacking a chat handle. The full 128 bits stay in the verification panel, and that panel — not the
inline form — is the proof.

### 7.3 Revocation and rotation

Revocation produces a **certificate signed by the account** under `wac-revoke-v2`, covering
`(account, device_id, revoked_at)`. The timestamp is inside the signed message, so the server cannot
backdate a genuine revocation to pretend a device was already excluded at the time of a message.

The certificate is not for the server, which already knows the account key: it is for the **other
group members**, who must be able to observe the revocation without trusting anyone and commit the
MLS removal accordingly. Without it, the server would regain the power to have devices of its
choosing evicted. Revoked devices are therefore **served** to clients, with their certificate —
hiding them would make revocation indistinguishable from omission, and omission is what the server
can still do.

Rotation changes the account identity key and is signed **by the outgoing key**, under
`wac-rotate-v2`, covering `(account, new_identity_key, rotated_at)`. Verifying against the new key
would only prove possession of it, that is, nothing. Its main effect is mechanical and free: every
existing attestation becomes unverifiable, because clients recompute them against the current key.
Total revocation is not a separate mechanism, it is a consequence.

The old-key signature proves *continuity*, not legitimacy. A thief holds the same seed and can
rotate first; the server cannot tell them apart and applies the first valid rotation.

**The chain is published**, and that is what makes an account id survive its own key changing.
Each log entry for an account carries the rotation signature that authorised it, so `GET
/v1/accounts/{account}/chain` serves every key the account has ever published, oldest first, with
the link that justifies each step. A client checks three things, all locally:

1. the first key fingerprints to the account id — **this is the anchor**, and it is what makes an
   id self-authenticating rather than something the directory asserts;
2. each later key is signed by the key before it, never by the anchor, since verifying everything
   against the first key would accept a chain whose middle was replaced;
3. each entry is in the log, by inclusion proof.

The signature is stored beside the leaf rather than inside it. The leaf commits to the account and
the key, and a signature is self-authenticating — serving the wrong one produces a chain that
fails to verify, which is the same outcome as serving none. What the server can still do is
**withhold** a link, and that is visible: a chain with a hole fails check 2 and the client reports
it rather than assuming continuity. Omission stays possible and stays detectable, which is the
asymmetry §7.2 is about, applied to keys instead of devices.

Without this, the gap was concrete rather than theoretical: an account id is computed from the
genesis key and does not move when the key rotates, so a server serving a rotation nobody signed
would have quietly handed the account to somebody else **under an id that still looked right**.

---

## 8. The transparency log

Attestations stop the server from adding a device. They do not stop it lying about the **account
key on first contact**: asking for someone's account for the first time gives nothing to compare
against. `crates/transparency` closes that gap.

### 8.1 RFC 6962 Merkle tree

Every published account key is appended to an append-only Merkle tree.

```
leaf_hash(contents) = SHA256(0x00 ‖ contents)
node_hash(l, r)     = SHA256(0x01 ‖ l ‖ r)
entry(account, key) = len‖account ‖ len‖key
```

**The `0x00` / `0x01` domain prefixes are not a formality.** Without leaf/node separation, the hash
of an internal node presents itself as a leaf hash — a **second-preimage attack** — and an attacker
forges an inclusion proof for the entry of their choosing. That is the part nobody guesses and
nobody should reinvent.

The tree is not padded up to a power of two; an isolated subtree is carried up as is. Padding with
empty leaves would make a 3-leaf tree and a 4-leaf tree whose last leaf is empty share the same
root. Entry contents are length-prefixed as in `attest`, for the same reason: without prefixes,
`("ab", key)` and `("a", "b"‖key)` produce the same leaf.

### 8.2 The signed tree head

```
STH message = "wac-sth-v1" ‖ size (u64 BE) ‖ root (32 bytes) ‖ timestamp (u64 BE)
```

The timestamp is inside the signed message: without it, an old head could be replayed forever to
hide the appends that followed. The domain is distinct from `attest`'s, so a head signature holds
in no other context.

### 8.3 The three checks

The client verifies three things, and it takes all three:

1. **Head signature** — the head really comes from the log.
2. **Inclusion** — the key served is the one in the log, with the leaf recomputed from the account
   and the key actually received, never from a hash supplied by the server.
3. **Consistency** — today's log extends the one seen yesterday.

Without the third, the server replaces an already-published key and serves a log that is just as
internally consistent: the first two checks pass and the log proves nothing about the past. The
test `a_rewritten_log_does_not_pass_consistency` pins it down.

### 8.4 Gossip

None of the three checks catches a server keeping **two logs** and serving one to each victim:
each sees a signed, consistent log in which their own view is perfect.

Detecting that needs two views compared over a channel the server does not control — and that
channel already exists: **the encrypted conversation**. The server carries its bytes without being
able to read or alter them.

The comparison does not confront roots, which legitimately differ because the sizes differ. The
recipient asks the server to **prove that its log extends the one served to the other party**. If
it has served two, no consistency proof relates two trees that have forked.

### 8.5 The structural weakness

The log is signed by the party it watches. A serious deployment would hand it to one or more
distinct operators, none of which is the messaging server. Here there is a single process, and
gossip is what partially compensates — it does not erase the defect.

The log's public key is itself served by the server, an acknowledged stopgap. It should ship with
the application. The client at least refuses to let it change afterwards.

---

## 9. The gateway

`GET /v1/gateway` (WebSocket), in `crates/server/src/gateway.rs`, replaces the 1.5-second poll and
the SSE stream before it. A 30-second poll remains for upkeep that has no triggering event.

Counter-intuitively this **removes** information from the server: it used to receive a signed
request per conversation per round, that is, an activity log accurate to the second. A long
connection replaces that with a single observation point, at open time.

### 9.1 The handshake challenge

The browser's `WebSocket` API accepts no custom header — the same limit `EventSource` had.
Authenticating the handshake would mean putting the signature in the URL, where it lands in the
access logs of every intermediary. So the socket opens **without identity**, and nothing is served
before the challenge.

1. Server sends `hello` with a 32-byte random challenge (base64) and `heartbeat_ms`.
2. Client answers with `identify`: `device_id`, the echoed `nonce`, an Ed25519 signature over
   `"wac-gateway-v1" ‖ len‖device_id ‖ len‖nonce`, and its cursors.
3. Server answers `ready` with the list of groups it subscribed the session to.

The device identifier is inside the signed message: without it, a challenge served to Alice could
be returned with Bob's signature captured elsewhere.

The challenge is issued by the server and consumed on first use, so the sixty-second replay window
that HTTP keeps does not exist on this path. The client has `IDENTIFY_MAX` = 10 seconds to answer.

### 9.2 Frames

Client frames (`op` field, snake_case):

| Frame | Fields |
|---|---|
| `identify` | `device_id`, `nonce`, `signature`, `cursors[]` (`group_id`, `seq`) |
| `subscribe` | `group_id` |
| `unsubscribe` | `group_id` |
| `heartbeat` | — |
| `signal` | `group_id`, `nonce`, `mac`, `payload` |

Server frames:

| Frame | Fields |
|---|---|
| `hello` | `heartbeat_ms`, `nonce` |
| `ready` | `groups[]` |
| `envelope` | `group_id`, `seq` |
| `gap` | `group_id`, `oldest` |
| `signal` | `group_id`, `payload` |
| `heartbeat_ack` | — |
| `error` | `reason` |

`deny_unknown_fields` is deliberately **not** set on client frames: a client newer than the server
must be able to add a field without the session being refused. An unknown field is ignored, never
interpreted.

Error reasons are deliberately coarse (`invalid frame`, `denied`, `conflict`, `too many
requests`, `internal error`), for the same reason `ApiError` refuses to distinguish "unknown
device" from "invalid signature": the distinction would turn the gateway into an enumeration
oracle. Detail goes to the server traces, not onto the wire.

The `signal` frame is authenticated by the **group MAC**, not by the session. The session knows its
owner's identity, as it happens — using it would undo sealed sender for the sole convenience of not
rechecking a MAC.

### 9.3 Bounds

| Bound | Value | Why |
|---|---|---|
| `MAX_FRAME_BYTES` | 64 KiB | applies **before** authentication; tungstenite's default is 64 MiB per message, which an unauthenticated peer could allocate repeatedly |
| `MAX_SUBSCRIPTIONS` | 512 | each subscription is a broadcast receiver with a queue |
| `MAX_CURSORS` | 512 | without it, one frame buys as many SQL queries as it has entries — amplification, not access, is the problem |
| `MAX_RESUME_PER_GROUP` | 200 | aligned on the HTTP path's pagination |
| `MAX_SIGNAL_BYTES` | 4096 | the largest thing the protocol carries in a frame |

### 9.4 Heartbeats and revalidation

`HEARTBEAT` is 30 seconds, announced in `hello`. `SILENCE_MAX` is 80 seconds — two heartbeats plus
a margin, so a client that loses one on a network switch is not disconnected for it.

Authentication moves from **per request** to **per session**, and that cuts both ways. A signature
per request revalidated for free, on every call, that the device was neither revoked nor evicted.
An open session would survive both. Hence `Session::revalidate`, which runs on every heartbeat: it
closes the socket of a revoked device and drops the groups it has left. A revocation therefore
takes effect on open sessions within at most two heartbeats. Two tests pin this down.

### 9.5 Cursors, and why the session is never load-bearing

The session is **never** a correctness dependency. Every frame says no more than "go look"; the
normal poll is what reads, rechecks membership and advances the cursor. A browser that blocks the
connection leaves the application entirely functional, only less responsive. A transport whose
failure lost messages would be a transport built on top of the transport.

An `envelope` frame carries only the sequence number. The client fetches the envelope by the
normal HTTP path, which rechecks its membership and applies pagination — duplicating that path
here would have duplicated its access control, and it is the forgotten copy that becomes the hole.

At open time the client announces its cursors in `identify` and the server replies only if it has
something to say. Catch-up serves sequence numbers only — and, when the cursor has fallen behind
what the group still holds, a `gap` frame first. See § 10.

### 9.6 Presence and multi-instance fan-out

`devices.last_seen_at` is written by the gateway heartbeat, and only from identity-authenticated
paths — never from an anonymous post, which the server cannot attribute anyway. It is truncated to
the minute and overwritten, with no history. Only the **maximum per account** is served to third
parties, and only to someone sharing a group.

Reading presence deliberately does not go through the session: the green dot would then depend on
it, and a blocked socket would show everyone offline. A wrong interface is worse than a late one.

Across instances, the broadcast hub speaks over Postgres `LISTEN/NOTIFY` on a single channel. The
`group_id` travels in the clear in the payload, which the server already knows from
`group_members` — so this adds nothing to what it knows. What it does add: a deployment set to
`log_statement = all` would see signals in its logs. "Signals never reach the disk" therefore now
depends on a database setting rather than being true by construction.

---

## 10. Retention, and the gap it can open

The server deletes an envelope when **both** conditions hold:

```
created_at < now() - 30 days   AND   seq <= groups.next_seq - 500
```

The conjunction is the design, not a tuning. Age alone empties a quiet conversation — three
hundred messages over two years, weighing nothing, gone. The tail alone evicts a device away for
two hours from a talkative group. Together, **no conversation shorter than 500 envelopes is ever
touched, at any age**, and losing anything takes being both a month and five hundred messages
behind.

Attachments go by age alone, at **90 days** — longer than envelopes, because a message restored
from the vault carries its attachment descriptor and stays resolvable for a while after the
envelope that delivered it is gone. Past three months the file is no longer downloadable, and
keeping it is the recipient's business.

A group with no member and no envelope younger than 30 days is deleted outright, and the
`ON DELETE CASCADE` takes its mailbox with it.

There are **no server-side delivery cursors**, and there will not be: a
`delivery_cursors(group_id, device_id, seq)` table would be a movement journal — when each person
last collected their mail, per conversation — which is precisely what the presence design refuses.
It would also bound nothing, since `MIN(cursor)` is pinned by the one device that never comes
back, so an age floor would be needed on top of it anyway.

### 10.1 `oldest`, and why the fetch response changed shape

`GET /v1/groups/{id}/envelopes` no longer returns a bare array. It returns:

```json
{ "oldest": 1204, "envelopes": [ { "seq": 1204, "payload": "…" } ] }
```

`oldest` is the smallest sequence the group still holds, or `next_seq + 1` when it holds none —
so a brand new group reports `1`, and a client at cursor `0` correctly concludes it has missed
nothing.

The client's rule is one line:

```
cursor < oldest - 1   ⟹   the envelopes in between no longer exist
```

Without this field an empty page means either "nothing new" or "everything you had not read is
gone", and a client reading it as the first waits forever on a ratchet that can never advance.
This is an unversioned breaking change to the response body, taken deliberately rather than added
as an optional sibling field: an optional field is one a client can keep ignoring, and ignoring
this one is exactly the failure being fixed.

The gateway says the same thing with the `gap` frame, emitted during catch-up **before** that
group's `envelope` frames — a client reading frames in order must learn its history is broken
before it is handed numbers to fetch.

### 10.2 What a gap actually costs

Not the history: the content is in the vault, which is on by default. **The MLS state.** A missing
envelope is a missing generation of the application ratchet, and nothing after it decrypts. A
device on the wrong side of a purge must therefore stop trying to decrypt — otherwise it produces
one error per envelope, on every poll, forever — restore what it can read from the vault, and ask
to be re-introduced to the group. If the vault is disabled, the content is gone.

---

## 11. The recovery escrow

**Off by default.** Enabling it is the one action in this protocol that puts the account root
secret on the server. `docs/THREAT-MODEL.md` § 2.2.2 states what that costs; this section states
what travels. The design argument is in
[`./specs/2026-08-22-recovery-escrow.md`](./specs/2026-08-22-recovery-escrow.md).

### 11.1 Derivation

One expensive step yields two independent keys — one names the row on the server, the other opens
it. Independence comes from the `info` labels, exactly as it does for the vault and device-sync
keys in `crypto-core/src/account.rs`.

```
password  salt   = SHA-256("wac-escrow-salt-v1" ‖ handle)
          okm    = Argon2id(password, salt, m = 256 MiB, t = 4, p = 1)  → 64 bytes
          lookup = HKDF-SHA256(okm, info = "wac-escrow-lookup-v1")      → 32 bytes
          seal   = HKDF-SHA256(okm, info = "wac-escrow-seal-v1")        → 32 bytes

passkey   prf    = WebAuthn PRF over the constant salt "wac-escrow-prf-v1" → 32 bytes
          lookup = HKDF-SHA256(prf, info = "wac-escrow-lookup-v1")
          seal   = HKDF-SHA256(prf, info = "wac-escrow-seal-v1")
```

**The Argon2id salt is derived from the handle and not drawn at random.** It cannot be random:
reading the stored parameters requires the lookup key, and computing the lookup key requires the
salt. A per-handle salt is unique per account, so no one table covers two users — and it is
precomputable against a *named* target, which the memory cost is what answers. The cost parameters
are client constants for the same circular reason; the stored copy exists so a later build
recognises an older escrow, is checked against a floor, and is inside the AAD.

**What the server receives is `SHA-256(lookup)`.** The pre-image never leaves the client.

### 11.2 The sealed object

```
sealed = nonce(12) ‖ AES-256-GCM(seal_key, nonce, seed(64), aad)          → 92 bytes, always
aad    = account_id ‖ 0x00 ‖ kind(1) ‖ params(13)
params = version(1) ‖ memory_kib(4) ‖ iterations(4) ‖ lanes(4)            big-endian
kind   = 0x01 password | 0x02 passkey
```

The plaintext is exactly what the pairing packet carries: `Account::export_seed`, 64 bytes, worth
the whole account.

The AAD is what makes three substitutions fail loudly instead of quietly. The account id stops a
server serving one account's ciphertext under another's lookup — which is also why the client
verifies nothing after opening: reaching that point already proves the id and the seed were sealed
together. The kind stops a passkey escrow being presented as a password one. The parameters stop a
downgrade.

The length is fixed and checked server-side. A caller-chosen length on the one table an
unauthenticated route reads back would be a storage channel.

### 11.3 The routes

| Route | Authentication | Effect |
|---|---|---|
| `POST /v1/recovery` | signed | Deposits or replaces one factor for the signing device's account |
| `GET /v1/recovery` | signed | Lists the kinds in use. **Never the ciphertext** |
| `POST /v1/recovery/forget` | signed | Removes one factor; removing an absent one succeeds |
| `POST /v1/recovery/claim` | **none** | `{lookup}` → the escrow, or 404 |

`claim` is `POST` so the lookup — a value derived from the password — stays out of every access
log between the client and the server. Same reasoning as `presence` in § 1.

**A wrong secret and an account with no escrow return the identical 404.** The server holds a hash
and compares it; it cannot tell them apart, and neither may the copy shown to the user.

### 11.4 Two destructions the protocol requires

**A rotation deletes every escrow of the account**, in the transaction that moves the identity
key. Rotation is the answer to a stolen device and a stolen device holds the seed; an escrow left
behind is the abandoned key still on the server, openable by a password the thief may have
watched being typed.

**A rename deletes the password escrow.** The handle is the salt, so after a rename the owner's
own password produces a different lookup: the row would never open again while remaining
grindable by whoever took the database. Re-sealing is impossible — it needs the password, which no
session holds. The passkey factor is unaffected; nothing in its derivation knows the handle.
