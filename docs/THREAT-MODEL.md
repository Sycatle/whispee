# Threat model

This document says what Whispee protects, who it protects it from, and — at equal length — what it
does not protect and cannot. It is for anyone deciding whether to trust this software with
something, and for anyone reviewing the design.

The short answer to that decision is: **do not**. Whispee is a learning and demonstration project.
It has had no external audit and will not get one. An E2EE protocol that is correct on paper fails
in practice on details only an audit finds. For communications that actually matter, use Signal.

For the wire-level mechanisms named here, see [`./PROTOCOL.md`](./PROTOCOL.md). For what each
mechanism is claimed to achieve, see [`./SECURITY-PROPERTIES.md`](./SECURITY-PROPERTIES.md).

---

## 1. Assets

What the design actually tries to keep:

| Asset | Where it lives |
|---|---|
| **Message content** | encrypted under the MLS application ratchet, decrypted only on member devices |
| **Attachment content** | encrypted client-side under a per-file AES-256-GCM key; the key travels inside the MLS message |
| **Account identity key (AIK)** | derived from a twelve-word BIP-39 phrase; every device of the account holds the seed |
| **Device authentication key** | non-extractable in IndexedDB on the web; signs every HTTP request |
| **MLS signature and group state** | per device, in the local store, encrypted at rest behind the local lock |
| **Recovery phrase** | a restoration path, and — since the history vault is on by default — the key to all archived history |
| **Recovery escrow** | **opt-in, off by default.** The account seed, sealed under a password or a WebAuthn PRF secret, *on the server*. The one asset in this table the server holds a copy of. See § 2.2.2 |
| **Group membership decisions** | who is in a group, and who may change that |
| **The truth about which devices belong to an account** | attestations, signed by the account, verified by every client |

What the design **does not** try to keep secret, and says so up front: which accounts are in which
group, when a post happens, and from which IP address.

---

## 2. Adversaries

### 2.1 A passive network observer

Someone reading the wire between a client and the server, without controlling either.

**Cannot**: read message content or attachment content; read the MLS handshake payloads; learn
message lengths beyond the padding bucket (§ padding: doubling buckets from 256 bytes); read
typing indicators, which are encrypted under the epoch export secret.

**Can**: see that a given IP talks to the server, and when; see the size class of each envelope;
see the rhythm of a conversation. Transport is TLS in any real deployment, so most of the rest
reduces to what the server sees — which is the next adversary.

### 2.2 The server operator, honest-but-curious

Runs the delivery service as written, keeps everything it observes, and reads it later.

**Cannot**: decrypt any envelope — it is a blind mailbox routing opaque blobs, and it holds no
MLS secret. Cannot decrypt attachments, whose per-file keys never take the server path. Cannot
learn message lengths beyond the bucket. Cannot learn who posted an envelope: sealed sender
authenticates *membership*, not identity. Cannot read the ephemeral signal payloads.

**Can**, and this is the honest list:

- **`group_members`** — it knows who talks with whom. Same trade-off as WhatsApp; avoiding it
  needs zero-knowledge credentials (Signal's Private Group System).
- **`devices.last_seen_at`** — the last activity of each device, to the minute. This is *the*
  cross-conversation register the rest of the schema refuses to keep, and it is kept deliberately.
  See §2.2.1.
- **timing and IP** of every post, and the target group of every post.
- **the MLS ratchet tree**, which the Welcome carries and which is public by construction: it
  contains the credentials, hence the members' names. Pinned by
  `the_welcome_exposes_identities_but_never_the_content`. The server already knows those identities
  from `devices` and `group_members`, so the leak adds nothing to what it knows — but it is real.
- **vault volume** — how many messages each account archives, and when.
- **the recovery escrow of any account that set one up**, and with it the ability to attack that
  account's recovery password offline. See § 2.2.2 — this is the only entry in this list that is
  not a metadata leak but a copy of a secret, and it exists only where a user asked for it.
- **attachment sizes**, to an order of magnitude: they now go into the same doubling buckets as
  messages, with a top bucket just under the server's 25 MiB ceiling.
- `created_at` on envelopes, which the retention purge now reads. It was kept for years for a purge
  that was never performed; it is finally the column it claimed to be, and it leaks exactly what it
  always leaked — the wall-clock time of every post, which the server observes as the request
  arrives anyway.

#### 2.2.1 What bounds the presence register

The register is a choice, not a drift, and Signal still refuses to keep one — there is no parity to
claim here, only an owned trade-off and its price. What bounds it:

- the column is per device but **never served per device to a third party**: only the maximum per
  account leaves. Serving the detail would say how many devices someone owns and which one they use
  at what hour — a distinct leak from "online". The owner does see their own devices, which is what
  makes a lost device that still checks in visible;
- it is written only from **identity-authenticated** paths. An anonymous post or a typing signal
  never touches it: the server does not know who posted, and inferring it would undo sealed sender.
  `an_anonymous_post_never_updates_presence` exists so it stays that way — the protection is one
  line;
- reading requires a **shared group**. Without that clause the route would be an activity oracle on
  any handle. An unknown handle and a handle with no shared group return the same thing, or it
  would also be an account-existence oracle;
- a **revoked** device stops counting;
- the setting **cuts at the source**: refusing presence stops the recording and erases what was
  noted, rather than filtering at read time. It is reciprocal, like read receipts — no longer
  broadcasting your presence also means no longer seeing others', or it would let someone see
  without being seen.

#### 2.2.2 What a recovery escrow hands the operator

Without one — which is the default — the account seed has **never been on this server in any
form**. The phrase is generated on a device, shown once, and never transmitted. An operator with
the whole database holds unreadable envelopes and public keys, and no path to an account.

A user who enables the password factor changes that for their own account, knowingly. The server
then holds `AES-256-GCM(seed)` under `Argon2id(password, salt = SHA-256(domain ‖ handle),
256 MiB, t=4)`. The operator can attack that password **offline**: no rate limit, no clock, no
need to touch the user's hardware. Winning yields the account seed, hence the account, hence —
since `wac-vault-v1` derives from the same seed — every row of that account's `vault_entries`,
retroactively.

Argon2id's memory cost is what stands in the way, and it is a factor rather than a barrier. The
online route is bounded at three attempts a minute per address (`throttle::Recovery`) and that
bound is irrelevant to this adversary, who never calls it.

**The passkey factor does not carry this.** Its key is 32 uniform bytes from an authenticator, so
there is nothing to grind; a stolen database yields nothing about it. Its cost is elsewhere: it is
bound to the deployment's origin and it dies with an authenticator that does not sync.

Three properties bound the feature rather than the adversary, and are stated because they are easy
to assume and wrong:

- **An escrow cannot be enumerated.** The row is named by `SHA-256` of a key from the same
  expensive derivation, so a wrong password and an account with no escrow return the same 404.
  The operator reading the table still sees which accounts have one — this closes the *network*
  oracle, not the database.
- **Nothing locks after N attempts.** A failed lookup names no account, so there is nothing to
  lock. That is the price of the previous property.
- **A rotation destroys the escrow, and a rename destroys the password one.** The first because
  the sealed seed is the one being rotated away from; the second because the handle is the salt.
  Both are enforced rather than documented — see `docs/specs/2026-08-22-recovery-escrow.md`.

### 2.3 The server operator, malicious

Same position, now actively lying, withholding, injecting and delaying.

**Cannot**:

- **add a device to an account.** Attestations are signed by the account key the server does not
  hold. `a_ghost_device_injected_in_sql_does_not_pass_client_verification` inserts a device
  straight into SQL, bypassing the endpoint: the server serves it, the client rejects it.
- **invent a revocation.** Revocation certificates are signed by the account too.
- **rewrite the transparency log.** Consistency proofs catch it —
  `a_rewritten_log_does_not_pass_consistency`.
- **produce a valid MLS message.** It can inject noise into a group (it holds the posting key) but
  nothing it writes will decrypt.
- **read anything by joining.** Adding itself as a member requires an attestation it cannot forge.

**Can**:

- **omit.** Leave a genuine device out of a list, or withhold a genuine revocation. The victim
  notices a device receiving nothing: censorship, noisy but real.
- **lie on first contact**, if the client does not check the log — which is exactly why the log
  exists — and, even with the log, **fork it**: keep two logs and serve one to each party. Each
  sees a signed, consistent log where their own view is perfect. Only gossip over the encrypted
  conversation catches that, and gossip requires that the two parties actually converse.
- **serve the log's own public key**, since that key is not shipped with the application. On a very
  first contact with a malicious server, there is nothing to compare it against. The client at
  least refuses to let it change afterwards.
- **delay a removal commit**, which lets the excluded device keep reading what was encrypted in the
  meantime. The server-side membership filter narrows the window without closing it.
- **serve hostile JavaScript**, on the web target, on every load. No browser policy fixes that —
  which is what the desktop application, with its interface inside the signed binary, exists for.
  What the web target has instead is a published, attested manifest of the bundle's hashes, which
  makes a substitution **detectable by whoever checks** rather than impossible. See §4quinquies for
  what that is worth and what it is not.
- **choose whom to wake**, wherever push is configured. See §4.
- **keep an envelope forever.** There is no purge, and no proof of deletion for anything.

### 2.4 Another group member

Someone legitimately inside the group.

**Cannot**: read a conversation they are not in; decrypt anything after being removed — the removal
commit re-keys the tree, and `a_removed_member_no_longer_decrypts_what_follows` freezes it, with the
removed member keeping *all* their group state and still failing on the next message; read others'
history vaults, each of which is encrypted under its own account's key.

**Can**:

- **forge a typing signal attributed to someone else.** The ephemeral channel is encrypted under a
  symmetric group key, so any member can produce a signal that appears to come from another.
  Harmless with two members, where there is only one other.
- **fork the group** if their client applies the role policy differently. MLS enforces no
  authorization; the clients do. `RequiredCapabilities` keeps out a client that cannot read the
  `0xF100` roster extension — it does not keep out one that reads it wrongly.
- **see everything said in the group while a member**, obviously, and keep it — **including past
  the conversation's lifetime**. Disappearing messages are deleted by each client on its own
  honour; a modified client keeps what it likes, and screenshots exist. The lifetime is agreed on
  in the group context, not enforced by it.
- **change how long the room remembers**, if they are the admin or a moderator. That is the
  intended rank and it is stated in `docs/PROTOCOL.md` §6.4; what it means here is that a
  moderator can shorten a conversation's memory without the admin, and that everybody sees the
  notice in the thread when they do.

### 2.5 Someone holding the unlocked device

**Out of scope by nature.** A compromised endpoint reads decrypted messages. Nothing in this design
addresses that, and claiming otherwise would be the dishonest part.

Concretely, they hold the seed — every device of an account holds it, which is the condition for
device parity — and therefore hold the account. They can attest a new device, revoke others, and
rotate the account key. Revocation alone does not answer a theft: the thief attests a fresh device
within the second. Rotation does, and it is a **race** the server cannot arbitrate — it applies the
first valid rotation. The only recourse on the other side is the fingerprint-change alert, which is
one more reason never to make that alert routine.

### 2.6 Someone holding the locked device

The local lock (Argon2id, 64 MiB, 3 passes) encrypts local state at rest on **this device**, and
nothing else. Against an attacker who has the device but not the password, the master key exists
only in memory of a running unlocked session — so a device that has been closed holds ciphertext.

**Can still**: attack the password offline, bounded only by Argon2id's cost and the password's
actual guessability. Passwords are now scored by zxcvbn against the common breach corpus, so that
attack starts from a real estimate rather than an optimistic bit count. A locked session re-locks
after five minutes without the user, in the foreground as well as in the background — but
re-locking drops the interface's state, not the key: it stays in the WebAssembly module's memory
until the tab closes.

The lock is **not a recovery factor**: forgetting it loses nothing permanently, since the phrase
still restores the account. Making it a second vault factor would double the loss surface for no
gain against a server that never sees it.

That last clause is exactly what a recovery escrow gives up, and it is why the two are separate
mechanisms with separate passwords and separate floors rather than one password doing both jobs.
The lock's password guards one device's disk against somebody holding that disk; an escrow
password guards a ciphertext the server holds, against somebody who never has to leave their
chair. Sharing a secret between the two would silently promote the weaker requirement.

---

## 3. Explicitly out of scope

- **A compromised endpoint.** An unlocked device reads the messages. There is no answer to this
  here and there is not going to be one.
- **A compromised account seed.** A device added by an account whose phrase leaked is duly
  attested, hence indistinguishable from a legitimate addition. The application signals the
  addition; only the user can say whether they own that device.
- **Traffic analysis by a global observer.** Hiding the rhythm and the endpoints would need a
  third-party relay and cover traffic. Neither exists here.
- **Post-quantum adversaries.** No PQXDH, no PQ ratchet.
- **Availability.** The server can refuse service, drop envelopes, or vanish. Nothing here defends
  against that; envelope loss is detectable through the sequence numbers, not preventable.
- **Contact discovery.** There is none, deliberately: no phone number and no email address
  anywhere. Discovery by number is the most toxic part of a messaging system — even hashed, the
  number space is enumerable in hours.
- **Impersonation by display name.** A display name is asserted by the account it describes and
  arrives over MLS: the group learns which member sent it, and nothing else. Anybody can call
  themselves Charlie, and the person who wants to be mistaken for Charlie is the one who will.
  Three things bound the damage rather than remove it — the handle stays on screen beside the
  name; the two surfaces with no room for both, a bubble author and a notification, drop the name
  entirely when two members of a conversation would render alike or when a name is another
  member's handle; and a local nickname, which no peer or server can influence, overrules the
  claim outright. None of that stops a convincing lookalike: `Charlle` is not `Charlie`, and no
  string comparison is going to say so. The handle underneath is the defence, and past it the
  fingerprint.

  The canonical handle format, `^[a-z0-9_]{3,32}$`, removes the wide classes — mixed case,
  bidirectional overrides, whitespace, non-ASCII homoglyphs — and closes the ambiguity that let a
  handle containing `:` split a device id. It leaves the narrow ones alone: `rn` still reads as
  `m`, and `_` is still a separator nobody looks at.

- **Impersonation by handle.** The handle used to be the account: it was the subject of the MLS
  credential, so every member of a room held it authenticated and nobody could claim somebody
  else's. It is an alias now, and it arrives the way a display name does — a claim by its owner,
  over MLS. **A member can therefore claim a handle they do not hold**, and this client cannot
  check that, because checking means asking the directory at render time, which is the one power
  the account-id design exists to take away from the server.

  What bounds it: the account id underneath is authenticated by the credential and is what every
  comparison in the protocol uses, so a false claim changes nothing about who can read what, who
  administers a group, or which devices belong to whom. Two members claiming one handle collapse
  to their ids on screen by the same ambiguity rule as two display names. And a handle is never
  re-issued once released, which removes the version of this attack that needs no lie at all —
  waiting for somebody to give a name up and then taking it.

  What it does not bound: somebody who has never seen the real `@charlie` has nothing to compare a
  claim against. That is first contact, and it is the same leap of faith it always was; the
  fingerprint is still the answer.

- **A lying directory.** `GET /v1/handles/{handle}` maps a name to an account, and the server may
  answer with somebody else's id, answer late, or refuse. This is deliberately survivable rather
  than prevented: the id it returns is a hash of a key that is inside the credential the client is
  about to verify, so a wrong id does not become a verifying one. The worst it achieves is sending
  somebody to the wrong account at first contact — the failure the product already has, and
  already answers with an out-of-band fingerprint comparison.

  The property that makes this bounded is that ids are **derived, never assigned**. A server that
  minted them could tell Alice and Carol two different things about one name and leave nothing to
  compare; here there is nothing to compare because there is nothing to disagree about.

- **A truncated account id.** Inline, an account shows the first 64 bits of its id. A truncated
  fingerprint is grindable: an attacker generates account keys until the leading characters of
  theirs match their target's. At 32 bits that is minutes on a laptop, which is why the inline form
  is not 32 bits. At 64 it costs on the order of `2^64` key generations to hit a chosen target,
  which is out of reach of anybody attacking a chat handle. The full 128 bits are in the
  verification panel, and **that panel is the proof** — the inline form is a convenience.

- **Two tabs of one account.** Not an attack, and worth a row anyway, because the loss it caused
  was silent and permanent. Each tab holds its own copy of the MLS ratchet in memory and persists
  over the other; decrypting an application message *consumes* the key for its generation, so once
  the surviving state has passed an envelope the other tab read, that envelope can never be read
  again. The client logs a skip and the message is gone.

  A tab now claims an exclusive Web Lock before reading anything, and the second one is stopped at
  a screen rather than allowed to run behind a warning. The lock is released by the browser when
  the tab dies, which is why it was preferred to an election or a heartbeat — both of which answer
  "what if the holder vanished" with a timeout that is either too short to be safe or too long to
  be usable.

  It **fails open**: a browser with no lock manager runs unguarded. Refusing to start a messenger
  because a lock could not be taken is a worse failure than the one being prevented, and it would
  be triggered by the environment rather than by anything the user did.

- **Legal compulsion of the operator.** It changes what the operator does, not what it can do; the
  "malicious server" row already covers the capability.
- **Supply chain below the source.** Reproducible builds cover the binary against the published
  source; they say nothing about `rustc`, the crates, or the operating system.
- **Supply chain in the interface.** The client went from seven production dependencies and none
  for the interface to roughly fifty, when Radix, CVA and Lucide were adopted for the shell. On a
  page that runs the user's cryptography, any one of them could read a key out of memory, and the
  same reproducible-build argument that covers the Rust side covers none of it: `pnpm-lock.yaml`
  pins what was installed, not what it does.

  The trade was made deliberately and it is worth stating both halves. What was bought is the
  accessibility work nobody here would have written correctly — focus traps, focus restoration,
  `inert`, collision-aware positioning, `role="switch"` — every one of which the hand-written
  version had got wrong. What was sold is a smaller surface to audit. A project that took this
  seriously at scale would vendor these packages and review them; this one has not.

---

## 4. Push notifications degrade sealed sender

This is the one property the project knowingly trades away. The mobile execution plan recorded the
decision and said it belonged in the documentation; it was never written down. It is written here.

Push **works, over Web Push, and only there**. A browser subscribes from the settings screen, the
server signs a VAPID token per push service and sends an empty wake-up, and a service worker shows
a notification with the tab closed. There is no FCM and no APNs provider, so the packaged mobile
application is still only notified while it is open.

It is off until a deployment sets `VAPID_SUBJECT`. Unset — which is the default, and the state of
every deployment that has not decided otherwise — `Silent` is the waker, it wakes nobody, and the
route serving the subscription key answers 503 so the client hides the control. That is not a
degraded mode: a deployment that talks to no push service keeps a fully working messenger.

The degradation is not caused by the tokens. It is caused by the feature's **existence**:

> A server that chooses *whom* to wake gains a targeted activity trigger. Ceasing to wake four
> members out of five makes the following posts attributable to the fifth. Sealed sender protects
> against a server that **observes**; it does not protect against a server that **paces**. No
> cryptography answers this.

That is the price of the feature. It is also why the feature is strictly optional and inert without
configuration: a self-hosted deployment that talks to no push service must stay fully functional,
and does.

**Turning it on is the user's decision as well as the operator's**, and the settings screen states
both halves of the cost — the push service learning the rhythm, and this server learning whom to
wake — above the switch rather than under it.

Three further limits follow from push, and hold whenever it is configured:

- **the third party learns the rhythm.** For a closed browser to learn a message is waiting, its
  vendor's push service — Google for Chrome, Mozilla for Firefox — must wake it, and can tie that
  browser to an address. The content stays encrypted; the activity metadata leaks, and that is
  irreducible, not a defect;
- **the wake-up carries nothing** — no text, no sender, no group id, because putting the message in
  the notification would show it to the provider *and* to the lock screen. Over Web Push that is
  not only a policy: with no payload there is nothing to encrypt, so the whole of RFC 8291 is
  unused and the subscription's own secrets are never read. `tests/webpush.rs` asserts the empty
  body at the wire;
- **the notification says only that something arrived.** The service worker cannot decrypt: the MLS
  keys are in the page's memory, not the worker's, and moving them there would hand the decryption
  keys to a context that outlives every tab. On iOS the same holds for a different reason — the
  service extension is a separate Swift process — and fixing that would require porting the crypto
  to native.

---

## 4bis. Local notifications are not push

Push is the feature §4 argues against, and the reason is the server: one that chooses *whom* to
wake gains a targeted activity trigger. A local notification has no server in it at all. The page
raises it about an envelope it has already decrypted, nobody is asked, and nobody learns one was
raised. It costs the threat model nothing.

What it buys is smaller in exact proportion: it fires only while the page is running. A closed
tab, a killed process or a sleeping phone produces nothing, and no client-side work changes that.
The honest statement is "you find out sooner while the application is open", not "you find out".

That gap is what §4's feature closes, on browsers, at the price §4 states — and closing it is what
makes the price worth restating on the screen that offers it.

What it does disclose is on the screen, not on the wire: that this application is installed, and
that something arrived. The notice carries no sender, no group and no text. Naming the
conversation is available and off by default, behind copy that says what lands on a lock screen
before offering the switch — the lock screen being the one surface encryption cannot reach.

---

## 4ter. Calls leak more than messages, and the leak has no cryptographic answer

The second property this project knowingly trades away, and the argument is the same shape as §4:
the audio stays unreadable, and the fact of the conversation does not.

The content is safe, and it is worth being precise about why rather than asserting it. A media
server has to read the transport in order to route one stream to five listeners without holding
five conversations — so the audio is encrypted a **second** time before it reaches that server,
frame by frame, under `export_secret(..., "wac-call-key-v1", call_id, 32)`. Every member derives
those bytes from the current MLS epoch; nothing is exchanged, so neither the delivery service nor
the media server is ever in possession of a key, and neither can be asked for one. A member removed
mid-call loses the audio, and does not lose it at the same instant they lose the messages.

> **A removed member keeps hearing the call for about half a minute.** Measured, with three
> browsers and a tone per participant: the removal commits, and the audio stops in both
> directions roughly twenty-seven seconds later. Two delays add up. The client re-derives the
> call key on a five-second timer rather than at each commit site — `Session.tickCall`, which
> argues its own case — and the media SDK then goes on decrypting with the keys already in its
> ring for some twenty seconds before it gives up on them. The removed participant also stays in
> the media room throughout, publishing audio nobody can read.
>
> So the guarantee is eventual, not immediate, and the messages and the audio do not stop
> together. For a removal made because somebody must stop hearing *now*, half a minute is the
> number to plan around.

What leaks is who was talking to whom, and for how long:

> **Sealed sender does not survive the media path.** A posted envelope carries no identity at all;
> an RTP stream carries a stable one for the length of a call. The delivery service sees that
> somebody is joining a call, when, and towards which group — it signs the token, so it must. The
> media server sees which participants share a room and for how long. Two calls in one conversation
> look unrelated to it, and a room does not name its conversation, but the *session* is legible in
> a way a message never is.

Two things narrow it, and neither closes it. The room is named by a digest over the group id and
the call id, so the media server cannot group a deployment's calls into conversations. The
participant identity is derived from the call key rather than being the device id, so the media
server never receives the directory — at the price that it is recognisable by members rather than
unforgeable: a member can take another member's identity, which is the forgery the ephemeral
channel already allows for the same reason (§ 2.4).

As with push, the feature is **strictly optional and inert without configuration**: no media
credentials, no token, no call button, and a fully working messenger. Unlike push, it is also
switchable per account from the interface, and the switch cuts both directions — an account that
places calls while refusing to receive them asks of others exactly what it declines to give.

The honest summary: **if the fact that you spoke to somebody is what must not be known, do not
place the call.** No setting in this application changes that, and no cryptography answers it.

---

## 4quater. Disappearing messages are a client-side promise

The lifetime lives in the MLS group context: authenticated, hashed into every commit, read
identically by every member. What it is **not** is enforced. Each client deletes on its own, and
this design has no way to reach into somebody else's storage — a modified client keeps the
message, a screenshot keeps it outside any client at all, and a member who wants a record has one.
Anybody reading "disappears after seven days" as "the other side cannot keep it" has been misled,
which is why the screen says so above the control rather than under it.

What is actually bought is narrower and real: **an ephemeral conversation is never deposited in
the vault**, so it is not sitting on a server for the rest of time under a key derived from a
phrase that does not rotate. Turning a lifetime on deletes this account's existing archive of the
conversation in the same gesture — the caller's own entries, never another member's.

The server never learns the lifetime. There is no column, parameter or header carrying it; the
only thing it sees is a `DELETE` on a vault it cannot read, and it keeps ciphertext envelopes on
its own schedule — up to thirty days — regardless of what the room decided. A message that was
never delivered inside its lifetime is therefore **lost rather than deleted**: the recipient
computes a deadline already past and never inserts it. That is the intended behaviour and it is
still a message somebody sent that nobody read.

The price is stated once more because it is easy to skip: a conversation with a lifetime does not
survive the loss of every device. Nothing archives it, so nothing restores it.

---

## 4quinquies. The served code is checkable, and the banner still stays

§2.3 lists what a malicious server can do, and one entry has no cryptographic answer: **serve
hostile JavaScript, on every load, to one person**. No browser policy fixes it. The desktop
application exists partly for that reason — its interface is inside a signed binary — and the web
target had nothing.

It now has something short of a defence and well short of nothing.

### What was built

Every release publishes `WEB-SHA256SUMS`, a hash per file of the bundle, produced by
`scripts/release-web.sh` and **attested by GitHub Actions** through Sigstore
(`.github/workflows/release.yml`). The attestation binds the manifest to a commit *and* to the
workflow that produced it: nobody, the maintainer included, can mint that binding outside Actions.

That is the part that matters. The repository already carries an Ed25519 key for the desktop
release, and `scripts/verify-release.sh` states its own limit — the key lives in the repository, so
whoever controls the repository can replace it. For a manifest whose entire job is to be
independent of the party serving the code, a key that party holds is not independence.

Two consumers: `scripts/verify-web.sh` compares a live deployment against a manifest, and
`extension/` does the same continuously from a browser.

### The precondition, and why it is stated here

**One manifest describes every deployment**, self-hosted included, because the bundle carries no
deployment's configuration any more. The API is reached on the page's own origin, the policy says
`connect-src 'self'`, and the log pin left the web build. Measured: two builds with entirely
different configuration are byte-identical across all 226 files, and a build in
`node:22-bookworm-slim` agrees with CI byte for byte.

Without that, a published manifest would have described the official deployment and nothing else —
a service to one operator, dressed as a general mechanism.

### What it does not establish, in order of how easily it is over-read

**The banner does not go away, and no version of this work removes it.** Everything the page
displays is drawn by the server being checked. A "verified" badge in the application would be
forged by exactly the server it is meant to catch, which is why the verdict lives in the
extension's toolbar icon and nowhere else. What the sentence changes is its second half: from
"nobody can check this" to "here is what to check it with".

**A targeted attack on somebody who does not check is untouched.** `verify-web.sh` passes for
everybody who runs it and fails only for the person being attacked — who is, by construction, the
person not running it. That is the ceiling of the manual half and the whole argument for the
extension.

**The extension re-requests rather than reads.** Chrome exposes no way to obtain the bytes a page
actually received, so resources are fetched again with `cache: "force-cache"`. A server that
answers differently to a second request defeats this and nothing here detects it. What it raises is
the cost of an attack from "serve anything" to "serve one thing consistently and hope nobody
compares" — real, and not the same as impossible.

**A service worker now sits between the page and the network.** `public/sw.js` answers
`/assets/*`, `/emoji/*.json` and `/fonts/*` from a cache, and it is itself covered by the manifest
like every other file in `dist`. Two consequences worth naming: the extension's re-request may be
answered by that cache rather than by the server, which is a check of the bytes that ran and not of
the bytes the server would serve now; and offline, the application starts from the last
`index.html` this browser received. Neither is a new way in — the entry point is revalidated
against the server on every load, and the cached assets are named by their own content — but both
are places where "what this browser is running" and "what that server is serving" can differ for
as long as there is no network.

**Verifiable or calls, not both.** `VITE_MEDIA_URL` still enters the Content-Security-Policy, so a
deployment configuring calls produces a bundle that no longer matches the published one. Until the
media server sits behind the same origin, an operator chooses between the two.

**The extension is its own supply chain.** It is another artefact, from another store, and
"verified by an extension" is worth exactly what the extension is worth. It is unpublished today,
so installing it means loading it from source.

**None of this concerns the audit.** A reproducible, attested, verified build establishes that the
bytes match the source. It says nothing about whether the source is right. That is why the banner
in the interface is now two banners, and why the second one shows on the desktop as well.

---

## 5. Known limitations

The full table, in order of real importance. Nothing here is softened.

| Limitation | Consequence |
|---|---|
| **Metadata** | Message sizes are now padded in buckets, and the sender is no longer identified to the server (sealed sender). Still visible: **who belongs to which group, when a post happens, and from which IP address**. Often more revealing than the content; hiding it would need a third-party relay and cover traffic. |
| **Log signed by the party it watches** | The auditable log exists, but it is signed by the same party it monitors. A serious deployment would hand it to distinct operators. Gossip between clients partially compensates — it does not erase the defect. |
| **Log key served by the server** | The client discovers it from the very server it is meant to monitor. The **desktop binary** pins it — packaged inside a signed artefact, that closes the hole on a first contact. The **web build no longer does**, and the removal was deliberate: there the server shipped the pin along with the code the pin constrained, so it was never a defence against the party building the bundle, and compiling it in made every deployment's bytes different — which is what stopped one published manifest from describing them all. What it did buy, a substitution that breaks every client at once instead of silently, is what §4quinquies provides and provides better. Either way the client still refuses to let the key change afterwards. |
| **Account deletion** | There is no mechanism, and that is deliberate: an append-only log forbids removing an entry. Removing one outside the code shrinks the log, which gossip immediately reports as an attack — rightly. |
| **Post noise** | The server holds each group's posting key: it can deposit envelopes. They will not decrypt — it cannot produce valid MLS — but it can pollute. That is the price of a symmetric MAC. |
| **Typing-post rhythm** | The signal's content is opaque and never reaches the disk, but the server sees that a post is happening towards a given group. In a one-to-one it infers that one of the two is writing. Sealed sender hides *who*, not *that* — disabling the indicator is the only real protection. That setting is reciprocal, and was not always: it used to cut emission alone, which let an account watch its correspondents hesitate while showing them nothing. Privacy from the server, taken as an advantage over the person on the other side. |
| **Image preview decoding** | A previewed attachment goes through the browser's image pipeline before anything is shown, and only the canvas re-encoding reaches the document — so a file lying about its type cannot become script. What it opens: the decoder is now reachable by any peer with a codec bug to spend, where before an attachment was only ever written to disk. The pixel ceiling that bounds a decode bomb is checked **after** the decode, because no browser API reports an image's dimensions without performing one. Previewing is opt-in, per file. |
| **Local notifications** | Any notice at all discloses, to whoever glances at the device, that Whispee is installed and that a message just arrived. It names no sender, no group and no content; the conversation name is shown only if the user turns that on, and the wording says what that puts on a lock screen before offering the switch. Irreducible — it is the cost of the feature existing. Unlike push, no server is involved and none learns a notice was raised, which is also why it only fires while the page is running. |
| **Replay window on a sealed-sender post** | An anonymous post carries no timestamp, so nothing bounds when the server should stop accepting a replay of it; remembering the nonce forever is the only complete answer, and it makes `posting_nonces` grow for the life of the deployment. It is now kept seven days. Past that a replay is accepted again — costing one duplicate row and one spurious wake-up, the MLS client discarding the message because that ratchet generation is already consumed. A storage nuisance, not a way into a conversation. |
| **Write quotas bound a rate, not a total** | KeyPackage top-ups, vault writes, attachment uploads and signed envelope posts are capped per device per minute. The counters live in memory, so they are per instance and reset on restart, and an account multiplies its allowance by registering more devices — two rate-limited open requests each. What those quotas never bounded is stored bytes; that is now `crates/server/src/storage.rs`, a per-account ceiling in the database rather than in memory, covering the vault and attachments. Envelopes stay outside it — see the row below. |
| **The anonymous post path is not rate-limited** | Bounding it would mean attributing a post to a device, which is the power sealed sender exists to remove; counting per group instead would throttle a conversation's honest members. Anyone holding a group's posting key can therefore grow `envelopes` in that group at will. They have to be a member — it is the ceiling the anonymous path removes, not the membership requirement. |
| **Declared timestamps** | The time shown on a message is the one its sender put there, inside the encrypted content. The server never sees it and cannot alter it — and any member of the group can date their own message to anything. It is an annotation: the thread's order is `seq`, which the server assigns and no member controls. In a one-to-one there is exactly one other person who could lie, and they could equally lie in the text. |
| **Unauthenticated signals** | The ephemeral channel is encrypted under a symmetric group key. In a group, a member can therefore make it look as though another is typing. Harmless with two, where there is only one other. |
| **Forward secrecy of signals** | None inside an epoch: compromising the export secret exposes that epoch's signals. They have no retrospective value and are stored nowhere — the trade is deliberate, it avoids making the history pay for a disposable datum. |
| **Receipts and coercion** | A read receipt proves a device displayed a message: information about behaviour, not content. Hence the opt-out, and its reciprocity. The opt-out is a property of the account and reaches its other devices as a sealed control message — it used to be per-device, and a refusal one forgotten laptop kept undoing was a refusal in name only. What no version of it can be is server-enforced: the server cannot see a receipt, so the reciprocity holds because the client holds it. A modified client can withhold its own and still read everyone else's. That is the price of the receipt being invisible to the server, and it is not payable in both directions. |
| **Preferences between devices** | The petnames and blocks of an account now travel between its own devices, inside the sealed control message. They are notes about people, carried by the very people they name — so the second seal is what makes this acceptable rather than a leak, and a peer sees an opaque body it cannot open. What a peer *does* learn is that a preference moved, since the message is a message: its size and its timing are visible to the server as any envelope's are. The server additionally learns that these accounts exchange envelopes, which it already knew from group membership. |
| **Blocking** | Local and weak by design: it declines to display something that was delivered and stored, it does not prevent delivery. Its server-side half is the contact policy below, which does prevent — the two answer different halves of one question, and only the second can decline an arrival. |
| **Contact policy** | `accounts.contact_policy` refuses to write a `group_members` row, so it is the one setting here the server *executes* rather than merely stores. It costs the server no new knowledge: `known` asks whether two accounts already share a group, which it maintains and could answer at any moment. What it does add is one more per-account fact on the server, and a fact worth more to a stranger than to its owner — hence served to the owner alone, and hence a refusal that is deliberately indistinguishable from the one a non-member already receives. A reply naming the reason would have made the setting an oracle: anybody could learn anybody's policy by trying. |
| **Contact policy, what it cannot do** | It is not retroactive and no column could make it so. `closed` refuses new additions and removes nobody from a group they are already in, because the membership that matters is the MLS tree, which this server cannot read. Nor does it hide an account: the directory still resolves a handle, and a refusal happens at the moment of the attempt. |
| **Session authentication** | On the gateway, the signature holds for the whole connection rather than per request. A revocation or a group removal therefore takes effect only at the next revalidation — at the client's next heartbeat, or at the server's tick for a silent client. |
| **Signals and Postgres logs** | Inter-instance fan-out routes signals through `pg_notify`. They are written to no table, but a server set to `log_statement = all` would see them in its logs. |
| **Device omission** | The server can neither *add* a device to an account (attestations) nor *invent* a revocation (signed certificates). It can still *omit* one from the list, or withhold a genuine revocation. The victim observes that a device receives nothing: censorship, noisy but real. |
| **Rotation race** | A stolen device holds the account key and can rotate before its owner. The server cannot tell them apart and applies the first valid rotation. The only recourse is the fingerprint-change alert on the other side — one more reason never to make it routine. |
| **Application fork** | MLS does not enforce roles: the clients do. A client that did not apply the same rule would produce not an error but a silent *fork* of the group. `RequiredCapabilities` stops a client that ignores the extension from joining, but not one that reads it badly. |
| **Removal and delay** | Post-compromise security starts at the **commit**, not at the revocation. A server that delays delivery of the removal commit lets the excluded party read what was encrypted in the meantime. The server-side membership filter narrows the window without closing it. |
| **Approximate seniority** | An admin's succession with no moderator designates the most senior member *in the sense of the MLS tree*. Since MLS reuses freed leaves, a late arrival can inherit. Determinism — which protects against forks — was preferred to accuracy; true seniority would require keeping arrival order in the roster. |
| **Group deletion** | An emptied group disappears from the client, and the server now deletes the row — and, by cascade, its mailbox — once no device is a member and no envelope younger than thirty days remains. Nothing proves it really erased anything; claiming so would be worse than saying nothing. What changed is that the server no longer has a *reason* to keep it. |
| **Retention bounds a rate of growth, not a total** | Envelopes are deleted past thirty days, and only once the group is five hundred sequences ahead of them. That is a steady state, not a ceiling: a group writing five hundred messages a day settles at around fifteen thousand envelopes and stays there. What the purge changes is the shape of the curve — growth stops being proportional to all of history and becomes proportional to the last thirty days of traffic. Attachments go at ninety days, so **a file older than three months is no longer downloadable**, and saving it is the recipient's business. |
| **A purge can break a long-absent device** | Losing one envelope loses one generation of the MLS application ratchet, and nothing after it decrypts. A device offline for more than thirty days in a group that has moved five hundred envelopes on comes back broken and must be re-introduced. The conjunction makes that rare — no conversation under five hundred envelopes is ever touched, at any age — and the `oldest` field on the fetch, with the gateway's `gap` frame, makes it **detectable** rather than silent. Neither makes it impossible, and no retention that deletes anything could. |
| **The vault is bounded; envelopes are not, and the reason is sealed sender** | `vault_entries` is deliberately never purged, so it had inherited the growth problem `envelopes` used to have. A per-account ceiling now bounds it, charged on write and credited when a purge deletes. `envelopes` keeps only the retention purge's steady state: a sealed post carries no device id, so charging the account behind it would mean recording the sender of every post — precisely what sealed sender removes. Anonymous byte tokens close it; they are specified and not built. |
| **The server records who uploaded which attachment** | Charging an upload to its uploader means keeping the uploader. The server always learned it — an upload is a signed request — but it did not store it; now it does, per attachment and per group. What it buys: the heaviest write this server accepts is bounded per person instead of against a ceiling one member could exhaust for a whole group. Rows uploaded before the quota carry no owner, and age out under the attachment retention. |
| **Compromised account** | A device added by an account whose phrase has leaked is duly attested, hence indistinguishable from a legitimate addition. The application signals it; only the user can say whether they own that device. |
| **Recovery escrow** | Opt-in and off by default. Enabling the password factor puts the account seed on the server, encrypted, where the operator can attack it offline — and the history vault goes with it. There is no version of a memorable-secret recovery that does not do this; what closes it is a rate-limiting hardware enclave, which a self-hosted deployment cannot be asked to run. The passkey factor has no such cost and is offered first. § 2.2.2 |
| **History vault** | It removes forward secrecy from the history: a leak of the phrase becomes retroactively total. It is **on by default**, with the counterpart stated on the recovery-phrase screen and restated in the present tense in the settings, where it remains switchable. |
| **Orphan history** | After recovery by phrase, the vault is readable but the corresponding groups appear nowhere: the client only knows the conversations its MLS state carries a trace of. The promise "survives the loss of every device" is therefore not yet kept. Keeping it would require a route listing archived groups and read-only conversations. |
| **Rotation and vault** | Rotating the account key makes already-archived history permanently unreadable. The rotation screen announces it; nothing allows re-encrypting it. |
| **Presence register** | The server holds the last activity time of every device. That is a register transverse to conversations — waking hours, timezone, absences — which no encrypted formulation avoids. Switchable, and then not recorded. |
| **Presence and sealed sender** | Presence shrinks the anonymity set of an anonymous post: a post in a two-member group where only one member is awake can be attributed. |
| **Presence precision** | Truncating to the minute bounds what *clients* see, not what the server knows: it observes the exact instant of every request anyway. |
| **Push and sealed sender** | A server that chooses whom to wake gains a targeted activity trigger: ceasing to wake four members out of five makes the following posts attributable to the fifth. Sealed sender protects against a server that observes, not one that paces. No cryptography answers this; it is the price of the feature, and the reason it is strictly optional and inert without configuration. |
| **Backups** | Not implemented. A cleartext backup entirely defeats E2EE; it is the most common production failure. |
| **Post-quantum** | No PQXDH, no PQ ratchet. Vulnerable to *harvest-now-decrypt-later*. |
| **The web** | The server delivers the JS on every load and can therefore deliver a version that exfiltrates the keys. No amount of WebCrypto fixes that — only a native application or a signed extension does. |
| **Password list** | Rejection uses zxcvbn's common pack — the top of the breach corpora — loaded on demand. HIBP's range API was declined: it would send a SHA-1 prefix, narrowing the password to a few hundred candidates, to a third party at the very moment it is chosen. The long tail of once-breached passwords therefore passes. |
| **Entropy estimate** | The figure shown is zxcvbn's guess count, which accounts for words, dates, keyboard runs and substitutions. It only knows the patterns it ships: the English word lists are left out for their 1.2 MB, so an English word that is not also a common password is overrated, and nothing here models an attacker who knows the user. |
| **Lock and memory** | The session re-locks after five minutes without the user, backgrounded or not. That drops the state the interface holds; the key remains in the WebAssembly module's memory until the tab closes, and no browser API lets us demand otherwise. |
| **Vault volume** | The server learns how many messages each account archives and when. It already knew who talks to whom; this adds a volume and a chronology. That leak is no longer borne by a minority who chose it: it is the normal regime. Avoiding it would require padding and decoy deposits. |
| **Vault deletion** | No erasure endpoint. Even if there were one, nothing would prove the server really deleted the copies. |
| **Compromised endpoint** | Out of scope by nature. A compromised device reads the decrypted messages. |
| **Unfixable advisories in the crypto backend** | `cargo audit` reports four RUSTSEC entries against `libcrux-sha3 0.0.8` and `libcrux-secrets 0.0.5`, both reached through `crypto-core` → `openmls_rust_crypto` → `hpke-rs 0.6.1`. They cannot be fixed from here: the corrected releases are `0.0.x`, which Cargo does not treat as compatible, and `hpke-rs 0.6.1` pins them — moving forward needs OpenMLS 0.9, which is still a release candidate. On impact, the honest split: the two SHA-3 advisories concern SHAKE, and the ciphersuite in use (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) never calls it, so that code is compiled in and not executed. The `libcrux-secrets` one — a constant-time swap/select that may be incorrect on aarch64 — is a shared primitive and **cannot** be dismissed that way; it applies to Apple Silicon and to every Android handset. |
