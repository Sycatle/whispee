# Security properties

This document states, one by one, what Whispee claims to achieve — and, in the same breath, where
each claim stops. Every property here has a caveat, and the caveat is part of the property. It is
for anyone who needs to know exactly how far a guarantee reaches before relying on it.

Whispee is a learning and demonstration project. It has had no external audit and will not get one.
For communications that actually matter, use Signal.

Mechanisms are described in [`./PROTOCOL.md`](./PROTOCOL.md); the adversaries and the full
limitations table are in [`./THREAT-MODEL.md`](./THREAT-MODEL.md).

---

## 1. Confidentiality

**Claim.** Message content is readable only by the members of the group at the time of sending. The
server routes opaque blobs and holds no key that opens them. Group secrecy comes from MLS (RFC
9420) through OpenMLS 0.8.1 in `crates/crypto-core`, which is the only production crypto path — a
1-to-1 conversation is simply a group of two, using the same primitive.

Attachments follow the same rule by a different path: each file is encrypted client-side under its
**own** AES-256-GCM key, and that key travels inside the MLS message together with the file name
and MIME type. Reusing a key across files would mean one leaked descriptor opens them all; one key
per file bounds the damage and lets a specific attachment be shared without granting the rest.

Call audio follows it by a third: a media server terminates the transport encryption — that is what
routing one stream to several listeners means — so every frame is encrypted a second time before it
gets there, under `export_secret(..., "wac-call-key-v1", call_id, 32)`. Each member derives those
bytes from the current epoch, nothing is exchanged, and neither server ever holds a key it could be
asked for. The call id is in the exporter's context so two calls in one epoch do not share a key.

**Caveat.** Length is not content. Message bodies are padded into doubling buckets from 256 bytes,
so the server learns an order of magnitude and no more. Attachments go into the same buckets,
applied to the plaintext before encryption, with a top bucket capped just under the server's 25 MiB
ceiling — so their size also reduces to an order of magnitude, at up to twice the bytes over the
wire. And the server holds each group's posting key, so it can deposit envelopes into a group: they
will never decrypt, but it can pollute.

`ratchet-lab` — a teaching reimplementation of X3DH and the Double Ratchet — is **never** part of
this. It is not imported by `crypto-core` nor by any code a user runs, and the absence of that
dependency in `crypto-core`'s manifest is an invariant to preserve.

---

## 2. Integrity and authenticity

**Claim.** A modified or substituted ciphertext fails to decrypt rather than yielding forged bytes.
MLS authenticates every application message under the sender's MLS signature key. Attachments carry
their integrity in the AEAD itself — a substituted or altered blob fails decryption, so no separate
digest is needed. `tampered_ciphertext_is_rejected` pins this down.

**Caveat.** This holds **only in release builds**. OpenMLS 0.8.1 runs a `debug_assert!(false)`
before returning the decryption error (`framing/private_message_in.rs:136`): in a debug build, a
message altered in transit panics the process instead of being cleanly rejected. That is a remotely
triggerable denial of service, reachable by flipping a single byte. `cargo test --release` is
mandatory and a debug build must never be deployed.

The second caveat is about MIME types: the type of an attachment comes from the sender and is an
indication, not a proof. Files are therefore **downloaded, never rendered inline**, and the server
answers `application/octet-stream` with `nosniff` and `Content-Disposition: attachment` so the
browser guesses nothing on its own. A file declared `image/png` but containing SVG or HTML would
otherwise execute script on that origin — within reach of the keys in IndexedDB.

---

## 3. Forward secrecy

**Claim.** MLS's application ratchet consumes a generation per message, so compromising a device's
current state does not retroactively open older messages whose keys have been deleted. KeyPackages
are single-use for the same reason, and their init key must never be served twice — which is not
OpenMLS's job: `key_package_reuse_must_be_prevented_by_the_server` states as much. The server
removes each KeyPackage from the stock the moment it is served, using `DELETE ... RETURNING` over
`FOR UPDATE SKIP LOCKED`, and reports stock exhaustion for a device.

**Caveat, and it is a large one: the history vault deliberately removes forward secrecy from the
history.** Vault entries are encrypted under a key derived from the recovery phrase, which is
**stable forever**. If that phrase ever leaks, every archived past leaks with it, retroactively.
Without the vault that past would have stayed out of reach — that is forward secrecy, and it is a
real protection, not an inconvenient side effect.

The trade was settled the other way, and the reason has to be stated: a messenger whose
conversation restarts empty at every reload is not one. Putting that choice behind a settings
screen would have been refusing it for almost everyone, without almost anyone deciding. So it is
taken once, here, and it stays revocable in the settings. The argument against it remains true —
that is precisely what makes it a trade-off rather than an improvement.

Two consequences follow from the default:

- **the recovery phrase now protects the past as much as the account**, and it is stated as such on
  the screen that shows it, since that is the only moment it is in front of anyone;
- **rotating the account key makes archived history permanently unreadable**, its key deriving from
  the old phrase. The rotation screen says so before offering the button.

Two more things the interface states rather than hides: archiving **does not reach back in time**
— the keys of already-exchanged messages are destroyed and nothing reconstitutes them; and stopping
the backup **does not erase** what was archived. The server keeps the entries and the key remains
derivable from the phrase. Promising a deletion one does not control would be a security lie.

Each account has **its own** vault under its own key, so a message in a two-party conversation is
stored twice, once per participant. Sharing a vault key between accounts would give one the power
to read the other's backups long after the conversation.

Signals have no forward secrecy at all inside an epoch: compromising the export secret exposes that
epoch's typing indicators. They are worth nothing retrospectively and are stored nowhere, which is
why that trade was accepted.

---

## 4. Post-compromise security

**Claim.** This is the property MLS was chosen for, and the only one that genuinely deprives a
device of what follows. A removal commit re-keys the tree through TreeKEM in O(log N). The test
`a_removed_member_no_longer_decrypts_what_follows` freezes it in the strongest form: the removed
member keeps **all** their group state and still fails to read the next message.

Filtering server-side takes nothing away from a compromised party — it holds the group secrets and
would decrypt whatever it obtained by another route. The commit is what removes the capability.

Removal takes an account with **all its devices**; the unit is never the device. And the ephemeral
signal channel inherits this for free: its key is the epoch export secret, so it changes at every
commit and a removed member loses the typing indicator at the same instant they lose the messages.

**Caveat.** PCS starts at the **commit**, not at the revocation. Between the moment a device is
declared revoked and the moment some other member commits the removal, everything encrypted is
readable by the excluded device. A server that delays delivery of the removal commit widens that
window at will. The server-side membership filter narrows it and does not close it.

This is also why revocation produces a certificate signed by the account rather than a database
row: other members must be able to see the revocation without trusting the server, and act on it
themselves. Any member who has verified a certificate may evict the device without waiting for a
moderator — that delay is exactly what revocation exists to remove.

---

## 5. Key transparency

**Claim — and it is implemented.** `crates/transparency` is an RFC 6962 append-only Merkle log of
account keys. The server publishes a signed tree head and, on request, inclusion and consistency
proofs. The client checks the head's signature, then inclusion (recomputing the leaf from the
account and key it actually received, never from a hash the server supplies), then consistency
(today's log extends the one seen yesterday). All three are required: without consistency, a server
replaces an already-published key and serves a log that is internally perfect —
`a_rewritten_log_does_not_pass_consistency` pins that down.

This closes the last real cryptographic gap in the project: trust on first use on the account key.
Attestations stop the server adding a device; nothing before this stopped it lying about the
account key on a first contact, serving its own and relaying in the clear between two perfectly
encrypted sessions.

The `0x00` (leaf) and `0x01` (node) domain prefixes are load-bearing: without them an internal
node's hash presents itself as a leaf, and an attacker forges an inclusion proof for the entry of
their choosing.

**Caveat, stated plainly: the log is signed by the party it watches.** A serious deployment would
hand it to one or more operators, none of which is the messaging server. Here there is a single
process.

No check catches a server keeping **two logs** and serving one to each victim: each sees a signed,
consistent log in which their own view is perfect. Only **gossip** catches a fork, and it works by
asking the server to prove that one's own log extends the one served to the other party — over the
encrypted conversation, the one channel the server carries without being able to read or alter.
Gossip therefore only works between people who actually converse, and it partially compensates for
the structural defect rather than erasing it.

And the log's own public key is served by the server, an acknowledged stopgap: it should ship with
the application. The client at least refuses to let it change afterwards.

---

## 6. Device attestation

**Claim.** Each device carries a signature by the account over `(account, device_id, auth_key,
mls_key)`, length-prefixed to forbid field confusion, and every client re-verifies it on receipt —
never trusting the server's verification, since the server is what is under suspicion. The result
is a single asymmetry: **the server can withhold a device, never add one.**

Without it, a server composing the device list freely would only have to add a device it controls
to Bob's list to be invited into every conversation. No cryptography would break: the message stays
end-to-end encrypted, one of the ends simply happens to be the server. That is the attack WhatsApp
was accused of in 2019. `a_ghost_device_injected_in_sql_does_not_pass_client_verification` embodies
the attacker rather than simulating one — it inserts the device straight into the database,
bypassing the endpoint; the server serves it, the client rejects it.

The displayed fingerprint covers the **account key alone**, so it does not change when a
correspondent adds a phone. A fingerprint that changed at every legitimate event would be ignored
within weeks; device additions are signalled separately. In the same spirit the interface says
nothing while things are fine, and alerts only when a correspondent's fingerprint changes, with
manual comparison available on demand. A permanent "identity not verified" banner is learned and
ignored within days; on the day it matters, it is already invisible. Verified state is therefore
stored as **the fingerprint itself** rather than a boolean — that is what makes a change
detectable.

**Caveat.** Three of them.

- **Omission remains.** The server can still leave a genuine device out of the list, or withhold a
  genuine revocation. The victim notices a device that receives nothing: censorship, noisy but real.
- **A compromised seed is indistinguishable.** Every device of an account holds the seed — that is
  the condition of their parity, each able to attest, revoke and read like the others, with no
  "main" device. So a device added by whoever has the phrase is duly attested. The application
  signals the addition; only the user can say whether they own that device.
- **Rotation is a race.** Rotation, signed by the outgoing key, invalidates every existing
  attestation as a mechanical consequence — `a_rotation_invalidates_every_existing_attestation`
  measures it: 2 verifiable devices, 0 after rotation, 1 after re-attestation. But the thief holds
  the same key and can rotate first, and the server cannot tell them apart: it applies the first
  valid rotation. The only recourse is the fingerprint-change alert on the other side.

Registration itself is trust on first use. Reclaiming an existing handle with a different key is
refused, but nothing proves the first arrival was legitimate. A real deployment would back that
endpoint with a phone or email verification.

An account is named by its key — `SHA256` of the genesis identity key — and a handle is an alias
it answers to. That is what lets the alias move without the account moving with it, and it is why
the directory that maps one to the other is allowed to lie: the id it returns is a hash of a key
that is inside the credential the client then verifies, so a wrong answer never becomes a verifying
one. Section 5 covers the key itself; the published rotation chain is what ties the id, which is
computed from the *first* key, to whatever key is current.

---

## 7. The local lock

**Claim.** A password encrypts local state at rest **on this device**, derived with **Argon2id, 64
MiB, 3 passes** — roughly a second. WebCrypto offers only PBKDF2, which costs computation alone,
and that is exactly what a GPU does by the billion; Argon2id's *memory* cost is what brings a
parallel attack back down to the level of an ordinary processor. Hence a derivation in Rust rather
than the native browser primitive.

The encryption goes through an indirection:

```
password --Argon2id--> unlock key --encrypts--> master key --encrypts--> state
```

The master key is random and independent of the password. Changing the password therefore
re-encrypts 32 bytes and never the whole state — which grows with the conversations, and which
would otherwise pass back through memory in the clear at the worst possible moment: the one where
the user suspects a compromise.

Compared with an IndexedDB non-extractable key, this protects against something new. A
non-extractable key resists script exfiltration but not whoever **obtains the browser session** —
they only have to call the decryption API. With the lock, the master key exists only in memory.

The password policy is a minimum length and a rejection of known sequences, with no composition
rules. "One capital, one digit" creates no entropy — it moves the `A` to the front and the `1!` to
the end, inside a space attackers know better than we do. NIST dropped those rules in SP 800-63B.

**Caveat.** Four.

- **It is not a recovery factor.** Forgetting it loses nothing permanently: the twelve-word phrase
  is still the only restoration path. Making it a second vault factor would double the loss surface
  for zero gain against a server that never sees the password anyway.
- **It re-locks after five minutes without the user**, backgrounded or not. That drops the state
  the interface holds; the key stays in the WebAssembly module's memory until the tab closes, and
  no browser API lets us demand otherwise.
- **The rejected-password list is zxcvbn's common pack** — the top of the breach corpora, loaded on
  demand. The k-anonymous Have I Been Pwned API was declined: it would send a SHA-1 prefix to a
  third party at the very moment the password is chosen. The long tail of once-breached passwords
  therefore passes.
- **The figure shown is a guess count, not a bit count.** It accounts for words, dates, keyboard
  runs and substitutions — but only the patterns it ships with. The English word lists are left out
  for their 1.2 MB, so an English word that is not also a common password is overrated, and nothing
  here models an attacker who knows the user.

One more thing the lock does not change, on web and desktop alike: the cryptography still runs in
WebAssembly inside the webview, so private keys live in the module's linear memory, reachable by
the page's JavaScript. Moving them into native Rust — where `zeroize` genuinely applies and
JavaScript has no access — would require making every client crypto call asynchronous, and remains
to be done.

---

## 8. Account recovery

**Claim, in two parts, because the two factors do not claim the same thing.**

**The passkey factor**: the account seed is sealed under 32 uniform bytes produced by a WebAuthn
authenticator's PRF extension. An adversary holding the entire database learns nothing about it
and has nothing to guess. This is a full claim.

**The password factor**: the account seed is sealed under `Argon2id(password, 256 MiB, t = 4)` and
the ciphertext is stored on the server. **This is deliberately not claimed to resist an adversary
who obtains that ciphertext.** It resists guessing at the cost of one Argon2id evaluation per
attempt, which is a factor and not a barrier, and the property it actually delivers is: *an
attacker who has the database recovers the account if and only if they guess the password.*

The floor enforced on that password is stricter than the local lock's — sixteen characters, and a
zxcvbn estimate above 10^14 guesses — for a reason worth stating rather than tuning: the lock's
password guards one disk against somebody holding that disk, and forgetting it costs nothing
because the phrase still works. This one guards a ciphertext an attacker holds forever, and it is
what somebody chose *instead of* keeping the phrase.

**Not claimed, and each of these is a design consequence rather than a gap:**

- **No protection against the server operator.** They hold the ciphertext by construction. The
  online rate limit (three claims a minute per address) is irrelevant to them; they never call the
  route. Closing this needs a rate-limiting hardware enclave, which a self-hosted deployment
  cannot be required to run.
- **No account lockout.** A failed claim names no account — that is what stops the route being an
  enumeration oracle — so there is nothing to lock after N attempts. The two properties are the
  same property seen from two sides.
- **No protection of the vault separately from the account.** The vault key derives from the same
  seed, so an escrow that opens the account opens the archive with it.
- **No claim about a passkey's availability.** Whether it survives losing this device depends on
  the provider's sync, which the application cannot observe and does not report.
- **Recovery does not restore conversations.** It restores the account and the vault. MLS
  membership can only be granted by a device already in the group — the same limit the phrase
  path has always had.

Pinned by `crypto-core`'s escrow tests (a substituted account, kind or parameter set fails to
open; parameters below the floor are refused before Argon2 runs) and by
`server/tests/recovery.rs` (a wrong secret is indistinguishable from an absent escrow; a rotation
destroys the escrow; the quota bites).

---

## 9. Metadata resistance

**Claim.** Two mechanisms, and both are real.

**Sealed sender.** The server never needed to know *who* posts — only that the poster is a member,
so as not to be an open mailbox. Those are different things and the second suffices. Each group
carries a posting key, distributed to members **through MLS** rather than by the server, and
posting requires `HMAC(posting key, "wac-post-v1" ‖ group_id ‖ nonce ‖ SHA256(body))`. Envelope
posts therefore carry no device signature at all. Handing the server the job of distributing that
key would be asking it to hand out the means of not talking to it.

**Padding.** Message bodies go into doubling buckets from 256 bytes, with an ISO/IEC 7816-4 `0x80`
end-of-content marker. "ok", "yes" and a 200-character text produce **exactly the same size**.
Doubling bounds the waste under 100 % and leaves the server nothing but an order of magnitude.

A third gain came from a change made for other reasons: the WebSocket gateway **removes**
information from the server. The old polling loop sent a signed request per conversation per round
— an activity log accurate to the second. One long-lived connection replaces that with a single
observation point, at open time.

**Caveat.** What still leaks:

- **the IP address**, on every connection and every post;
- **the timing**, and with it the whole rhythm of a conversation, which often says more than the
  lengths did;
- **the target group** of every post, and therefore **group membership and group size** —
  `group_members` is known to the server. Same trade-off as WhatsApp; avoiding it needs
  zero-knowledge credentials (Signal's Private Group System);
- **attachment sizes**, and **vault volume and chronology**;
- **presence**, which shrinks the anonymity set of an anonymous post: a post in a two-member group
  where only one member is awake can be attributed. The inference partly existed already — stream
  subscriptions say who listens to which group — but it was volatile and confined to one group; it
  becomes durable and cross-conversation;
- **the typing rhythm**: the signal payload is opaque and never reaches the disk, but the server
  sees that a post is happening towards a given group. In a one-to-one it infers that one of the
  two is writing. Sealed sender hides *who*, not *that*; disabling the indicator is the only real
  protection.

And sealed sender's own price: the server holds the posting key, so it can deposit noise. It will
never produce valid MLS, but it can pollute. Zero-knowledge tokens would avoid that, at the cost of
machinery out of proportion with this project.

Finally, the one degradation the project accepts knowingly: **push notifications**. Not through
their tokens — through their existence. A server that chooses whom to wake gains a targeted
activity trigger; ceasing to wake four members out of five makes the following posts attributable
to the fifth. Sealed sender protects against a server that observes, not against one that paces,
and no cryptography answers that. It is the price of the feature, which is why the feature is
strictly optional and inert without configuration. See
[`./THREAT-MODEL.md`](./THREAT-MODEL.md#4-push-notifications-degrade-sealed-sender).

And the second one, of the same kind and larger: **calls**. Sealed sender does not survive the
media path. A posted envelope carries no identity; an RTP stream carries a stable one for the
length of a call, so the delivery service sees that somebody joined a call and towards which group,
and the media server sees who shared a room with whom and for how long. The room is a digest over
the group and call ids and the participant name is derived from the call key, so neither the
conversation nor the device directory is handed over — but the *session* is legible in a way a
message never is. Optional, inert without configuration, and switchable per account in both
directions. If the fact that you spoke to somebody is what must not be known, do not place the
call. See [`./THREAT-MODEL.md`](./THREAT-MODEL.md#4ter-calls-leak-more-than-messages-and-the-leak-has-no-cryptographic-answer).

---

## 10. Distribution integrity

**Claim.** On the web, the server delivers the JavaScript on every load and can deliver a hostile
version; no browser policy opposes that. The desktop application closes that path by packing the
interface into the installed binary — that, and not the comfort of a native window, is why the
target exists. Releases are **reproducible first, signed second**: a signature says "someone
holding this key produced this file", not "this file corresponds to this source". The binary is
reproducible, hence verifiable by rebuilding it, without trusting anyone; the signature then only
authenticates the publication. Ed25519 via `openssl`, because this project already verifies Ed25519
signatures everywhere — one primitive for one question.

**Caveat.** It moves trust rather than removing it: trust now goes to the binary's distribution
channel, and a substituted binary silently annuls the entire benefit. Which is what verification
answers — and its own limits are: first install is trust on first use; the public key lives in the
repository, so whoever controls the repository can replace it alongside the binary (the only real
protection is comparing its fingerprint out of band); with no update mechanism,
`verify-release.sh` must be run by hand, and a user who never runs it is protected by nothing;
verification checks that every file listed in `SHA256SUMS` conforms, not that no other file was
added beside them; and reproducibility holds **at a given environment** — another `rustc` or
`pnpm` produces a different binary with nothing compromised, hence the published `BUILD-INFO`. It
was verified between two successive builds on the same machine; reproducibility across distinct
machines has not been measured.

---

## 11. What has never been verified

Stated here so it is not inferred from silence.

- **The WebAssembly shipped to users was, until now, related to its source by nothing.** It is a
  committed binary loaded by every target; no check read it. `scripts/verify-wasm.sh` now rebuilds
  the crate and compares byte for byte, and `test.yml` runs it. What that proves is narrow: that
  what ships is what the repository says it is — not that the source is correct, nor that the
  toolchain is honest.
- **Biometric unlock has never executed a single line.** The code exists; the development machine
  has no Android NDK and no physical device. A bug found while writing this documentation — five
  Tauri commands were never registered — is fixed, but the path remains unverified, including
  whether the dependency compiles.
- **Push is half-built**: the server records tokens, decides who to wake, and sends nothing. No
  provider, no configuration, no device-side registration, no user-facing setting.
- **The native storage migration has never been run end to end**, and it cannot be covered by the
  existing harness (`node --test`, no DOM, no IndexedDB, no IPC). It is the code that runs once per
  installation and whose failure is irreversible.
- **The WebAuthn PRF path has never been exercised against a real authenticator here.** It is
  written against the specification and the browsers' documented behaviour, including the case
  where an authenticator reports `prf.enabled` at creation and returns no output until an
  assertion. That fallback in particular has never run on hardware that takes it.
- **Mobile has not been built here.** Tauri 2 targets iOS and Android from the same codebase, but
  that requires the Android SDK and, for iOS, a macOS machine. A mobile webview will not match
  native on gestures and notifications in any case.
