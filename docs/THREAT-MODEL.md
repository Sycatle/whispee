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
| **Recovery phrase** | the only restoration path, and — since the history vault is on by default — the key to all archived history |
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
- **attachment sizes**, to an order of magnitude: they now go into the same doubling buckets as
  messages, with a top bucket just under the server's 25 MiB ceiling.
- `created_at` on envelopes, kept for a purge that is never performed.

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
- **choose whom to wake**, if push is ever configured. See §4.
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
- **see everything said in the group while a member**, obviously, and keep it.

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

The lock is **not a recovery factor**: forgetting it loses nothing permanently, since the
twelve-word phrase remains the only restoration path. Making it a second vault factor would double
the loss surface for no gain against a server that never sees it.

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
- **Legal compulsion of the operator.** It changes what the operator does, not what it can do; the
  "malicious server" row already covers the capability.
- **Supply chain below the source.** Reproducible builds cover the binary against the published
  source; they say nothing about `rustc`, the crates, or the operating system.

---

## 4. Push notifications degrade sealed sender

This is the one property the project knowingly trades away. The mobile execution plan recorded the
decision and said it belonged in the documentation; it was never written down. It is written here.

Push is **half-built**: the server records tokens, decides who to wake, and sends nothing. There is
no FCM or APNs provider, no configuration, no device-side token registration, and no user-facing
setting. `Silent` is the default waker and it wakes nobody.

The degradation is not caused by the tokens. It is caused by the feature's **existence**:

> A server that chooses *whom* to wake gains a targeted activity trigger. Ceasing to wake four
> members out of five makes the following posts attributable to the fifth. Sealed sender protects
> against a server that **observes**; it does not protect against a server that **paces**. No
> cryptography answers this.

That is the price of the feature. It is also why the feature is strictly optional and inert without
configuration: a self-hosted deployment that talks to neither Apple nor Google must stay fully
functional, and does.

Three further limits follow from push, and hold whenever it is configured:

- **the third party learns the rhythm.** For a sleeping phone to learn a message is waiting,
  Google or Apple must wake it — and they can tie that device to an account. The content stays
  encrypted; the activity metadata leaks, and that is irreducible, not a defect;
- **the wake-up carries nothing** — no text, no sender, no group id, because putting the message in
  the notification would show it to the provider *and* to the lock screen;
- **on iOS, the notification will never show the content.** The service extension is a separate
  Swift process; the keys live in a WASM module inside the webview. Fixing that would require
  porting the crypto to native.

---

## 5. Known limitations

The full table, in order of real importance. Nothing here is softened.

| Limitation | Consequence |
|---|---|
| **Metadata** | Message sizes are now padded in buckets, and the sender is no longer identified to the server (sealed sender). Still visible: **who belongs to which group, when a post happens, and from which IP address**. Often more revealing than the content; hiding it would need a third-party relay and cover traffic. |
| **Log signed by the party it watches** | The auditable log exists, but it is signed by the same party it monitors. A serious deployment would hand it to distinct operators. Gossip between clients partially compensates — it does not erase the defect. |
| **Log key served by the server** | The client discovers it from the very server it is meant to monitor, which does not protect against a malicious server on first contact. It should ship with the application. The client at least refuses to let it change afterwards. |
| **Account deletion** | There is no mechanism, and that is deliberate: an append-only log forbids removing an entry. Removing one outside the code shrinks the log, which gossip immediately reports as an attack — rightly. |
| **Post noise** | The server holds each group's posting key: it can deposit envelopes. They will not decrypt — it cannot produce valid MLS — but it can pollute. That is the price of a symmetric MAC. |
| **Typing-post rhythm** | The signal's content is opaque and never reaches the disk, but the server sees that a post is happening towards a given group. In a one-to-one it infers that one of the two is writing. Sealed sender hides *who*, not *that* — disabling the indicator is the only real protection. |
| **Image preview decoding** | A previewed attachment goes through the browser's image pipeline before anything is shown, and only the canvas re-encoding reaches the document — so a file lying about its type cannot become script. What it opens: the decoder is now reachable by any peer with a codec bug to spend, where before an attachment was only ever written to disk. The pixel ceiling that bounds a decode bomb is checked **after** the decode, because no browser API reports an image's dimensions without performing one. Previewing is opt-in, per file. |
| **Declared timestamps** | The time shown on a message is the one its sender put there, inside the encrypted content. The server never sees it and cannot alter it — and any member of the group can date their own message to anything. It is an annotation: the thread's order is `seq`, which the server assigns and no member controls. In a one-to-one there is exactly one other person who could lie, and they could equally lie in the text. |
| **Unauthenticated signals** | The ephemeral channel is encrypted under a symmetric group key. In a group, a member can therefore make it look as though another is typing. Harmless with two, where there is only one other. |
| **Forward secrecy of signals** | None inside an epoch: compromising the export secret exposes that epoch's signals. They have no retrospective value and are stored nowhere — the trade is deliberate, it avoids making the history pay for a disposable datum. |
| **Receipts and coercion** | A read receipt proves a device displayed a message: information about behaviour, not content. Hence the opt-out, and its reciprocity. |
| **Session authentication** | On the gateway, the signature holds for the whole connection rather than per request. A revocation or a group removal therefore takes effect only at the next revalidation — at the client's next heartbeat, or at the server's tick for a silent client. |
| **Signals and Postgres logs** | Inter-instance fan-out routes signals through `pg_notify`. They are written to no table, but a server set to `log_statement = all` would see them in its logs. |
| **Device omission** | The server can neither *add* a device to an account (attestations) nor *invent* a revocation (signed certificates). It can still *omit* one from the list, or withhold a genuine revocation. The victim observes that a device receives nothing: censorship, noisy but real. |
| **Rotation race** | A stolen device holds the account key and can rotate before its owner. The server cannot tell them apart and applies the first valid rotation. The only recourse is the fingerprint-change alert on the other side — one more reason never to make it routine. |
| **Application fork** | MLS does not enforce roles: the clients do. A client that did not apply the same rule would produce not an error but a silent *fork* of the group. `RequiredCapabilities` stops a client that ignores the extension from joining, but not one that reads it badly. |
| **Removal and delay** | Post-compromise security starts at the **commit**, not at the revocation. A server that delays delivery of the removal commit lets the excluded party read what was encrypted in the meantime. The server-side membership filter narrows the window without closing it. |
| **Approximate seniority** | An admin's succession with no moderator designates the most senior member *in the sense of the MLS tree*. Since MLS reuses freed leaves, a late arrival can inherit. Determinism — which protects against forks — was preferred to accuracy; true seniority would require keeping arrival order in the roster. |
| **Group deletion** | An emptied group disappears from the client, but the server keeps the mailbox. Nothing would prove it really erased it; claiming so would be worse than saying nothing. |
| **Compromised account** | A device added by an account whose phrase has leaked is duly attested, hence indistinguishable from a legitimate addition. The application signals it; only the user can say whether they own that device. |
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
