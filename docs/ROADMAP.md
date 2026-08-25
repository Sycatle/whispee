# Status and roadmap

This document says what works, what is half-finished, and what will deliberately not be
finished. It is a status page rather than a plan: it exists so that someone reading the code
does not mistake written-but-never-executed code for a working feature.

Whispee is a learning and demonstration project, with no external audit. See
[`../README.md`](../README.md) for the full disclaimer, and
[`./ARCHITECTURE.md`](./ARCHITECTURE.md) for how the pieces fit.

## What works

Everything in this list is implemented and has tests, unless the row says otherwise.

| Area | State |
|---|---|
| MLS messaging (RFC 9420, OpenMLS 0.8.1) | 1-to-1 and groups, one primitive for both |
| Account identity | An account is the fingerprint of its genesis key; the handle is a renameable alias, retired rather than freed |
| Multi-device accounts | Every device is a group member; account-signed attestations stop the server adding a device |
| Groups, roles, removal | Admin and moderators in a group-context extension (`0xF100`); post-compromise security on removal |
| Device revocation, account rotation | Signed certificates other members can check without trusting us |
| Key transparency | RFC 6962 append-only log, inclusion and consistency proofs, gossip over the encrypted conversation |
| Sealed sender | Group post MAC; the server learns that a member posted, not which one |
| Padding | Doubling steps from 256 bytes, on messages and attachments alike |
| Delivery service | Axum + Postgres, signed requests, nonces, rate limits, `envelopes` partitioned by `HASH(group_id)` |
| Gateway | WebSocket, one connection for every group, dynamic subscription, catch-up by cursor |
| Multi-instance fan-out | Postgres `LISTEN/NOTIFY` |
| Receipts, typing, presence, reactions, replies | All four signals, with their settings — account-wide, sealed between an account's own devices |
| Mentions | `@handle` in the composer, the account on the wire, the current name on screen |
| Attachments | Per-file AES-256-GCM key carried inside the MLS message, padded into doubling buckets |
| One tab per account | An exclusive Web Lock, taken before anything is read — two tabs consume each other's message keys |
| Local lock | Argon2id 64 MiB / 3 passes, unlock key → master key indirection, re-locking after five minutes without the user |
| Disappearing messages | Seven days by default, carried in a `0xF101` group-context extension; admin or moderator may change it |
| History vault | On by default, revocable in settings — and never used for a conversation that has a lifetime |
| Desktop application | Tauri 2, interface packaged in the binary. Installers for the three desktop systems are built by CI on a tag, attested, and unsigned by the platforms |
| Reproducible signed releases | `scripts/release.sh` and `scripts/verify-release.sh` |
| Mobile adaptation | Navigation, safe areas, keyboard, touch targets, lifecycle, offline state, native storage, QR pairing |
| Push notifications | Web Push, off until a deployment sets `VAPID_SUBJECT`; the wake-up carries nothing. Browsers only — no FCM, no APNs |

The mobile work was carried out as seven numbered workstreams. Six landed. What each one left
behind is in the next section, because "landed" and "verified on a real device" are not the
same claim.

## What is not fully verified

These are finished features whose last mile could not be exercised on the development machine.

| Area | What has not been checked |
|---|---|
| Keyboard and safe areas | Never seen on a physical device — only in a browser and an emulator. No longer untestable, though: an iPhone can load the `deploy/` stack through a tunnel |
| Native storage migration | The end-to-end migration path has never been run from start to finish |
| Background re-locking | Verified only in its wiring, not its timing |
| QR pairing | The scan itself, for want of `BarcodeDetector` on Chrome under Linux; encoding and decoding are tested |
| Mobile builds | Only ever built in CI, never locally — no Android NDK and no macOS host here. `ios.yml` has since had one green run on `workflow_dispatch`; `android.yml` produces an unsigned debug APK |
| Mobile builds in CI | `test.yml` runs the suites and the WebAssembly check on every pull request; `android.yml` and `ios.yml` stay manual or `main`-only, so no mobile artefact is built on a PR |

## Push notifications — Web Push works, FCM and APNs do not

**What works, end to end:** a browser subscribes from the settings screen, the server signs a
VAPID token per push service and sends an empty wake-up, and the service worker shows a
notification with the tab closed. `crates/server/src/vapid.rs` holds the ES256 half,
`crates/server/src/push.rs` the emitter, `apps/web/src/lib/push.ts` and `apps/web/public/sw.js`
the browser half.

**What turns it on is one variable, `VAPID_SUBJECT`** — the contact a push service is told to
reach. There is no private key to supply: the pair is the server's own, created on first start
(`migrations/0020_vapid.sql`), the same shape `log_key` has had since the transparency log. Unset,
the waker is `Silent`, the key route answers 503, and the client hides the control. That is the
second of the three limits in `migrations/0011_push.sql`, and it is still the behaviour to
preserve first.

### Why Web Push and not FCM

The roadmap used to describe FCM and APNs, and said the missing part was "all of it the part that
requires secrets". That was true and it was not the hard part. The hard part is device-side
registration, and this section used to say it "needs a Tauri plugin that does not exist".

**That sentence has expired.** Several exist now — `tauri-plugin-notifications` (0.5.0-rc.11,
20k downloads, last published 2026-06-30) announces FCM and APNs delivery outright, and
`tauri-plugin-mobile-push`, `tauri-plugin-remote-push` and `tauri-plugin-fcm` sit beside it. A
release candidate is not a thing to lean a messenger on without reading it, but "no such plugin"
is no longer why this is unwritten.

What is still why: **APNs cannot be exercised at all without a paid Apple Developer membership.**
Registering for remote notifications needs the `aps-environment` entitlement, which needs a
provisioning profile, which needs the membership — a free personal team is not offered the Push
Notifications capability, and the simulator receives no remote push. There is an iPhone here now
and it changes nothing about that. On the Android side there is no device here at all.

So writing it would still produce what this document refuses elsewhere: integration code that has
never been executed and looks like a feature. The wall moved from "the tooling does not exist" to
"nothing here can run it", which is a smaller wall and an honest one.

Web Push removed that wall for one specific reason. **The wake-up carries nothing**, so there is
no payload to encrypt, so the whole content-encryption half of Web Push — RFC 8291, `aes128gcm`,
the `p256dh` and `auth` subscription secrets — is unused. What is left is one ES256 signature.

It also needed no migration for the addresses: without a payload the only thing worth keeping is
the endpoint URL, so `push::Address { provider, token }` holds a subscription unchanged.

### What it cost elsewhere

**The server has an outbound HTTP client now**, which it had never had. `reqwest` with rustls, no
cookie store, no redirect following — a push endpoint that answers with a redirect is not one to
follow carrying a bearer token. No request is made unless a deployment sets the variable.

**There is a service worker**, and `notifications.ts` used to argue against one. The objection was
that a worker would cache the application shell served by the server the desktop build exists to
stop trusting. It exists because a push message wakes a worker and never a document — and it
caches now as well.

What makes that acceptable is written in its header and asserted in `push.test.ts`, which runs the
file in a sandbox and checks what it decides: `index.html` is fetched from the network every time
and read from the cache only when there is none, so a corrected deployment takes effect on the next
load; what is answered from the cache first is either addressed by its content (`/assets/`, which
Vite fingerprints) or is not code (`/emoji/*.json`, `/fonts/`). `crypto_wasm_bg.wasm` and
`pdfjs/wasm/` are excluded for being both executable and stably named. The residual cost is stated
rather than buried: offline, the application starts from the last `index.html` this browser
received.

### What is still missing

- **FCM and APNs.** The packaged mobile application is not covered; the web client and an Android
  browser are. `Vapid::wake` matches on the provider name, so a second emitter lands beside it
  without touching the call site, but neither is written and the wall described above has not
  moved.

  A Tauri webview has no service worker either, so `pushSupported()` is false there and a packaged
  build has **no background wake-up path at all**. Since the web client became installable, the
  ranking is inverted on a phone: the site added to the home screen is notified and the native
  application is not. Saying so is not a recommendation to prefer the web — it is the shape of the
  next piece of work.

- **Android without Google services.** Recorded until now under "What will not be resolved" as
  "not specified, and not planned". The first half of that was wrong, and the entry was in the
  wrong list: UnifiedPush is specified, precisely, and its fix is inside this design rather than
  outside it. Its endpoints are Web Push endpoints — RFC 8030, authenticated with the same VAPID
  signature `vapid.rs` already mints — so the transport, the token cache and the dead-subscription
  handling all apply unchanged.

  It is **not** free, and the first reading of this said it was. The Android specification requires
  the body be RFC 8291 content of between 1 and 4096 bytes: an empty POST, which is exactly what
  this server sends and what the section above calls the reason Web Push was affordable, is not a
  legal UnifiedPush message. So it needs the content-encryption half after all — ECDH on P-256,
  HKDF, AES-128-GCM — plus the two subscription secrets `p256dh` and `auth`, which
  `migrations/0011_push.sql` has no columns for because there was nothing to encrypt under them.

  What that costs is smaller than it sounds and worth writing down before somebody re-estimates
  it: `p256`, `hkdf`, `sha2` and `aes-gcm` are already dependencies of this server, so it is one
  cargo feature (`p256/ecdh`), one module and one migration. **And the wake-up stays empty of
  meaning** — the ciphertext can carry a single constant byte, which satisfies the minimum without
  telling the distributor, the push server or the lock screen anything. The property is preserved,
  not traded.

  The client half is unchanged by any of this and is still the reason it is unplanned: registering
  with a distributor is Kotlin, over Android broadcast intents, and there is no Android device
  here.

- **Watches.** Nothing, and nothing is possible before the line above: a watch shows the
  notifications its phone received. A generic "New message" on a wrist is also close to worthless,
  which is a second reason this is a whole piece of work rather than a setting.
- **iOS needs the site installed to the home screen** before it will subscribe at all. That is now
  possible — `public/manifest.webmanifest` and the `apple-mobile-web-app-*` metas exist, and until
  they did there was no version of this client iOS would have subscribed. Still untested on a
  device, but no longer for want of one: there is an iPhone here and a tunnelled `deploy/` stack
  reaches it. It is the next thing to run, and it is the one that decides how much APNs is worth
  buying. Even then a notification there can never show content: the service extension is
  a separate Swift process while the keys live in a WASM module inside the webview.
- **The notification is generic.** "New message", and nothing else. The worker cannot decrypt: the
  MLS keys are in the page's memory, not the worker's, and moving them would hand the decryption
  keys to a context that outlives every tab. Same constraint iOS imposes, arrived at on purpose.
- **No automated test can establish that Google and Mozilla accept these tokens.**
  `tests/webpush.rs` checks the token against the specification and against the public key
  advertised beside it, using a fake push service that verifies the signature and asserts the body
  is empty. A service disagreeing with our reading of RFC 8292 would pass every one of them.

  What closes that is `a_real_push_service_accepts_the_token`, ignored by default because it needs
  a subscription minted by a real browser: it signs exactly as the emitter does and sends to the
  live endpoint. Run once against Chrome's service, which answered `201 Created`, and the
  notification appeared with every tab closed — server to FCM to service worker to screen. Mozilla
  has not been tried. The command is in `docs/DEPLOY.md` beside the browser pass.

### What push costs, and it is not the tokens

Unchanged by any of the above, and the reason the feature stays optional. Push **degrades sealed
sender** — not through its tokens, but through its existence. A server that chooses *whom* to wake
gains a targeted activity trigger: ceasing to wake four members out of five makes subsequent posts
attributable to the fifth. Sealed sender protects against a server that observes, not against a
server that **paces**. Nothing cryptographic answers this.

A second party learns something too, and the settings screen says so before offering the switch:
the browser's push service — Google for Chrome, Mozilla for Firefox — sees a wake-up arrive every
time a message does, and can tie that to an address. The content stays encrypted; the timing does
not.

That is the price of the feature, and it is the reason it must stay strictly optional, inert
without configuration, and empty — the wake-up carries no text, no sender and no group id, so
neither the push service nor the lock screen learns who writes to whom.

## Biometric unlock — written, never executed

The code exists: `apps/desktop/src/commands.rs` and `apps/web/src/lib/biometrics.ts`, with the
prompt fired **inside the native process, on the path to the key** rather than in JavaScript
before the call — a prompt on the JavaScript side is a courtesy a hostile script skips.

**No line of that path has ever run.** There is no Android NDK and no device on the
development machine, so even the compilation of the dependency has only ever been confirmed by
CI. A bug found during this work — five Tauri commands (`master_seal`, `master_open`,
`master_present`, `master_clear`, `biometric_available`) were never listed in
`generate_handler!`, so every biometric call compiled cleanly and failed at runtime — is now
fixed. That class of bug is exactly what an unexecuted path hides, and finding one is not
evidence that it was the only one. The path remains unverified.

What the feature trades, which the settings screen states before offering the button rather
than in a footnote: a password is stored nowhere — it exists only in its owner's head, and that
is what makes the state unreadable to whoever walks off with the disk. Enabling biometrics
**writes the master key onto the device**, sealed by the native process's secrets, which are
themselves in the clear in the application's private directory. Protection becomes the
system's: the private directory plus the prompt in front of the key. Solid against someone who
picks the phone up; worthless against someone who extracts its storage — a rooted device, an
unencrypted backup, a disk image.

That is **strictly weaker than the password alone**. It is not a reason to refuse the feature:
a lock removed because it is tiresome protects less than a lukewarm one that stays on. It is a
reason to say so first.

## Adding somebody to an existing group

**Done.** `Session.addAccount` adds an account and all of its devices to a group that already
exists, and the thread says so — a membership notice is posted for the addition, the removal and
the departure alike, so everybody sees the same history of who came and went.

Three things it settles, recorded because each was a way it could have gone wrong quietly:

- **Who may add.** Moderators and the admin, the same rank that may remove. A member able to add
  somebody they cannot then remove would change the room for everybody with no way back.
- **What the new member reads.** Nothing said before their own commit. That is the MLS ratchet
  rather than a policy, so no setting can soften it; the confirmation says it plainly instead of
  leaving the reader to assume.
- **The posting key.** It travels *through* MLS, once per session, so somebody joining afterwards
  never sees that message — it predates their commit. Left alone they would fall back to signed
  posts: working, and a silent downgrade of sealed sender. Adding clears `postingKeyShared` so
  the next poll re-shares it.

What it does not do: there is no invitation to accept. The added member is in the group from the
commit, and the first they know of it is the conversation appearing.

## What the identity change left open

The account model moved from "a handle *is* the account" to "an account is its key, and a handle
is a name it answers to". `docs/specs/2026-08-21-account-identity.md` carries the design and a
section on what it did not foresee. Three things it deliberately did not close:

| Gap | Why it is still there |
|---|---|
| First contact is a leap of faith | A lying directory hands you a stranger's id, and only an out-of-band fingerprint comparison catches it. The change made sure renaming does not make this worse; it did not make it better |
| A handle claim is not verifiable by a client | A member can claim a handle they do not hold. Checking means asking the directory at render time, which is the one power this design took away from the server. The account id underneath is authenticated and is what every comparison uses |
| A stolen seed still wins the rotation race | The thief holds the same key and can rotate first. Anchoring on the genesis key does not change that — the chain is valid either way |

## What will not be resolved

Not "later" — these are known and accepted, and none of them has a fix inside the current
design.

- **The storage migration will have no automated coverage.** The harness (`node --test`,
  without a DOM) can test neither IndexedDB nor Tauri IPC. The most dangerous code in the whole
  mobile effort — the code that runs once per installation, and whose failure is irreversible —
  is verified by hand.
- **On iOS, a notification can never show content.** The service extension is a separate Swift
  process; the keys live in a WASM module inside the webview. Fixing that means porting the
  cryptography to native code.
- **No device can run a *native* build here.** This used to read "there is no physical device
  here", and there is an iPhone now — which changes less than it sounds. Biometric invalidation on
  re-enrolment and `windowSoftInputMode` live in a packaged application, and packaging one for
  that iPhone needs a paid Apple Developer membership; the Android side has no device at all.

  A real notch and a real virtual keyboard are the exception and have left this list: they belong
  to the web client, which that iPhone can load from a tunnelled `deploy/` stack. Untested, but no
  longer untestable — see "What is not fully verified".

## Longer-standing gaps

These predate the mobile work and are argued in full in [`../README.md`](../README.md) and
[`./THREAT-MODEL.md`](./THREAT-MODEL.md). The short list, so this page is not misleading by
omission:

- **The vault is bounded now; envelopes are bounded by a clock rather than by a ceiling.**
  `vault_entries` is deliberately never purged — the archived content is what makes deleting
  envelopes acceptable — so it had inherited the role of the unbounded store. It no longer has
  it: `crates/server/src/storage.rs` holds a per-account ceiling, 256 MiB by default, charged on
  every vault write and every attachment upload and credited back when a purge deletes. What
  remains outside it is `envelopes`, and not by oversight: a sealed post carries no device id, so
  charging the account behind it means recording the sender of every post — the register sealed
  sender exists to remove. The answer is anonymous byte tokens, specified in
  [`./specs/2026-08-24-posting-allowance.md`](./specs/2026-08-24-posting-allowance.md) and not
  built. Until it is, envelopes are held by the retention purge's steady state and by a rate
  limit, which bound a month of traffic rather than a total.
- **Charging the uploader means recording the uploader.** `attachments` now carries the account
  that deposited it, where before the server learned it for the length of a request and kept
  nothing. That is a metadata leak, it is in the limitations table of
  [`./THREAT-MODEL.md`](./THREAT-MODEL.md), and it is what buys the heaviest write this server
  accepts a personal bound instead of a ceiling shared by a whole group.
- **On the desktop build, notifications neither collapse nor open the conversation.** Tauri's
  notification plugin replaces `window.Notification` with a shim that drops the `tag` and returns
  no handle, so forty arriving messages would be forty notices and clicking one does nothing. The
  plugin is therefore not installed: notifications are web-grade on the web, and whatever the
  platform webview offers on the desktop. The unread count in the title works everywhere.
- **A vault deletion that never succeeds is forgotten when the session ends.** Turning on a
  lifetime erases this account's archive, and every other member's client now does the same when
  it sees the commit — the deletion each member owes for their own copy. That call can fail, so
  the debt is queued and retried on the next poll. The queue is in memory: an application closed
  before a retry succeeds no longer knows it owed one. What that leaves is a readable archive on
  the server for a conversation that has since been told to forget. It is no longer served into a
  thread — `Archive.restore` refuses a conversation with a lifetime, the same refusal `store`
  already made — so what survives is bytes on a server, not history on a screen. Closing it means
  persisting the debt, which is a schema change and is not done.
- **The transparency log is signed by the party it watches.** Gossip catches a forked log
  partially; it does not remove the defect.
- **The MLS keys still live in WASM linear memory**, reachable by the page's JavaScript, on
  every platform including desktop. Moving them into native Rust means making every client
  crypto call asynchronous.
- **Device secrets sit in a plaintext file** on the native side, `0600`. Real protection at rest
  means Keychain and Keystore, which needs per-platform native code.
- **The recovery escrow is a knowing downgrade, not a solved problem.** A password that gets an
  account back with no device left can only work by putting the account key on the server,
  encrypted, where its holder can attack the password offline. It is off by default and the screen
  argues against itself before offering the field. The thing that would actually close it is a
  rate-limiting hardware enclave — Signal's SVR — which a self-hosted deployment cannot be asked
  to run. The passkey factor has no such cost and is the one to prefer where it works.
- **No backups, no post-quantum, no account deletion.** The last is deliberate: an append-only
  log cannot drop an entry, and shrinking the log is precisely what gossip reports as an attack.
- **The web will always ship its own weakness**: the server delivers the JavaScript and can
  deliver a hostile version. Only the packaged desktop binary closes that path, and it moves the
  trust to the distribution channel — which is what the verifiable release in
  [`./BUILD.md`](./BUILD.md) answers.
