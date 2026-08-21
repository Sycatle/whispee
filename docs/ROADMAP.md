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
| Receipts, typing, presence, reactions, replies | All four signals, with their settings |
| Mentions | `@handle` in the composer, the account on the wire, the current name on screen |
| Attachments | Per-file AES-256-GCM key carried inside the MLS message, padded into doubling buckets |
| One tab per account | An exclusive Web Lock, taken before anything is read — two tabs consume each other's message keys |
| Local lock | Argon2id 64 MiB / 3 passes, unlock key → master key indirection, re-locking after five minutes without the user |
| History vault | On by default, revocable in settings |
| Desktop application | Tauri 2, interface packaged in the binary |
| Reproducible signed releases | `scripts/release.sh` and `scripts/verify-release.sh` |
| Mobile adaptation | Navigation, safe areas, keyboard, touch targets, lifecycle, offline state, native storage, QR pairing |

The mobile work was carried out as seven numbered workstreams. Six landed. What each one left
behind is in the next section, because "landed" and "verified on a real device" are not the
same claim.

## What is not fully verified

These are finished features whose last mile could not be exercised on the development machine.

| Area | What has not been checked |
|---|---|
| Keyboard and safe areas | Never seen on a physical device — only in a browser and an emulator |
| Native storage migration | The end-to-end migration path has never been run from start to finish |
| Background re-locking | Verified only in its wiring, not its timing |
| QR pairing | The scan itself, for want of `BarcodeDetector` on Chrome under Linux; encoding and decoding are tested |
| Mobile builds | Only ever built in CI, never locally — no Android NDK and no macOS host here |
| Mobile builds in CI | `test.yml` runs the suites and the WebAssembly check on every pull request; `android.yml` and `ios.yml` stay manual or `main`-only, so no mobile artefact is built on a PR |

## Push notifications — half-built, and stopping there is the decision

**What exists, server-side, and works:** token registration and replacement
(`crates/server/src/push.rs`, `migrations/0011_push.sql`), the logic that decides which devices
to wake after an envelope is posted, and a `Waker` trait whose default implementation, `Silent`,
sends nothing.

`Silent` is not a stub. It is the behaviour of a deployment that has configured no provider,
and that deployment must stay **fully functional**: tokens register, nothing is sent, the
application keeps working exactly as it does today. Anyone wiring a real provider in must
preserve that first.

**What is missing, precisely — all of it the part that requires secrets:**

1. **An FCM provider.** HTTP v1, therefore OAuth2 with a service account, therefore an RS256
   JWT.
2. **An APNs provider.** ES256 JWT, `content-available: 1`.
3. **The configuration that wires them in.** Absent by default, or the second of the three
   limits written into `migrations/0011_push.sql` falls.
4. **Device-side token registration.** The token comes from the operating system through a
   Tauri plugin that has to be integrated, and it **changes without warning** — so registration
   must be replayed at every start, not only when the feature is switched on.
5. **The user-facing setting.** Enabling it belongs to the user, and the screen has to say what
   it discloses before offering the switch — as the vault screen does, for the same reason.

The server also has **no outbound HTTP client** today. Adding one is a dependency and a new
network surface on a service that had none.

**None of this is written, deliberately.** Integration code that has never been executed would
look like a feature where there is none, and a half-wired provider is the kind of thing that
appears to work in review and fails in the hands of the person relying on it.

### What push costs, and it is not the tokens

Push **degrades sealed sender** — not through its tokens, but through its existence. A server
that chooses *whom* to wake gains a targeted activity trigger: ceasing to wake four members out
of five makes subsequent posts attributable to the fifth. Sealed sender protects against a
server that observes, not against a server that **paces**. Nothing cryptographic answers this.

That is the price of the feature, and it is the reason it must stay strictly optional, inert
without configuration, and empty — the wake-up carries no text, no sender and no group id, so
neither Apple, nor Google, nor the lock screen learns who writes to whom.

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
- **There is no physical device here.** Biometric invalidation on re-enrolment, a real notch,
  `windowSoftInputMode`: three things no emulator settles honestly.
- **Android without Google services has no wake path.** UnifiedPush would be the answer. It is
  not specified, and it is not planned.

## Longer-standing gaps

These predate the mobile work and are argued in full in [`../README.md`](../README.md) and
[`./THREAT-MODEL.md`](./THREAT-MODEL.md). The short list, so this page is not misleading by
omission:

- **The history vault is the server's unbounded store, and must stay unpurged.** `envelopes` is
  no longer the gap it was: the retention purge deletes an envelope past thirty days once its
  group is five hundred sequences ahead of it, which turns unbounded growth into a steady state
  proportional to the last month of traffic. That purge is only acceptable because the content
  survives elsewhere — in `vault_entries`, which is therefore deliberately never purged, and has
  inherited the role `envelopes` used to play. The debt moved; it was not paid. The bound that
  would settle it is the per-account **stored-bytes quota** `crates/server/src/throttle.rs`
  already names: write quotas cap a rate per device per minute, and ten vault writes a minute,
  forever, is still forever.
- **On the desktop build, notifications neither collapse nor open the conversation.** Tauri's
  notification plugin replaces `window.Notification` with a shim that drops the `tag` and returns
  no handle, so forty arriving messages would be forty notices and clicking one does nothing. The
  plugin is therefore not installed: notifications are web-grade on the web, and whatever the
  platform webview offers on the desktop. The unread count in the title works everywhere.
- **The transparency log is signed by the party it watches.** Gossip catches a forked log
  partially; it does not remove the defect.
- **The MLS keys still live in WASM linear memory**, reachable by the page's JavaScript, on
  every platform including desktop. Moving them into native Rust means making every client
  crypto call asynchronous.
- **Device secrets sit in a plaintext file** on the native side, `0600`. Real protection at rest
  means Keychain and Keystore, which needs per-platform native code.
- **No backups, no post-quantum, no account deletion.** The last is deliberate: an append-only
  log cannot drop an entry, and shrinking the log is precisely what gossip reports as an attack.
- **The web will always ship its own weakness**: the server delivers the JavaScript and can
  deliver a hostile version. Only the packaged desktop binary closes that path, and it moves the
  trust to the distribution channel — which is what the verifiable release in
  [`./BUILD.md`](./BUILD.md) answers.
