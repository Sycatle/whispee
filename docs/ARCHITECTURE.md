# Architecture

This document describes how Whispee is laid out — which crate does what, what depends on
what, how one message travels from a text field to another person's screen, and where state
lives on each platform. It is for anyone about to change code and wondering where a change
belongs.

Whispee is a learning and demonstration project. It has received no external audit and will
not receive one. For communications that actually matter, use Signal. The rest of the
project's reasoning is in [`../README.md`](../README.md); the adversary it argues against is
in [`./THREAT-MODEL.md`](./THREAT-MODEL.md), and what it claims to guarantee is in
[`./SECURITY-PROPERTIES.md`](./SECURITY-PROPERTIES.md).

## Read this first

**`apps/web/src/lib/session.ts` is 2 323 lines, and it is the point where everything
converges.** The WASM module, the delivery service client, local storage, the local lock, the
history vault, the gateway, receipts, typing signals, presence, roles, pairing, device
revocation and account rotation all meet in a single `Session` class. It is the largest file
in the repository by a factor of four, and there is no smaller unit that can be understood on
its own before it.

That is not an accident of growth to be tidied away in passing. It holds exactly the
decisions the protocol does not make — when to replenish KeyPackages, when to persist, how a
guest discovers the group waiting for it, which cursor advances on what — and those decisions
are coupled to each other in ways that survive being split into files. Before touching it,
read it. A change made in one method of that class routinely has to be paid for in three
others.

The mobile work found the same thing from the other side: three separate workstreams all had
to edit `session.ts`, and they only stayed parallel because their regions inside it happened
to be disjoint. See [`./ROADMAP.md`](./ROADMAP.md).

## The repository

```
crates/
  attest/          Canonical attestation, revocation, rotation and post-MAC message formats.
  transparency/    RFC 6962 append-only Merkle log: heads, inclusion and consistency proofs.
  crypto-core/     OpenMLS 0.8.1. The only production crypto path: identities, groups, roles,
                   pairing, the local lock's Argon2id derivation.
  crypto-wasm/     wasm-bindgen bindings. The single JavaScript-facing surface of crypto-core.
  ratchet-lab/     Teaching reimplementation of X3DH and the Double Ratchet. Never shipped.
  server/          Axum + PostgreSQL delivery service: routing, ordering, access control.
    migrations/    sqlx migrations, applied at process start.
    src/           Routes, signed-request auth, WebSocket gateway, fanout hub, rate limits,
                   presence, the transparency log's server side, push.
    tests/         Integration tests: they drive a real server against a real database.
apps/
  web/             Vite 7 + React 19 + Tailwind 4. Also the source of the desktop and mobile
                   interfaces — it is built once and packaged three times.
    src/lib/       All non-UI logic. session.ts is the convergence point named above,
                   and session-types.ts holds the shapes it hands around — split out so that
                   several features can grow without colliding in the same two hundred lines.
    src/ui/        Primitives. A Button that cannot fail contrast, a Field whose label is
                   required by its type. Nothing here knows what a conversation is.
    src/state/     The bridge between a mutable class and React: a revision counter, the
                   provider that subscribes to it, and the error/confirmation channel.
    src/routes/    A hash router in fifty lines. The open conversation lives in the URL.
    src/app/       The shell: three columns, the rail, the detail column, the settings screen.
    src/components/  React components. Screens, not logic.
    src/lib/generated/  wasm-bindgen glue and emoji-index.json, committed build artefacts.
    public/        crypto_wasm_bg.wasm, the fonts, and emoji/ — seven Twemoji sheets, committed.
    scripts/       patch-wasm-glue.mjs, emoji-assets.mjs.
  desktop/         Tauri 2. One crate serving desktop, Android and iOS.
    src/           store.rs (atomic session files), cipher.rs (device secrets), commands.rs
                   (the IPC surface), lib.rs (the entry point mobile needs).
    capabilities/  Tauri permissions: default.json for every target, mobile.json for the
                   biometric prompt, which only exists on Android and iOS.
    gen/           Generated Gradle and Xcode projects. Not versioned, regenerated per build.
docs/              This directory.
release/           whispee.pub, the release public key. artefacts/ is produced, not versioned.
scripts/           release.sh and verify-release.sh.
.github/workflows/ test.yml runs the suites, clippy, and the WebAssembly check. android.yml
                   and ios.yml build mobile artefacts, on demand or on main only.
```

## The crates, and why they are separate

### `attest`

Holds one definition of the canonical messages an account signs: the device attestation
(`wac-attest-v1`), the revocation certificate (`wac-revoke-v1`), the account rotation
(`wac-rotate-v1`), and the sealed-sender post MAC (`wac-post-v1`).

**Why it is not simply a module inside `crypto-core`.** The signer is `crypto-core`, in the
client. The verifier is `server`. Two implementations of the same byte layout diverge sooner
or later, and the benign divergence — rejected signatures, caught by the first test — is not
the only one available. Field confusion is introduced exactly this way, and it produces no
error anywhere. One definition, tested once.

There is a second reason, and it constrains the whole workspace: **the server does not speak
MLS and must not start.** `attest` therefore depends on `ed25519-dalek` and `sha2`, and
nothing else. Putting these formats in `crypto-core` would drag OpenMLS into the server
binary.

### `transparency`

The append-only Merkle log (RFC 6962) that closes the trust-on-first-use gap on account keys:
signed tree heads, inclusion proofs, consistency proofs.

It exists as a separate crate for the same reason as `attest`, applied to a different
producer/verifier pair: the log is built by `server` and checked by `crypto-core` through
`crypto-wasm`. Two hash constructions differing by a byte give proofs that are systematically
rejected — or, far worse, a proof accepted against a different tree. Same dependency
discipline, same motive: no OpenMLS in the server.

Its honest caveat is not architectural but it belongs next to the crate: the log is signed by
the party it watches. Gossip between clients over the encrypted conversation partially catches
a server serving two logs; it does not remove the defect.

### `crypto-core`

Everything a user's messages actually depend on: device identities, account root secrets,
group state, the admin-role policy, pairing, and the Argon2id derivation behind the local
lock. Built on OpenMLS 0.8.1.

**Invariant: `crypto-core` must never depend on `ratchet-lab`.** It is written in the
crate's manifest and in its `lib.rs`, and it is the single mechanical guarantee that no
hand-written cryptography drifts onto the execution path. The absence of that line in
`crypto-core/Cargo.toml` is the check; a pull request adding it must be rejected.

### `crypto-wasm`

The wasm-bindgen binding. It exposes one handle, `Client`, holding one device identity and its
conversations indexed by group id — rather than handing JavaScript two objects it could pair
up wrongly.

Two build details live here because they cannot live anywhere else. `getrandom` 0.2 is
declared with its `js` feature even though no code calls it: `openmls/js` only covers
getrandom 0.3, while OpenMLS's elliptic-curve crates still pull 0.2, and without the feature
the wasm32 build fails. That failure is the good outcome — bad randomness raises no error, it
silently produces predictable keys. And `wasm-opt` is given explicit feature flags, because
the version wasm-pack bundles otherwise refuses the bulk-memory operations rustc emits and
fails in a way the calling script does not notice.

### `ratchet-lab`

X3DH and the Double Ratchet, reimplemented by hand to understand them. Unaudited, not
side-channel resistant, no multi-device, no groups, no state persistence. It is never imported
by `crypto-core` nor by anything a user runs, and that is enforced by the invariant above.

### `server`

The delivery service MLS does not define. A blind mailbox: it routes opaque blobs, keeps a
total order per group, enforces group access control, and can decrypt none of it.

It depends on `attest` and `transparency`, on `sqlx`/Postgres, on Axum, and deliberately not
on `crypto-core` — except as a dev-dependency, where the integration tests use a real client
to drive it.

### `apps/desktop`

A Tauri 2 crate that is a **library first and a binary second**. On mobile there is no `main`:
the system starts the activity or the application and loads the Rust code as a native library,
so Tauri builds with `--lib`. A crate exposing only a binary fails with `no library targets
found`, after several minutes of cross-compilation.

It depends on `aes-gcm`, `ed25519-dalek` and `zeroize` from the workspace — the same versions
as everything else, so two copies of the same curve never end up in one binary — and on
`tauri-plugin-biometric`. That plugin is declared **without a target condition**, against
Tauri's own examples, because the build script compiles for the host: a per-target conditional
dependency is invisible to `tauri-build`, which then refuses the `biometric:default`
permission with a message about permissions rather than dependencies.

## Dependency invariants

| Invariant | Why | How it is checked |
|---|---|---|
| `crypto-core` must never depend on `ratchet-lab` | Unaudited teaching code must never reach a user | Absence of the line in `crypto-core/Cargo.toml`, stated in the manifest and in `lib.rs` |
| `server` must never depend on OpenMLS (outside dev-dependencies) | The server does not speak MLS; giving it the vocabulary invites giving it the role | `attest` and `transparency` carry no OpenMLS dependency |
| `attest` and `transparency` stay tiny | They are shared by producer and verifier; a heavy dependency there is a dependency in both | Two dependencies each: `ed25519-dalek`, `sha2` |
| The desktop crate exposes a `cdylib` | Mobile loads it as a native library | `[lib] crate-type = ["lib", "cdylib", "staticlib"]` |
| The web app is the only interface source | Reimplementing crypto per platform would triple the bug surface on the part where bugs are silent | `frontendDist` points at `apps/web/dist`; there is no separate UniFFI binding |

The last one is the reason a separate mobile binding was ruled out. One Rust crypto core,
three targets, one build of the interface.

## One message, end to end

A text typed into the composer in `apps/web`:

1. **`Session.sendContent`** (`apps/web/src/lib/session.ts`) encodes the content — text,
   attachment descriptor, reaction, reply or receipt — and pads it. Padding happens **before**
   encryption, in doubling steps from 256 bytes: it is the plaintext length that determines
   the ciphertext length, so padding afterwards would hide nothing and cost the same.

2. **`Client.encrypt`** crosses into the WASM module (`crates/crypto-wasm`), which calls
   `crypto-core`, which calls OpenMLS. Out comes an MLS application message for that group's
   current epoch. This is the only place message content is ever encrypted; everything on
   either side of it handles opaque bytes.

3. **The envelope is tagged.** `apps/web/src/lib/envelope.ts` prefixes one byte distinguishing
   an ordinary MLS message from a Welcome. The server does not speak MLS and cannot make that
   distinction itself.

4. **It is posted.** `Api.postEnvelope` sends `POST /v1/groups/{group_id}/envelopes`. Two
   authentication paths exist and the client prefers the first:

   - **sealed sender**: `HMAC(group post key, "wac-post-v1" ‖ group_id ‖ nonce ‖
     SHA256(body))`, carried in `X-Group-Mac` and `X-Group-Nonce`. It proves membership
     without naming the sender. The post key is distributed **through MLS**, never by the
     server — asking the server to hand out the means of not identifying yourself to it would
     defeat the point.
   - **signed**: an Ed25519 signature over method, path, timestamp, nonce and body digest,
     using the device authentication key — which is deliberately distinct from the MLS
     signature key. Reusing one key across two protocols is a classic failure as soon as the
     message formats overlap.

   In parallel, the **gateway** (`GET /v1/gateway`, WebSocket) is normally open. It never
   carries content and is never a correctness dependency: a frame only says "go and look".
   A browser that blocks it leaves the application fully functional, only less responsive.

5. **Postgres.** `post_envelope` increments `groups.next_seq` and inserts into `envelopes` **in
   the same transaction**. That is what gives the total order per group MLS requires: two
   members whose epochs diverge can no longer read each other. `envelopes` is partitioned by
   `HASH(group_id)` into sixteen partitions.

6. **Fan-out.** After the commit — never before, or clients would chase a `seq` a rolled-back
   transaction removed — `hub.publish` announces the sequence number. The hub reaches the other
   instances through Postgres `LISTEN/NOTIFY`, since the database is already there and fan-out
   is already best-effort. Connected clients receive an `envelope` frame carrying the sequence
   number and nothing else; they then fetch by the normal HTTP path, which rechecks membership.
   Duplicating that access control in the fan-out is how the forgotten copy becomes the hole.

7. **Waking.** `push::wake_detached` asks the configured waker to wake the group's devices.
   The default waker is `Silent` and sends nothing — see [`./ROADMAP.md`](./ROADMAP.md).

8. **The other end.** `Session.poll` fetches the envelope, verifies membership, decrypts
   through the WASM module, unpads, decodes, appends to the conversation view, archives to the
   history vault, and persists. Receipts advance a cursor on real messages only:
   `content.isControl()` keeps receipts out of both the thread and the vault, because a receipt
   that advanced the cursor would produce another receipt, and so on — ten envelopes in forty
   seconds, measured, for two people saying nothing.

## Where state lives, per platform

The constraint that shapes all of this is one property of one key.

**The device signing key is non-extractable, and the server refuses to change it.** On the web
it is a `CryptoKey` that `crypto.subtle` will never export, including to our own code. The
server compares `auth_key` in `register_device` and rejects a change. Together those two facts
mean a device's authentication key **cannot be moved**, ever, by anyone.

Everything else follows:

| | Web browser | Desktop and mobile (Tauri) |
|---|---|---|
| MLS state | IndexedDB, database `whispee`, encrypted before it gets there | `session.bin` in the app's private directory, encrypted by the same `DeviceCipher` abstraction |
| Device auth key | Non-extractable `CryptoKey` in IndexedDB | `secrets.bin`, held by the Rust process |
| State-at-rest key | Non-extractable `CryptoKey` in IndexedDB | Same file, same process |
| Master key when biometrics are on | Not available | `master.bin` — its existence *is* the on/off flag |
| Purged when | Browser eviction rules apply | Only on uninstall |

Why the native side exists at all: a mobile webview's storage **is not guaranteed**. iOS
evicts WKWebView data after seven days of inactivity; Android purges under memory pressure.
The loss is final, because the MLS ratchet destroys its keys as it goes — history becomes
unreadable and conversations have to be recreated.

Moving only the MLS state would have been worthless. A saved state whose authentication key
went missing lets the device issue no request at all. So the native side covers **both**, and
the interface it presents (`DeviceCipher` in `apps/web/src/lib/cipher.ts`) is a *capability* —
sign this, seal this — never a key holder. That is what lets `Session` be identical on both
platforms and what will let the key move again later, into the system keystore, without the
rest of the code learning that anything changed.

And it is why an **existing** browser installation cannot simply be migrated: its keys are
non-extractable, so they cannot be moved, and the server will not accept new ones for that
device. `apps/web/src/lib/migration.ts` therefore does not try to save the device — it
registers a new native one, attested by the account seed, and revokes the old. The price is
real and paid once: the MLS identity changes, so groups must be rejoined and history reread
from the vault. Which is also why **there is no migration without the vault**: history would
exist nowhere else, and migrating would trade a *possible* eviction for a *certain* loss.

What the native side does **not** buy, and must not be claimed:

- **Rust sees the key in the clear**, where the browser refused to export it. That is not a
  practical regression — a hostile script in the webview could already *use* a non-extractable
  key without extracting it, and it can still call `seal` and `sign` — but it is a property
  given up, and staying quiet about it would be dishonest.
- **The secrets file is plaintext on disk**, `0600`. That stops another user of the same
  system. It stops neither a rooted device, nor a disk backup, nor another process of the same
  user. Real at-rest protection means Keychain and Keystore, which needs native per-platform
  code and is not written.
- **The MLS keys never moved.** They still live in the WASM module's linear memory, reachable
  by the page's JavaScript, on every platform. Moving them to native Rust — where `zeroize`
  actually applies — requires making every client crypto call asynchronous. Not done.

Atomic writing is the one risk the native store introduces that IndexedDB did not have: an
interrupted IndexedDB transaction leaves the database intact, while an interrupted
`File::write` leaves a truncated file, which is precisely the final loss being avoided. Hence
`write to a temporary → fsync → rename → fsync the directory`, and deliberately **no N-1
copy**: a stale MLS state restored silently rewinds epochs and replays used keys. That is a
cryptographic fault, not a safety net.

## Emoji are artwork, not glyphs

Every emoji in the interface is Twemoji artwork, substituted into the text at render time by
`ui/Emoji.tsx`. This is the same thing Discord, Slack and X do — and Telegram and Signal too, from
Apple's set. It is worth writing down why, because the obvious alternative looks better on paper
and does not work here.

**The system font was the previous answer and it fails our own targets.** A Linux distribution
that ships no colour emoji font draws tofu, and the three platforms that do ship one draw three
different pictures for the same message. "The sender and the receiver see the same thing" is not
a nicety in a messenger. There is now **no fallback to it anywhere**: an emoji with no artwork
draws a neutral placeholder from the sheet, never the raw character.

**A self-hosted colour font would be the tidy fix, and no format delivers it.** The glyphs would
stay text: selection, copy, the composer's `<textarea>` and the system notification would all
work with no code at all. But this artwork uses gradients, and:

- **COLRv1** carries gradients and **WebKit does not implement it**.
- **OT-SVG** carries gradients and **WebKitGTK leaves it switched off by default**.
- **COLRv0** is supported everywhere and **has no gradients**.

WebKitGTK is the engine behind the Tauri build on Linux, and WKWebView behind the iOS one. There
is no format that renders this artwork on all four engines, so the font route is closed — not
inconvenient, closed.

### Twemoji replaced Fluent, for coverage rather than taste

Microsoft's Fluent Emoji draws 1,595 sequences and **no country flag at all**, no keycap, no `©️`
and no `®️`. `🇫🇷` from a peer had nothing to draw and fell back to the platform — the letters
"FR" on Windows. Worse, fourteen of those gaps were *in the catalogue*, because the generator
never checked that an entry it indexed had a file behind it.

Twemoji (`jdecked/twemoji`, CC-BY 4.0) covers Unicode completely, so the question stops being a
question and one set means one licence. Emojibase (MIT) supplies what Twemoji does not ship at
all: names, keywords, groups, canonical order, tone relationships and `:shortcodes:`.

Apple's set is what Telegram and Signal actually use — Telegram embeds it as five webp sheets in
`tdesktop/Telegram/Resources/emoji`. Its licence does not permit that, so it is not an option
here whatever the precedent.

### Seven sheets, not four thousand files

The first version shipped one SVG per emoji and let `loading="lazy"` fetch them. It was slow, and
the intuition points the wrong way about why: the whole untoned set is **3.3 MB**, which is one
photograph. The cost was **4,009 requests** — six at a time over HTTP/1.1 in development, one
round trip apiece through Tauri's custom protocol on the desktop.

`scripts/emoji-assets.mjs` now emits seven JSON sheets, keyed by sequence, holding inner SVG
markup. `lib/emoji-sprite.ts` fetches one, injects the whole thing as `<symbol>` elements in a
single mutation, and every emoji on screen is a `<use>` pointing into it — so a thread with thirty
👍 holds one copy of the path data rather than thirty decoded images.

Which sheet holds a sequence is *computed*, with no table to consult: no tone modifier means
`base`, one modifier means that tone's sheet, two means `mixed`. A reader who never opens the
picker never fetches the 4.5 MB of tone variants.

**Injecting a sheet whole is not an optimisation, it is the fix.** Injecting one `<symbol>` per
emoji on first sight — which is what a sane person writes first — froze the tab for over eight
seconds on the picker's 1,914 cells: appending to a sprite that hundreds of live `<use>` already
point into makes every one of them re-resolve. The whole sheet in one `innerHTML` costs 55 ms.
The price, stated plainly, is roughly 16,000 inert nodes and 24 MB in the document whether or not
anybody looks at those emoji. That is what the word "preloaded" costs.

### The naming rule, which is not the obvious one

Twemoji drops `FE0F` from its filenames — **except** when the sequence also contains a zero-width
joiner, where it keeps it. 972 of the 4,009 names depend on that, and there is exactly one
sequence filed against the rule (`👁️‍🗨️`). `keyOf()` in `lib/emoji.ts` is the single definition,
imported by the generator rather than restated, because getting it wrong is invisible to whoever
picked the emoji and only breaks for whoever receives it.

The generator refuses to emit a catalogue entry it has no artwork for, and fails the run with the
list. That check is what the fourteen orphaned keycaps were missing.

### Two ways to reach an emoji, plus the grid

`components/EmojiPicker.tsx` is the grid: search, a jump bar of category icons, sections in
Unicode's own order, and six skin-tone swatches. `lib/shortcode.ts` and `components/Shortcodes.tsx`
are the other route — typing `:smi` opens a completion list in the composer, and typing `:joy:`
whole substitutes it with no menu at all. Both read the same generated catalogue, which is a
dynamic import so its 296 kB stay out of the initial bundle.

The output is committed, for the reason the WebAssembly module is: the build must work offline,
and an application whose argument is that you can verify what you run should not fetch a third of
its interface at build time. `public/emoji/MANIFEST.json` records the upstream tag, commit and
archive digest; `public/emoji/LICENSE` carries the CC-BY attribution, which is an obligation and
not a courtesy.

What this still does not cover: display names, group names and attachment filenames are drawn by
the platform font, as are the composer and every other text input — a `<textarea>` cannot hold an
image without becoming a rich-text editor.

## Why the desktop application exists

Not for the native window. On the web, the server ships the JavaScript on every load and can
ship a version that exfiltrates the keys; no Content-Security-Policy addresses that, because
a CSP constrains what code may do, not who wrote it. In the desktop build the interface is
packaged inside the installed binary — the server no longer ships it, so it can no longer
replace it.

What that displaces rather than removes: trust now goes to the binary's distribution channel,
and a substituted binary cancels the entire benefit, silently. That is what the reproducible,
signed release answers — build first, signature second. See [`./BUILD.md`](./BUILD.md).

Which is also why `apps/desktop/capabilities/default.json` grants `core:default` and nothing
else. Every permission added there is a capability the page's JavaScript can reach, and
reducing exactly that is the point of this target.
