# Disappearing messages — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every conversation a lifetime carried in the MLS group context — seven days by default — after which each client deletes the message, with the vault switched off for that room.

**Architecture:** A group context extension `0xF101` beside the roster's `0xF100`, holding one `u32` of seconds. `crypto-core` owns its encoding, its preservation across commits, and the rule that admin and moderators may change it. Each client stamps an expiry on arrival — `min(sentAt, first seen) + lifetime` — and prunes from it. The server never learns the lifetime; it gains only a route to delete a group's vault, which credits `account_storage`.

**Tech Stack:** Rust 1.95 (edition 2024), OpenMLS 0.8.1, `wasm-bindgen`, Axum + sqlx + PostgreSQL 17, React 19 + TypeScript, `node --test`.

**Spec:** [`docs/specs/2026-08-24-disappearing-messages.md`](../specs/2026-08-24-disappearing-messages.md)

## Global Constraints

- Extension type: **`0xF101`**, RFC 9420 private-use range, beside `roles::ROSTER_EXTENSION` (`0xF100`).
- Body: one `u32`, big-endian, **seconds**. `0` means off. Absent means off.
- Default on conversations this client creates: **604800** (seven days).
- Rank required to change it: **admin or moderator** — `roster.can_moderate`. A flat group (no roster) lets anyone.
- The clock is `sentAt`, which is declared and not proven: every recipient clamps with `min(sentAt, first seen locally)`.
- Turning it on is **not retroactive** for messages already held. It **is** retroactive for the vault.
- The server never learns the lifetime. Do not add a column, a parameter or a header carrying it.
- The tree is formatted by hand: **never run `cargo fmt`** (`test.yml:228` says why, and there is no fmt check in CI).
- Server tests need PostgreSQL: `docker compose up -d`.

---

### Task 1: The extension, and what it encodes

**Files:**
- Create: `crates/crypto-core/src/lifetime.rs`
- Modify: `crates/crypto-core/src/lib.rs` (add `pub mod lifetime;`)

**Interfaces:**
- Produces:
  - `pub const LIFETIME_EXTENSION: u16 = 0xF101;`
  - `pub const DEFAULT_SECONDS: u32 = 604_800;`
  - `pub struct Lifetime(u32)` with `Lifetime::seconds(u32) -> Self`, `Lifetime::get(&self) -> u32`, `Lifetime::is_off(&self) -> bool`, `encode(&self) -> [u8; 4]`, `decode(&[u8]) -> Result<Self>`.

- [x] **Step 1: Write the failing test**

At the bottom of `crates/crypto-core/src/lifetime.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lifetime_survives_the_round_trip() {
        let seven_days = Lifetime::seconds(DEFAULT_SECONDS);
        assert_eq!(Lifetime::decode(&seven_days.encode()).unwrap(), seven_days);
    }

    #[test]
    fn zero_is_off_and_is_not_an_absent_extension() {
        assert!(Lifetime::seconds(0).is_off());
        assert!(!Lifetime::seconds(1).is_off());
    }

    /// Four bytes, big-endian, and nothing else — because this crosses the wire between clients
    /// that must all read it identically, and a length nobody checks is how a garbled extension
    /// becomes a lifetime somebody did not choose.
    #[test]
    fn a_body_of_the_wrong_length_is_refused() {
        assert!(Lifetime::decode(&[0, 0, 0]).is_err());
        assert!(Lifetime::decode(&[0, 0, 0, 0, 0]).is_err());
        assert!(Lifetime::decode(&[]).is_err());
    }

    #[test]
    fn the_default_is_seven_days() {
        assert_eq!(DEFAULT_SECONDS, 7 * 24 * 60 * 60);
    }
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p crypto-core --lib lifetime`
Expected: FAIL — `file not found for module lifetime`.

- [x] **Step 3: Write the module**

```rust
//! How long a conversation keeps what is said in it.
//!
//! # Why this is in the group context and not in a preference
//!
//! A lifetime one side sets and the other cannot see is a note to oneself. Carried in the group
//! context it is authenticated by MLS, hashed into every commit, and read identically by every
//! member — which is what makes "this disappears in seven days" a sentence about the room rather
//! than about one screen.
//!
//! # What it does not do
//!
//! Nothing here is enforced on anybody's machine. A modified client keeps what it likes and
//! screenshots exist. What the feature buys is that the message does not end up in an archive
//! sitting on a server for the rest of time, and `Conversation` is where that half is arranged.

use crate::error::{CryptoError, Result};

/// Group context extension type carrying the lifetime.
///
/// `0xF101` sits in RFC 9420's private-use range, next to `roles::ROSTER_EXTENSION`. Adjacent on
/// purpose: the two are the same kind of thing — a policy of the room, in the authenticated state.
pub const LIFETIME_EXTENSION: u16 = 0xF101;

/// Seven days, in seconds: what every conversation this client creates starts with.
pub const DEFAULT_SECONDS: u32 = 7 * 24 * 60 * 60;

/// How long a message lives in this conversation. `0` is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetime(u32);

impl Lifetime {
    pub fn seconds(seconds: u32) -> Self {
        Self(seconds)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    /// `0` and an absent extension mean the same thing to a reader, and are different states to a
    /// writer: absent is a group that never had the feature, `0` is one where somebody turned it
    /// off. Both keep everything; only the second one posted a notice saying so.
    pub fn is_off(&self) -> bool {
        self.0 == 0
    }

    pub fn encode(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let four: [u8; 4] = bytes
            .try_into()
            .map_err(|_| CryptoError::PolicyViolation("lifetime extension of invalid length"))?;

        Ok(Self(u32::from_be_bytes(four)))
    }
}
```

Add to `crates/crypto-core/src/lib.rs`, in the module list kept alphabetical:

```rust
pub mod lifetime;
```

- [x] **Step 4: Run test to verify it passes**

Run: `cargo test -p crypto-core --lib lifetime`
Expected: PASS, four tests.

- [x] **Step 5: Commit**

```bash
git add crates/crypto-core/src/lifetime.rs crates/crypto-core/src/lib.rs
git commit -m "feat(crypto): a lifetime a room agrees on, not a note to oneself"
```

---

### Task 2: Carrying it without dropping the roster

**Files:**
- Modify: `crates/crypto-core/src/conversation.rs` (`roster_extension` at line 53, `create_with`, `set_roles`)
- Modify: `crates/crypto-core/src/identity.rs` (`capabilities`, line 30)
- Test: `crates/crypto-core/tests/lifetime.rs`

**Interfaces:**
- Consumes: `Lifetime`, `LIFETIME_EXTENSION`, `DEFAULT_SECONDS` from Task 1.
- Produces:
  - `fn context_extensions(roster: Option<&Roster>, lifetime: Option<Lifetime>) -> Result<Extensions<GroupContext>>` — replaces `roster_extension`.
  - `Conversation::lifetime(&self) -> Result<Option<Lifetime>>`
  - `Conversation::set_lifetime(&mut self, identity: &Identity, lifetime: Lifetime) -> Result<Change>`

**This is the task where the feature can silently destroy an existing one.** `update_group_context_extensions` replaces *all* extensions: setting the lifetime with a vector that omits the roster removes the roster, and the group becomes flat — everybody an administrator, silently, in a commit the others accept because it is well formed. Both setters must therefore rebuild the whole set from both current values.

- [x] **Step 1: Write the failing test**

`crates/crypto-core/tests/lifetime.rs`:

```rust
//! The conversation lifetime, where it lives and what it must not take with it.

mod common;

use crypto_core::lifetime::{DEFAULT_SECONDS, Lifetime};

/// A new administered group starts at seven days, and still has its admin.
#[test]
fn a_new_group_starts_at_seven_days() {
    let alice = common::identity("alice");
    let group = crypto_core::Conversation::create_administered(&alice, "alice".into()).unwrap();

    assert_eq!(group.lifetime().unwrap().map(|l| l.get()), Some(DEFAULT_SECONDS));
    assert_eq!(group.roster().unwrap().map(|r| r.admin().to_owned()), Some("alice".into()));
}

/// Setting the lifetime keeps the roster.
///
/// The failure this pins is not hypothetical: `update_group_context_extensions` replaces every
/// extension, so a setter that rebuilds only its own drops the roster and turns an administered
/// group flat — everyone an admin, in a commit the others accept because nothing about it is
/// malformed.
#[test]
fn setting_the_lifetime_keeps_the_roster() {
    let alice = common::identity("alice");
    let mut group = crypto_core::Conversation::create_administered(&alice, "alice".into()).unwrap();

    group.set_lifetime(&alice, Lifetime::seconds(3600)).unwrap();
    group.apply_pending(&alice).unwrap();

    assert_eq!(group.lifetime().unwrap().map(|l| l.get()), Some(3600));
    assert_eq!(
        group.roster().unwrap().map(|r| r.admin().to_owned()),
        Some("alice".into()),
        "the roster was dropped by a commit that only meant to change the lifetime"
    );
}

/// And the reverse: changing the roster keeps the lifetime.
#[test]
fn setting_the_roster_keeps_the_lifetime() {
    let alice = common::identity("alice");
    let mut group = crypto_core::Conversation::create_administered(&alice, "alice".into()).unwrap();

    group.set_lifetime(&alice, Lifetime::seconds(3600)).unwrap();
    group.apply_pending(&alice).unwrap();
    group.set_roles(&alice, "alice".into(), vec!["bob".into()]).unwrap();
    group.apply_pending(&alice).unwrap();

    assert_eq!(group.lifetime().unwrap().map(|l| l.get()), Some(3600));
}

/// A flat conversation — a 1-to-1 — also gets the default, and gains no roster from it.
#[test]
fn a_flat_conversation_has_a_lifetime_and_no_roster() {
    let alice = common::identity("alice");
    let group = crypto_core::Conversation::create(&alice).unwrap();

    assert_eq!(group.lifetime().unwrap().map(|l| l.get()), Some(DEFAULT_SECONDS));
    assert!(group.roster().unwrap().is_none());
}
```

**`crates/crypto-core/tests/common/` does not exist yet — this task creates it.** `roles.rs` and
`conversation.rs` each build their identities and their groups with helpers of their own. Lift the
ones this file needs into `crates/crypto-core/tests/common/mod.rs`, have the existing files call
the shared version, and do not write a second identity builder. `apply_pending` takes the identity
(`conversation.rs:190`), which is why it appears in every call above.

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p crypto-core --test lifetime`
Expected: FAIL — no method `lifetime` on `Conversation`.

- [x] **Step 3: Rebuild the whole extension set from both values**

Replace `roster_extension` in `crates/crypto-core/src/conversation.rs`:

```rust
/// The group context extensions, built from **every** policy the group carries.
///
/// # Why this takes both, always
///
/// `update_group_context_extensions` replaces the whole set. A setter that builds only its own
/// extension therefore deletes the other one, and the deletion is silent: the commit is well
/// formed, the other members apply it, and an administered group becomes flat — everybody an
/// admin — because somebody changed how long messages live. Both setters go through here, and
/// here reads the current state of both.
///
/// The required capabilities list every extension present, which is what stops a client that
/// cannot read one of them from joining and then applying a policy it never saw.
fn context_extensions(
    roster: Option<&Roster>,
    lifetime: Option<Lifetime>,
) -> Result<Extensions<GroupContext>> {
    let mut types = Vec::new();
    let mut extensions = Vec::new();

    if let Some(roster) = roster {
        types.push(ExtensionType::Unknown(ROSTER_EXTENSION));
        extensions.push(Extension::Unknown(
            ROSTER_EXTENSION,
            UnknownExtension(roster.encode()?),
        ));
    }

    if let Some(lifetime) = lifetime {
        types.push(ExtensionType::Unknown(LIFETIME_EXTENSION));
        extensions.push(Extension::Unknown(
            LIFETIME_EXTENSION,
            UnknownExtension(lifetime.encode().to_vec()),
        ));
    }

    extensions.insert(
        0,
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&types, &[], &[])),
    );

    Extensions::from_vec(extensions).map_err(mls)
}
```

`create_with` takes the lifetime too, and every conversation this client creates starts with the default:

```rust
    fn create_with(identity: &Identity, roster: Option<Roster>) -> Result<Self> {
        let mut builder = MlsGroupCreateConfig::builder()
            .ciphersuite(crate::identity::CIPHERSUITE)
            .capabilities(crate::identity::capabilities());

        // Every conversation starts at seven days, administered or flat. A 1-to-1 has no roster
        // and still has a lifetime: the two policies are independent, which is why the builder is
        // now called unconditionally.
        builder = builder.with_group_context_extensions(context_extensions(
            roster.as_ref(),
            Some(Lifetime::seconds(crate::lifetime::DEFAULT_SECONDS)),
        )?);

        let group = MlsGroup::new(
            &identity.provider,
            &identity.signer,
            &builder.build(),
            identity.credential.clone(),
        )
        .map_err(mls)?;

        Ok(Self { group })
    }
```

The reader and the setter:

```rust
    /// The conversation's lifetime, or `None` for a group predating the extension.
    ///
    /// Read from the group context, hence from authenticated state: neither the server nor a
    /// single member can forge it.
    pub fn lifetime(&self) -> Result<Option<Lifetime>> {
        match self.group.extensions().unknown(LIFETIME_EXTENSION) {
            Some(raw) => Lifetime::decode(&raw.0).map(Some),
            None => Ok(None),
        }
    }

    /// Sets how long messages live here. Subject to the policy: a member without a role sees
    /// their commit refused by the others.
    ///
    /// Not retroactive for what members already hold — MLS has no way to reach into their
    /// storage, and a policy that pretended otherwise would be a claim rather than a mechanism.
    /// What it does reach is the vault, and that is arranged on the client side.
    ///
    /// Same discipline as the rest: publish the commit before [`Conversation::apply_pending`].
    pub fn set_lifetime(&mut self, identity: &Identity, lifetime: Lifetime) -> Result<Change> {
        let roster = self.roster()?;

        let (commit, _welcome, _group_info) = self
            .group
            .update_group_context_extensions(
                &identity.provider,
                context_extensions(roster.as_ref(), Some(lifetime))?,
                &identity.signer,
            )
            .map_err(mls)?;

        self.change(commit)
    }
```

`set_roles` passes the current lifetime through in the same way: `context_extensions(Some(&roster), self.lifetime()?)`.

Read `set_roles`'s existing tail — the `Change` it builds from `commit` — and mirror it exactly in `set_lifetime` rather than inventing a second way to package a commit.

In `crates/crypto-core/src/identity.rs`, `capabilities` must advertise both, or a member cannot join a group carrying the new extension:

```rust
        Some(&[
            ExtensionType::Unknown(crate::roles::ROSTER_EXTENSION),
            ExtensionType::Unknown(crate::lifetime::LIFETIME_EXTENSION),
        ]),
```

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p crypto-core`
Expected: PASS — the four new tests, **and the whole existing suite**, `roles.rs` and `conversation.rs` included. A failure there means the extension set was rebuilt wrongly, which is exactly what Task 2 exists to get right.

- [x] **Step 5: Commit**

```bash
git add crates/crypto-core/src/conversation.rs crates/crypto-core/src/identity.rs crates/crypto-core/tests/lifetime.rs
git commit -m "feat(crypto): carry the lifetime beside the roster, never instead of it"
```

---

### Task 3: Who may change it

**Files:**
- Modify: `crates/crypto-core/src/roles.rs` (`CommitSummary`, `authorize`)
- Modify: `crates/crypto-core/src/conversation.rs` (`authorize_commit`, around line 432)
- Test: `crates/crypto-core/tests/roles.rs` (the pure rule) and `crates/crypto-core/tests/lifetime.rs` (the commit path)

**Interfaces:**
- Consumes: `CommitSummary`, `authorize` as they stand.
- Produces: `CommitSummary.changes_lifetime: bool`, and `changes_roster` narrowed to mean *the roster actually changed*.

`changes_roster` is currently computed as "any `GroupContextExtensions` proposal exists". A lifetime change is such a proposal, so left alone it would demand the admin. Both flags must come from **comparing the proposed extensions with the current ones**.

- [x] **Step 1: Write the failing test**

In `crates/crypto-core/tests/roles.rs`, beside the existing rule tests:

```rust
/// A moderator may change the lifetime. It is the same rank that admits and removes members.
#[test]
fn a_moderator_may_change_the_lifetime() {
    let roster = Roster::new("alice".into(), vec!["bob".into()]).unwrap();
    let summary = CommitSummary {
        committer: "bob",
        removals: Vec::new(),
        adds: 0,
        changes_roster: false,
        changes_lifetime: true,
        remaining: vec!["alice", "bob"],
    };

    assert!(authorize(Some(&roster), &summary, &Context::default()).is_ok());
}

/// An ordinary member may not.
#[test]
fn an_ordinary_member_may_not_change_the_lifetime() {
    let roster = Roster::new("alice".into(), vec!["bob".into()]).unwrap();
    let summary = CommitSummary {
        committer: "carol",
        removals: Vec::new(),
        adds: 0,
        changes_roster: false,
        changes_lifetime: true,
        remaining: vec!["alice", "bob", "carol"],
    };

    assert!(authorize(Some(&roster), &summary, &Context::default()).is_err());
}

/// A flat group has no rule to apply, and a 1-to-1 is a flat group.
#[test]
fn anyone_changes_the_lifetime_of_a_flat_group() {
    let summary = CommitSummary {
        committer: "carol",
        removals: Vec::new(),
        adds: 0,
        changes_roster: false,
        changes_lifetime: true,
        remaining: vec!["alice", "carol"],
    };

    assert!(authorize(None, &summary, &Context::default()).is_ok());
}
```

Match the construction style of the summaries already in that file — if they are built by a helper, use the helper and give it the new field.

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p crypto-core --test roles`
Expected: FAIL — `CommitSummary` has no field `changes_lifetime`.

- [x] **Step 3: Add the flag and the rule**

In `roles.rs`, on `CommitSummary`:

```rust
    /// The commit changes how long messages live here.
    ///
    /// Distinct from `changes_roster` although both travel as a `GroupContextExtensions`
    /// proposal, and the distinction is the rule: changing the room's memory is moderation, like
    /// admitting and removing members. Handing out power is not, and stays the admin's alone.
    pub changes_lifetime: bool,
```

In `authorize`, after the roster check:

```rust
    if commit.changes_lifetime && !committer_can_moderate {
        return Err(CryptoError::PolicyViolation(
            "changing the lifetime requires a role",
        ));
    }
```

And in the doc table above `authorize`, add the row so the prose keeps matching the code:

```rust
/// | change the lifetime | admin, moderator |
```

- [x] **Step 4: Compute the two flags by comparison**

In `conversation.rs`, `authorize_commit` replaces the single `changes_roster` line. Proposals carry the extensions they would install; decode them and compare against what the group holds now:

```rust
        // Both flags come from comparing what the proposal installs with what the group holds.
        // Testing for "a GroupContextExtensions proposal exists" cannot tell a lifetime change
        // from a roster change, and would demand the admin for both — silently making the
        // moderator's rank narrower than the table in `roles.rs` says it is.
        let proposed: Option<&Extensions<GroupContext>> = commit
            .queued_proposals()
            .find_map(|p| match p.proposal() {
                Proposal::GroupContextExtensions(gce) => Some(gce.extensions()),
                _ => None,
            });

        let (changes_roster, changes_lifetime) = match proposed {
            None => (false, false),
            Some(extensions) => {
                let new_roster = match extensions.unknown(ROSTER_EXTENSION) {
                    Some(raw) => Some(Roster::decode(&raw.0)?),
                    None => None,
                };
                let new_lifetime = match extensions.unknown(LIFETIME_EXTENSION) {
                    Some(raw) => Some(Lifetime::decode(&raw.0)?),
                    None => None,
                };

                (new_roster.as_ref() != Some(&roster), new_lifetime != self.lifetime()?)
            }
        };
```

`Roster` must derive `PartialEq` for that comparison — it already does; if a future edit removes it, this stops compiling, which is the right outcome.

Note what the comparison buys beyond the rank: a proposal that **drops** the roster reads as `new_roster = None`, which differs from the sitting roster, so it counts as a roster change and needs the admin. The silent-flattening commit of Task 2 is refused here even if a client is written to send it.

- [x] **Step 5: Add the commit-path test**

In `crates/crypto-core/tests/lifetime.rs`:

```rust
/// The rule is enforced on the commit, not merely in an interface.
///
/// Two members, one of them an ordinary member of an administered group: their commit changing
/// the lifetime is refused by the other side when it is applied, which is where enforcement has
/// to live. An interface that hides the control protects nobody from a client that does not.
#[test]
fn an_ordinary_members_lifetime_commit_is_refused_by_the_others() {
    // Build the two-member administered group the way `roles.rs` already does it, have the
    // ordinary member commit `set_lifetime`, hand the commit to the admin, and assert the
    // application fails with `PolicyViolation`.
    let (mut admin, mut member) = common::administered_pair("alice", "bob");

    let change = member.conversation.set_lifetime(&member.identity, Lifetime::seconds(60)).unwrap();

    let refused = admin.conversation.apply(&admin.identity, &change.commit);

    assert!(refused.is_err(), "an ordinary member changed the room's memory and it was accepted");
}
```

`common::administered_pair` is the helper for "two members of one administered group, able to hand
commits to each other". If `roles.rs` already has it under another name, move it into `common` in
Task 2's lift and call it; if it has no such helper, write it there. Its exact shape and the name
of the method that applies somebody else's commit come from that file — adjust the call, never the
property being asserted, which is that the refusal happens on application.

- [x] **Step 6: Run tests to verify they pass**

Run: `cargo test -p crypto-core`
Expected: PASS, whole crate.

- [x] **Step 7: Commit**

```bash
git add crates/crypto-core/src/roles.rs crates/crypto-core/src/conversation.rs crates/crypto-core/tests/roles.rs crates/crypto-core/tests/lifetime.rs
git commit -m "feat(crypto): moderation covers the room's memory, not just its membership"
```

---

### Task 4: Reaching it from JavaScript

**Files:**
- Modify: `crates/crypto-wasm/src/lib.rs`
- Modify (generated, by the build): `apps/web/src/lib/generated/crypto_wasm.js`, `crypto_wasm.d.ts`, `apps/web/public/crypto_wasm_bg.wasm`

**Interfaces:**
- Produces, on the conversation handle already exposed there: `lifetimeSeconds(): number | undefined` and `setLifetime(seconds: number): Uint8Array` (the commit to publish, matching how the existing `setRoles` returns its commit — read it and mirror it exactly).

- [x] **Step 1: Add the two bindings**

Follow the shape of the existing role bindings in that file: same error mapping through `to_js`, same handling of `Change`, same naming convention (`js_name` in camel case).

- [x] **Step 2: Rebuild the WebAssembly and its glue**

```bash
cd apps/web && pnpm run wasm
```

- [x] **Step 3: Verify the committed artefact matches its source**

Run: `./scripts/verify-wasm.sh`
Expected: three `ok` lines. This is what CI's `wasm` job checks, and the reason the binary is committed at all.

- [x] **Step 4: Commit**

```bash
git add crates/crypto-wasm/src/lib.rs apps/web/src/lib/generated apps/web/public/crypto_wasm_bg.wasm
git commit -m "feat(crypto-wasm): let the client read and set a conversation's lifetime"
```

---

### Task 5: Deleting a group's vault

**Files:**
- Modify: `crates/server/src/routes.rs` (route table around line 120, and a new handler beside `store_vault`)
- Test: `crates/server/tests/storage.rs`

**Interfaces:**
- Produces: `DELETE /v1/vault/{group_id}`, signed, deleting the calling account's entries for that group and crediting `account_storage`.

- [x] **Step 1: Write the failing test**

```rust
/// Dropping a group's vault removes that account's entries and gives the bytes back.
#[tokio::test]
async fn deleting_a_groups_vault_credits_the_account() {
    let server = start().await;
    let (alice, device, group) = account_with_group(&server, "alice").await;

    let path = format!("/v1/vault/{}", hex::encode(&group));
    device.post(&path, vault_body(1, 1000)).await;
    assert_eq!(counter(&server.pool, &alice.id).await, 1000);

    let response = device.signed_at("DELETE", &path, Vec::new(), now(), &path).await;
    assert!(response.status().is_success(), "delete refused: {}", response.status());

    assert_eq!(counter(&server.pool, &alice.id).await, 0);
    assert_eq!(counter(&server.pool, &alice.id).await, actually_stored(&server.pool, &alice.id).await);
}

/// It removes the caller's entries and nobody else's.
///
/// The vault is indexed by account, and two members of one group each have their own. A delete
/// that took the group's rows rather than the caller's would let anybody erase everybody's
/// archive of a shared conversation.
#[tokio::test]
async fn deleting_a_vault_leaves_the_other_members_alone() {
    let server = start().await;
    let (alice, alice_device, group) = account_with_group(&server, "alice").await;
    let bob = TestAccount::create(&server, &unique("bob")).await;
    let bob_device = bob.device(&server, &unique("device")).await;

    let path = format!("/v1/vault/{}", hex::encode(&group));
    alice_device
        .post(&format!("/v1/groups/{}/members", hex::encode(&group)),
              serde_json::json!({ "device_ids": [alice_device.id, bob_device.id] }))
        .await;
    alice_device.post(&path, vault_body(1, 1000)).await;
    bob_device.post(&path, vault_body(2, 700)).await;

    alice_device.signed_at("DELETE", &path, Vec::new(), now(), &path).await;

    assert_eq!(counter(&server.pool, &alice.id).await, 0);
    assert_eq!(counter(&server.pool, &bob.id).await, 700, "one member erased another's archive");
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `docker compose up -d && cargo test -p server --test storage`
Expected: FAIL — 405, the route does not exist.

- [x] **Step 3: Write the handler**

Beside `store_vault`, and registered as `.delete(drop_vault)` on the existing `/v1/vault/{group_id}` route:

```rust
/// Drops the caller's vault for one group.
///
/// # Why the caller's and not the group's
///
/// The vault is indexed by account: two members of one conversation each hold their own archive
/// of it, sealed under their own key. Deleting by group would let either of them destroy the
/// other's copy of a shared history — which is not what turning on a lifetime asks for, and is
/// not something one member gets to do to another.
///
/// The bytes are credited in the same transaction that removes the rows, as `purge_once` does:
/// see `crate::storage` for what drifts when a deletion path forgets.
async fn drop_vault(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let group_id = decode_group_id(&group_id)?;
    let account = caller_account(&pool, &signed.device_id).await?;

    let mut tx = pool.begin().await?;

    let (removed, bytes): (i64, i64) = sqlx::query_as(
        "WITH gone AS (
             DELETE FROM vault_entries
              WHERE account = $1 AND group_id = $2
          RETURNING octet_length(payload) AS bytes
         )
         SELECT count(*)::bigint, COALESCE(SUM(bytes), 0)::bigint FROM gone",
    )
    .bind(&account)
    .bind(&group_id)
    .fetch_one(&mut *tx)
    .await?;

    crate::storage::credit(&mut tx, &account, bytes).await?;
    tx.commit().await?;

    Ok(Json(serde_json::json!({ "removed": removed })))
}
```

No membership check, deliberately, and say so in the comment: the caller can only ever delete rows keyed to their own account, so a non-member deleting their own (empty) vault for a group they left is a no-op rather than a leak — and requiring membership would leave somebody who was removed from a group unable to erase their own archive of it.

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p server --test storage`
Expected: PASS, all storage tests including the reconciliation one.

- [x] **Step 5: Commit**

```bash
git add crates/server/src/routes.rs crates/server/tests/storage.rs
git commit -m "feat(server): let an account drop its own archive of one conversation"
```

---

### Task 6: Saying it in the thread

**Files:**
- Modify: `apps/web/src/lib/content.ts` (a new `TYPE_EXPIRY = 14`, its encoder, its branch in `encodeBody` and in the decoder around line 682)
- Modify: `apps/web/src/lib/session-types.ts` (the `Content` union)
- Modify: `apps/web/src/lib/i18n.ts` and the thread renderer, wherever `membership` notices are turned into a sentence
- Test: `apps/web/src/lib/content.test.ts`

**Interfaces:**
- Produces: `{ kind: "expiry"; seconds: number }` in `Content`, `encodeExpiry(seconds: number): Uint8Array`.

- [x] **Step 1: Write the failing test**

```ts
test("an expiry notice survives the round trip", () => {
  const encoded = encode({ kind: "expiry", seconds: 604800 });
  const decoded = decode(encoded);

  assert.deepEqual(decoded.body, { kind: "expiry", seconds: 604800 });
});

test("turning it off is a notice too, and is not an absent one", () => {
  const decoded = decode(encode({ kind: "expiry", seconds: 0 }));

  assert.deepEqual(decoded.body, { kind: "expiry", seconds: 0 });
});
```

Use the same `encode`/`decode` entry points the neighbouring tests in that file use, and match their assertion style.

- [x] **Step 2: Run test to verify it fails**

Run: `cd apps/web && pnpm test`
Expected: FAIL — the union has no `expiry`.

- [x] **Step 3: Add the kind**

```ts
/**
 * A change to how long this conversation keeps what is said in it.
 *
 * A notice rather than a silent setting, for the reason membership notices exist: a room whose
 * memory grows from seven days to a year has changed in the way that matters, and the change
 * belongs in the history where everybody sees it rather than in a menu somebody may never open.
 */
const TYPE_EXPIRY = 14;

export function encodeExpiry(seconds: number): Uint8Array {
  const out = new Uint8Array(5);
  out[0] = TYPE_EXPIRY;
  new DataView(out.buffer).setUint32(1, seconds, false);
  return out;
}
```

Its branch in `encodeBody`, its case in the decoder (four bytes, big-endian, refusing a body of any other length as the neighbouring cases refuse theirs), and `| { kind: "expiry"; seconds: number }` in the `Content` union.

The sentence in the thread names the actor and the value, as membership notices do: *"Alice set messages to disappear after 7 days"*, and for `0`: *"Alice turned off disappearing messages"*. Put it where the membership sentences are built, not in the component.

- [x] **Step 4: Run tests to verify they pass**

Run: `cd apps/web && pnpm test && pnpm run typecheck && pnpm run lint`
Expected: PASS, all three.

- [x] **Step 5: Commit**

```bash
git add apps/web/src/lib/content.ts apps/web/src/lib/content.test.ts apps/web/src/lib/session-types.ts apps/web/src/lib/i18n.ts
git commit -m "feat(content): say in the thread when the room's memory changes"
```

---

### Task 7: The expiry, stamped once and clamped

**Files:**
- Modify: `apps/web/src/lib/session-types.ts` (`Message` gains `expiresAt?: number`; `ConversationFlags.ephemeralMs` **is removed**)
- Create: `apps/web/src/lib/expiry.ts`
- Test: `apps/web/src/lib/expiry.test.ts`

**Interfaces:**
- Produces:
  - `export function expiryOf(sentAt: number | undefined, seenAt: number, lifetimeSeconds: number): number | undefined`
  - `export function isExpired(message: Message, now: number): boolean`
  - `export function prune(messages: Message[], now: number): Message[]`

- [x] **Step 1: Write the failing test**

```ts
import assert from "node:assert/strict";
import { test } from "node:test";

import { expiryOf, isExpired, prune } from "./expiry.ts";

const HOUR = 3600;

test("the deadline runs from when the sender says they wrote it", () => {
  assert.equal(expiryOf(1_000_000, 1_000_500, HOUR), 1_000_000 + HOUR * 1000);
});

test("a sender cannot buy time by post-dating their own message", () => {
  // sentAt an hour in the future, seen now: the clamp takes the moment it was seen.
  const seen = 1_000_000;
  assert.equal(expiryOf(seen + HOUR * 1000, seen, HOUR), seen + HOUR * 1000);
});

test("a sender may shorten their own message, which was never forbidden", () => {
  const seen = 1_000_000;
  const sent = seen - HOUR * 1000;
  assert.equal(expiryOf(sent, seen, HOUR), sent + HOUR * 1000);
});

test("no lifetime means no deadline", () => {
  assert.equal(expiryOf(1_000_000, 1_000_000, 0), undefined);
});

test("control traffic carries no sentAt and never expires", () => {
  // Expiring a membership notice would leave a thread describing a room nobody joined.
  assert.equal(expiryOf(undefined, 1_000_000, HOUR), undefined);
});

test("pruning drops what is past and keeps the rest, in order", () => {
  const now = 2_000_000;
  const messages = [
    { seq: 1, sender: "bob", mine: false, content: { kind: "text", text: "old" }, expiresAt: now - 1 },
    { seq: 2, sender: "bob", mine: false, content: { kind: "text", text: "kept" }, expiresAt: now + 1 },
    { seq: 3, sender: "bob", mine: false, content: { kind: "text", text: "no deadline" } },
  ] as Message[];

  assert.deepEqual(prune(messages, now).map((m) => m.seq), [2, 3]);
});

test("a message already past its deadline when it arrives is expired on arrival", () => {
  const now = 2_000_000;
  const message = { seq: 1, sender: "bob", mine: false, content: { kind: "text", text: "late" }, expiresAt: now - 1 } as Message;

  assert.equal(isExpired(message, now), true);
});
```

- [x] **Step 2: Run test to verify it fails**

Run: `cd apps/web && pnpm test`
Expected: FAIL — cannot find module `./expiry.ts`.

- [x] **Step 3: Write the module**

```ts
/**
 * When a message stops existing, and why that is computed once rather than read from a clock.
 *
 * # The lie the sender can tell
 *
 * `sentAt` travels inside the MLS message and its own documentation states the important half:
 * declared, not proven. A member can put a future timestamp in their own message and buy it a
 * longer life. So the deadline is `min(sentAt, first seen here) + lifetime`: shortening one's own
 * message stays possible, which was never forbidden, and extending it does not.
 *
 * # Why the deadline is stamped and stored
 *
 * A message keeps the deadline it was given when it arrived, even if the conversation's lifetime
 * changes afterwards. That is what "turning it on is not retroactive" means in code, and it also
 * means a device that was offline during a change does not recompute a different answer from the
 * same history.
 */
import type { Message } from "./session-types.ts";

/** The deadline for a message, or `undefined` when nothing expires it. */
export function expiryOf(
  sentAt: number | undefined,
  seenAt: number,
  lifetimeSeconds: number,
): number | undefined {
  if (lifetimeSeconds <= 0) return undefined;
  // Control traffic is not history: a membership notice that expired would leave a thread
  // describing a room nobody ever joined.
  if (sentAt === undefined) return undefined;

  return Math.min(sentAt, seenAt) + lifetimeSeconds * 1000;
}

export function isExpired(message: Message, now: number): boolean {
  return message.expiresAt !== undefined && message.expiresAt <= now;
}

/** The messages that are still alive, in the order they were given. */
export function prune(messages: Message[], now: number): Message[] {
  return messages.filter((message) => !isExpired(message, now));
}
```

- [x] **Step 4: Remove the flag this replaces**

Delete `ephemeralMs` from `ConversationFlags` in `session-types.ts`. It is a local preference promising the same thing and enforcing nothing; leaving it beside a group policy that does would make two features out of one, and the wrong one would be the easier to find. `grep -rn "ephemeralMs" apps/web/src` must come back empty.

- [x] **Step 5: Run tests to verify they pass**

Run: `cd apps/web && pnpm test && pnpm run typecheck`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add apps/web/src/lib/expiry.ts apps/web/src/lib/expiry.test.ts apps/web/src/lib/session-types.ts
git commit -m "feat(web): a deadline the sender cannot extend"
```

---

### Task 8: Wiring it into the session

**Files:**
- Modify: `apps/web/src/lib/session.ts` (message insertion, the periodic poll, the vault decision)
- Modify: `apps/web/src/lib/session-vault.ts` (refuse to archive an ephemeral room)
- Modify: `apps/web/src/lib/content.ts` consumers where a decoded message becomes a `Message`
- Test: `apps/web/src/lib/session-vault.test.ts`, and the session tests where messages are inserted

**Interfaces:**
- Consumes: `expiryOf`, `isExpired`, `prune`, `Conversation.lifetimeSeconds()` from Task 4.

- [x] **Step 1: Write the failing test**

```ts
test("an ephemeral conversation is never archived", async () => {
  const archive = await Archive.open(() => KEY);
  const api = server();

  await archive.store(api, GROUP, [said(1, "hi")], { lifetimeSeconds: 604800 });

  // Not "tried and refused" — never asked. A room that forgets must not be leaving copies on a
  // server that does not.
  assert.equal((api as unknown as { kept: number }).kept, 0);
});

test("a conversation with no lifetime is archived as before", async () => {
  const archive = await Archive.open(() => KEY);
  const api = server();

  await archive.store(api, GROUP, [said(1, "hi")], { lifetimeSeconds: 0 });

  assert.equal((api as unknown as { kept: number }).kept, 1);
});
```

- [x] **Step 2: Run test to verify it fails**

Run: `cd apps/web && pnpm test`
Expected: FAIL — `store` takes no such argument.

- [x] **Step 3: Wire the three places**

1. **On insertion**, every message built from a decoded envelope gets `expiresAt = expiryOf(sentAt, Date.now(), lifetime)`, and one already expired is **not inserted at all**. A device back from ten days offline must not see expired messages appear and then vanish.
2. **On the poll** that already sweeps conversations every thirty seconds, `prune` each open view and persist the result. Reuse that timer; a second one for expiry would be a second clock to keep in step.
3. **On the vault**, `Archive.store` takes the conversation's lifetime and returns without asking when it is non-zero.

- [x] **Step 4: Run tests to verify they pass**

Run: `cd apps/web && pnpm test && pnpm run typecheck && pnpm run lint`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add apps/web/src/lib/session.ts apps/web/src/lib/session-vault.ts apps/web/src/lib/session-vault.test.ts apps/web/src/lib/content.ts
git commit -m "feat(web): drop what has expired, and archive nothing that will"
```

---

### Task 9: The screen, and what it must say before the control

**Files:**
- Modify: the conversation information panel (the component holding the per-conversation settings — find it with `grep -rn "archiveToVault" apps/web/src/components`)

- [x] **Step 1: Add the control**

A choice of lifetimes — off, one day, seven days, thirty days — shown to everybody, enabled only for a member who may moderate, and disabled with the reason rather than hidden: somebody who cannot change it should learn that a rank is required, not that the feature does not exist.

- [x] **Step 2: Write the two sentences that have to be there**

Above the control, not beneath it:

> Messages sent from now on disappear for everybody after this delay. **Nothing enforces it on the other side**: a modified client keeps what it likes, and screenshots exist. What it does guarantee is that they are not archived on this server.

And where the lifetime is on, next to the backup setting:

> This conversation is not backed up. If you lose every device, it does not come back — including what was written today.

- [x] **Step 3: Turning it on offers the deletion it implies**

Switching a lifetime on calls `DELETE /v1/vault/{group}` from Task 5, and the confirmation says what is about to be destroyed: this account's archive of this conversation, on the server, irreversibly. `archiveToVault`'s own doc comment already states the rule this follows — *"the screen that offers it has to offer the deletion too or it is claiming something it has not done"*.

- [x] **Step 4: Verify**

Run: `cd apps/web && pnpm test && pnpm run typecheck && pnpm run lint`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add apps/web/src/components
git commit -m "feat(ui): offer a lifetime, and say what it does not do first"
```

---

### Task 10: The prose, the whole suite, the pull request

**Files:**
- Modify: `README.md`, `docs/PROTOCOL.md`, `docs/THREAT-MODEL.md`, `docs/SECURITY-PROPERTIES.md`, `docs/ROADMAP.md`

- [x] **Step 1: Document the extension where the other one is documented**

`docs/PROTOCOL.md` describes `0xF100` and its encoding. `0xF101` goes beside it: four bytes big-endian, seconds, `0` off, absent off, required capabilities, and the rank that may change it.

- [x] **Step 2: State the change of default**

`README.md`'s status table and `docs/ROADMAP.md`: conversations keep seven days by default, and an ephemeral conversation is not archived, so it does not survive the loss of every device. That is a different product from the one the vault row currently describes, and both rows have to agree.

- [x] **Step 3: State what it does not defend against**

`docs/THREAT-MODEL.md`: deletion is client-side and unenforceable — screenshots, a modified client, a member who keeps what they like. The server keeps ciphertext up to thirty days and never learns the lifetime. A message never delivered inside the lifetime is lost rather than deleted.

`docs/SECURITY-PROPERTIES.md`: what is actually claimed is that an ephemeral message is never deposited in the vault, and that is testable — it is the test of Task 8.

- [x] **Step 4: Run everything**

```bash
docker compose up -d
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
./scripts/verify-wasm.sh
cd apps/web && pnpm test && pnpm run typecheck && pnpm run lint
```

Expected: green throughout.

- [x] **Step 5: Open the pull request against `dev`**

Explain the decision rather than the diff: why the lifetime is a group policy and not a preference, why the clamp on `sentAt` exists, why the vault loses, why turning it on is not retroactive for messages and is for the vault, and that the default changes what the product is. Say what was run.
