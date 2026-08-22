//! WebAssembly binding for `crypto-core`.
//!
//! # The E2EE guarantee is weaker in a browser
//!
//! The server ships the JavaScript on every page load. Nothing stops a compromised — or
//! coerced — server from serving a modified build that exfiltrates the keys. No amount of
//! WebCrypto, WASM or non-extractable keys fixes that: the problem is structural.
//!
//! What the web still buys you:
//!
//! * keys kept out of reach of application JS (non-extractable `CryptoKey`);
//! * a strict CSP and subresource integrity to cut down on third-party scripts;
//! * code transparency, to make a targeted delivery detectable.
//!
//! What only a native app or a signed extension gives you: the certainty that the code
//! running today is the code that was audited yesterday.
//!
//! This limit must be **told to the user** in the interface, not buried in a privacy policy.
//!
//! # In-memory state
//!
//! This module keeps session state in WASM linear memory. It is lost on page reload: the
//! caller must persist [`Client::export_state`] and re-encrypt it at rest.

use std::collections::HashMap;

use crypto_core::lock::derive_unlock_key;
use crypto_core::pairing::{PairingOffer, seal};
use crypto_core::{Account, Conversation, Identity, Incoming};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// The single JavaScript-side handle: one device identity and its conversations.
///
/// Conversations are indexed by group id rather than exposed as separate objects. Juggling
/// two paired handles from JS — an identity and a conversation — invites mixing them up, and
/// encrypting with the wrong identity fails silently.
#[wasm_bindgen]
pub struct Client {
    identity: Identity,
    conversations: HashMap<Vec<u8>, Conversation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitationJs {
    #[serde(with = "serde_bytes")]
    commit: Vec<u8>,
    #[serde(with = "serde_bytes")]
    welcome: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum IncomingJs {
    /// A message to display.
    Application {
        sender: Option<String>,
        #[serde(with = "serde_bytes")]
        plaintext: Vec<u8>,
    },
    /// Group membership or keys changed: refresh the displayed fingerprints.
    GroupChanged,
    /// A proposal waiting for a commit. Nothing to display.
    Proposal,
}

/// The roles of a group, as read from the group context.
#[derive(Serialize)]
struct RosterJs {
    admin: String,
    moderators: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerJs {
    name: String,
    fingerprint: String,
}

#[wasm_bindgen]
impl Client {
    /// Creates a device identity.
    ///
    /// `name` travels in the clear inside the MLS credential and is visible to the server and
    /// to every group member. Put nothing sensitive in it.
    #[wasm_bindgen(js_name = create)]
    pub fn create(name: &str) -> Result<Client, JsError> {
        Ok(Self {
            identity: Identity::create(name).map_err(to_js)?,
            conversations: HashMap::new(),
        })
    }

    /// Rebuilds a client from an exported state.
    ///
    /// `groupIds` is the list of conversations to reload. MLS storage offers no enumeration:
    /// keeping that list, alongside the state, is the caller's job.
    ///
    /// **Never** restore a state older than the last one exported: groups would roll back an
    /// epoch and replay keys already used. An MLS state is not an ordinary backup — only one
    /// live copy may exist.
    #[wasm_bindgen(js_name = restore)]
    pub fn restore(state: &[u8], group_ids: Vec<js_sys::Uint8Array>) -> Result<Client, JsError> {
        let identity = Identity::restore(state).map_err(to_js)?;

        let mut conversations = HashMap::new();
        for group_id in group_ids {
            let group_id = group_id.to_vec();
            let conversation = Conversation::load(&identity, &group_id).map_err(to_js)?;
            conversations.insert(group_id, conversation);
        }

        Ok(Self { identity, conversations })
    }

    /// Ids of the open conversations, to persist next to the state so they can be reloaded
    /// through [`Client::restore`].
    #[wasm_bindgen(js_name = conversationIds)]
    pub fn conversation_ids(&self) -> Vec<js_sys::Uint8Array> {
        self.conversations
            .keys()
            .map(|id| js_sys::Uint8Array::from(id.as_slice()))
            .collect()
    }

    /// This device's name, as written into the MLS credential.
    #[wasm_bindgen(js_name = name)]
    pub fn name(&self) -> String {
        self.identity.name().to_owned()
    }

    /// Produces a KeyPackage to publish on the server.
    ///
    /// **Single use.** The server must remove it from the pool as soon as it serves it, and
    /// the caller must restock regularly: with an empty pool, nobody can open a conversation
    /// with this device any more.
    #[wasm_bindgen(js_name = publishKeyPackage)]
    pub fn publish_key_package(&self) -> Result<Vec<u8>, JsError> {
        self.identity.publish_key_package().map_err(to_js)
    }

    /// This device's fingerprint, to display so the peer can compare it.
    /// This device's MLS signature public key.
    ///
    /// It must be attested by the account **at the same time** as the HTTP authentication
    /// key: attested separately, a legitimate device's attestation could be recombined with a
    /// hostile device's MLS key.
    #[wasm_bindgen(js_name = signatureKey)]
    pub fn signature_key(&self) -> Vec<u8> {
        self.identity.signature_key().to_vec()
    }

    #[wasm_bindgen(js_name = fingerprint)]
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Creates a conversation and returns its group id.
    #[wasm_bindgen(js_name = createConversation)]
    pub fn create_conversation(&mut self) -> Result<Vec<u8>, JsError> {
        let conversation = Conversation::create(&self.identity).map_err(to_js)?;
        let id = conversation.id();
        self.conversations.insert(id.clone(), conversation);
        Ok(id)
    }

    /// Creates an administered group. The creator is its one and only admin.
    ///
    /// Reserve this for real groups. A 1-to-1 must go through `createConversation`: roles make
    /// no sense there, and the flat group is the correct shape.
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(&mut self, admin: String) -> Result<Vec<u8>, JsError> {
        let conversation =
            Conversation::create_administered(&self.identity, admin).map_err(to_js)?;
        let id = conversation.id();
        self.conversations.insert(id.clone(), conversation);
        Ok(id)
    }

    /// The group roster: `{admin, moderators}`, or `null` if the group is flat.
    #[wasm_bindgen(js_name = roster)]
    pub fn roster(&self, group_id: &[u8]) -> Result<JsValue, JsError> {
        let roster = self
            .conversations
            .get(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .roster()
            .map_err(to_js)?;

        to_value(&roster.map(|r| RosterJs {
            admin: r.admin().to_owned(),
            moderators: r.moderators().to_vec(),
        }))
    }

    /// Replaces the group's roles. Like every commit, publish it before `applyPending`.
    ///
    /// Passing an `admin` different from the current one **hands the group over**: the sender
    /// cannot take it back.
    #[wasm_bindgen(js_name = setRoles)]
    pub fn set_roles(
        &mut self,
        group_id: &[u8],
        admin: String,
        moderators: Vec<String>,
    ) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        Ok(self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .set_roles(identity, admin, moderators)
            .map_err(to_js)?
            .commit)
    }

    /// Prepares the removal of a member, designated by their MLS signature key.
    ///
    /// It is this removal — not server-side filtering — that actually cuts the device off from
    /// what follows: the commit re-keys the tree. Same discipline as `invite`: publish, then
    /// `applyPending`.
    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(&mut self, group_id: &[u8], mls_key: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        Ok(self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .remove(identity, mls_key)
            .map_err(to_js)?
            .commit)
    }

    /// Asks to leave the group. Returns a **proposal**, not a commit.
    ///
    /// RFC 9420 forbids removing yourself in a commit you generate: another member has to pick
    /// it up through `commitPending`. Display the consequence honestly — until someone
    /// commits, the departure has not happened and the conversation is still being read.
    #[wasm_bindgen(js_name = leaveGroup)]
    pub fn leave_group(&mut self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        self.conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .leave(identity)
            .map_err(to_js)
    }

    /// Commits the pending proposals — typically a member's request to leave.
    #[wasm_bindgen(js_name = commitPending)]
    pub fn commit_pending(&mut self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        Ok(self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .commit_pending(identity)
            .map_err(to_js)?
            .commit)
    }

    /// The other members' MLS signature keys, as they appear in the tree.
    ///
    /// Comes from the authenticated state, not from the server. This is what lets the client
    /// notice that a member of the tree is no longer among its account's active devices.
    #[wasm_bindgen(js_name = peerSignatureKeys)]
    pub fn peer_signature_keys(&self, group_id: &[u8]) -> Result<JsValue, JsError> {
        let keys = self
            .conversations
            .get(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .peer_signature_keys(&self.identity);

        to_value(&keys.into_iter().map(serde_bytes::ByteBuf::from).collect::<Vec<_>>())
    }

    /// Prepares the addition of a member. Returns `{commit, welcome}` **without applying
    /// anything**.
    ///
    /// The two halves go to different places: the `commit` to the members already present, the
    /// `welcome` to the invitee alone.
    ///
    /// The group stays at its current epoch until [`Client::applyPending`]. Publish first,
    /// apply second: the reverse breaks the group beyond repair if publication fails — the
    /// sender would have changed epoch, the others not, and the commit would be lost.
    #[wasm_bindgen(js_name = invite)]
    pub fn invite(&mut self, group_id: &[u8], key_package: &[u8]) -> Result<JsValue, JsError> {
        // `identity` is pulled out of `self` before the mutable borrow of the map: the two
        // fields are disjoint, but going through a method would borrow all of `self`.
        let identity = &self.identity;
        let invitation = self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .invite(identity, key_package)
            .map_err(to_js)?;

        to_value(&InvitationJs {
            commit: invitation.commit,
            welcome: invitation.welcome,
        })
    }

    /// Applies the commit prepared by `invite`, once it has been published.
    ///
    /// Returns the up-to-date ratchet tree, to hand to the invitee along with their Welcome. It
    /// cannot be produced any earlier: until the commit is applied, the tree does not contain
    /// the new member and their Welcome would be rejected.
    #[wasm_bindgen(js_name = applyPending)]
    pub fn apply_pending(&mut self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        self.conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .apply_pending(identity)
            .map_err(to_js)
    }

    /// Joins a conversation from a Welcome. Returns the group id.
    #[wasm_bindgen(js_name = join)]
    pub fn join(&mut self, welcome: &[u8], ratchet_tree: &[u8]) -> Result<Vec<u8>, JsError> {
        let conversation =
            Conversation::join(&self.identity, welcome, ratchet_tree).map_err(to_js)?;
        let id = conversation.id();
        self.conversations.insert(id.clone(), conversation);
        Ok(id)
    }

    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        self.conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .encrypt(identity, plaintext)
            .map_err(to_js)
    }

    /// Processes an incoming message: application data or a group change.
    ///
    /// The result must be handled in both cases. Ignoring a `groupChanged` leaves the device at
    /// a stale epoch, and everything that follows becomes undecryptable.
    #[wasm_bindgen(js_name = process)]
    pub fn process(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        revoked: Vec<js_sys::Uint8Array>,
    ) -> Result<JsValue, JsError> {
        // MLS signature keys whose revocation certificate the client has **verified**.
        //
        // An empty list is not neutral: it makes the removal of a revoked device by a
        // non-admin member fail — exactly the stolen-phone case. The client must fill it from
        // the device list of the account concerned, after verification.
        let context = crypto_core::roles::Context {
            revoked: revoked.iter().map(|k| k.to_vec()).collect(),
        };

        let identity = &self.identity;
        let incoming = self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))?
            .process(identity, message, &context)
            .map_err(to_js)?;

        to_value(&match incoming {
            Incoming::Application { sender, plaintext } => {
                IncomingJs::Application { sender, plaintext }
            }
            Incoming::GroupChanged => IncomingJs::GroupChanged,
            Incoming::Proposal => IncomingJs::Proposal,
        })
    }

    /// The other members' fingerprints, to be compared out of band.
    ///
    /// The interface must make that comparison possible and understandable. Without it, a
    /// malicious server can sit in the middle of two perfectly encrypted sessions with no
    /// cryptographic check catching it.
    #[wasm_bindgen(js_name = peerFingerprints)]
    pub fn peer_fingerprints(&self, group_id: &[u8]) -> Result<JsValue, JsError> {
        let peers: Vec<PeerJs> = self
            .conversation(group_id)?
            .peer_fingerprints(&self.identity)
            .into_iter()
            .map(|(name, fingerprint)| PeerJs { name, fingerprint })
            .collect();

        to_value(&peers)
    }

    /// Symmetric key of this group's ephemeral channel, for the current epoch.
    ///
    /// **These bytes must only serve throwaway signals.** They do not go through the
    /// application ratchet, so they offer no forward secrecy within an epoch, and they do not
    /// authenticate the sender — the key belongs to the group. Routing a message through them
    /// would forfeit both properties MLS was chosen for.
    ///
    /// The key changes on every commit: a removed member loses this channel along with the
    /// rest, with no special handling.
    #[wasm_bindgen(js_name = signalKey)]
    pub fn signal_key(&self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.conversation(group_id)?.signal_key(&self.identity)?)
    }

    /// The group's current epoch. Two members at different epochs cannot read each other:
    /// it is the first thing to look at when a message does not go through.
    #[wasm_bindgen(js_name = epoch)]
    pub fn epoch(&self, group_id: &[u8]) -> Result<u64, JsError> {
        Ok(self.conversation(group_id)?.epoch())
    }

    /// Exports the complete session state.
    ///
    /// **This blob contains the private keys in the clear.** It must never reach
    /// `localStorage`, a backup, or the server. Encrypt it first with a non-extractable
    /// `CryptoKey` held in IndexedDB.
    ///
    /// Never restore an *old* state: it rolls the group back an epoch and replays keys already
    /// used, destroying forward secrecy.
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Result<Vec<u8>, JsError> {
        self.identity.export_state().map_err(to_js)
    }

    fn conversation(&self, group_id: &[u8]) -> Result<&Conversation, JsError> {
        self.conversations
            .get(group_id)
            .ok_or_else(|| JsError::new("unknown conversation"))
    }
}

/// Errors crossing the WASM boundary are flattened into a message.
///
/// They must never carry secret material: an error message ends up in the console, in a crash
/// report, or in a third-party telemetry service.
fn to_js(err: crypto_core::CryptoError) -> JsError {
    JsError::new(&err.to_string())
}

/// Serializes to JavaScript producing real `Uint8Array`s.
///
/// `serde_wasm_bindgen` does produce a `Uint8Array` — but only for values that go through
/// `serialize_bytes`. `Vec<u8>` takes the "sequence" path by default and comes out as an
/// `Array` of numbers. JavaScript then receives something that *looks* like a byte array but
/// that `TextDecoder`, `fetch` or `crypto.subtle` refuse. Combined with `#[serde(with =
/// "serde_bytes")]` on the fields concerned, this serializer produces the right type.
///
/// Note: `wasm-bindgen-test` tests do not catch this flaw, because they deserialize into Rust
/// types, which accept both representations. Only a real JavaScript client reveals it.
fn to_value<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    let serializer = serde_wasm_bindgen::Serializer::new();
    value
        .serialize(&serializer)
        .map_err(|e| JsError::new(&e.to_string()))
}


/// Handle on the pseudonymous account.
///
/// Kept separate from [`Client`] on purpose: an account outlives its devices, and a device can
/// exist for the duration of a pairing without ever holding the account key. Merging them
/// would suggest one implies the other.
///
/// **This object holds the account's root key.** Losing it means losing the account;
/// disclosing it means giving the account away.
#[wasm_bindgen]
pub struct AccountKey {
    inner: Account,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedAccountJs {
    /// To display **once only**. It is not kept and cannot be shown again: a phrase the app can
    /// re-display is a phrase the thief of an unlocked device can re-display too.
    phrase: String,
    #[serde(with = "serde_bytes")]
    identity_key: Vec<u8>,
}

#[wasm_bindgen]
impl AccountKey {
    /// Creates an account and returns `{phrase, identityKey}`.
    pub fn generate() -> Result<JsValue, JsError> {
        let (inner, phrase) = Account::generate().map_err(to_js)?;
        let identity_key = inner.identity_key().to_vec();

        // The handle is dropped here: the caller calls `restore` again with the phrase.
        // Returning both an object and a handle would force JS to keep them paired, and a
        // phrase orphaned from its account is exactly the bug we do not want.
        drop(inner);
        to_value(&CreatedAccountJs { phrase, identity_key })
    }

    /// Rebuilds the account from its recovery phrase.
    pub fn restore(phrase: &str) -> Result<AccountKey, JsError> {
        Ok(Self { inner: Account::from_phrase(phrase).map_err(to_js)? })
    }

    /// Rebuilds the account from the seed received during a pairing.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8]) -> Result<AccountKey, JsError> {
        let seed: [u8; 64] = seed
            .try_into()
            .map_err(|_| JsError::new("account seed of invalid size"))?;
        Ok(Self { inner: Account::from_seed(seed) })
    }

    #[wasm_bindgen(js_name = identityKey)]
    pub fn identity_key(&self) -> Vec<u8> {
        self.inner.identity_key().to_vec()
    }

    /// The account fingerprint, to be compared out of band.
    ///
    /// Stable when the account gains or loses a device: a hostile device is caught by the
    /// device-added notification, not by a fingerprint change that would be ignored from
    /// happening legitimately too often.
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    /// Signs a device's membership of this account.
    pub fn attest(
        &self,
        handle: &str,
        device_id: &str,
        auth_key: &[u8],
        mls_key: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.attest(handle, device_id, auth_key, mls_key).map_err(to_js)?.to_vec())
    }

    /// Signs the revocation of a device of this account.
    ///
    /// The certificate is verifiable by anyone holding the account's public key: that is what
    /// lets **another** group member commit the removal without taking the server's word for
    /// it.
    pub fn revoke(
        &self,
        handle: &str,
        device_id: &str,
        revoked_at: u64,
    ) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.revoke(handle, device_id, revoked_at).map_err(to_js)?.to_vec())
    }

    /// Signs this account's move to a new identity key.
    ///
    /// Call it on the **old** account, which thereby names its successor.
    ///
    /// This is the only real answer to a stolen device: it holds the seed, hence the whole
    /// account, and revoking it does not stop it from attesting a new one. Rotation, on the
    /// other hand, invalidates every attestation at once.
    pub fn rotate(
        &self,
        handle: &str,
        new_identity_key: &[u8],
        rotated_at: u64,
    ) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.rotate(handle, new_identity_key, rotated_at).map_err(to_js)?.to_vec())
    }

    /// Seed to hand to a device being paired. **It is worth the whole account.**
    #[wasm_bindgen(js_name = exportSeed)]
    pub fn export_seed(&self) -> Vec<u8> {
        self.inner.export_seed().to_vec()
    }

    /// Symmetric key of the backup vault, derived on demand.
    #[wasm_bindgen(js_name = vaultKey)]
    pub fn vault_key(&self) -> Vec<u8> {
        self.inner.vault_key().to_vec()
    }

    /// Symmetric key every device of the account shares, for the state they owe each other.
    ///
    /// Distinct from the vault key on purpose — see `Account::device_sync_key`.
    #[wasm_bindgen(js_name = deviceSyncKey)]
    pub fn device_sync_key(&self) -> Vec<u8> {
        self.inner.device_sync_key().to_vec()
    }
}

/// Verifies a device attestation served by the server.
///
/// **Always re-check this on the client.** The server already verifies on write, but the
/// server is precisely who we suspect: its check is an early filter, never a guarantee. See
/// the test `a_ghost_device_injected_in_sql_does_not_pass_client_verification`.
#[wasm_bindgen(js_name = verifyAttestation)]
pub fn verify_attestation(
    identity_key: &[u8],
    account: &str,
    device_id: &str,
    auth_key: &[u8],
    mls_key: &[u8],
    attestation: &[u8],
) -> bool {
    let claim = attest::DeviceClaim { account, device_id, auth_key, mls_key };
    attest::verify(identity_key, &claim, attestation).is_ok()
}

/// Verifies a revocation certificate served by the server.
///
/// **Always call this.** A client that took the server's word for it would hand the server the
/// power to evict any device it chose — targeted censorship, durable, and indistinguishable
/// from a legitimate revocation.
#[wasm_bindgen(js_name = verifyRevocation)]
pub fn verify_revocation(
    identity_key: &[u8],
    account: &str,
    device_id: &str,
    revoked_at: u64,
    revocation: &[u8],
) -> bool {
    let claim = attest::RevocationClaim { account, device_id, revoked_at };
    attest::verify_revocation(identity_key, &claim, revocation).is_ok()
}

/// Verifies one link of an account's rotation chain.
///
/// # Why this crosses the wasm boundary rather than being written in TypeScript
///
/// The same reason `postMac` gives: the signed message has a canonical format — a domain label
/// and length-prefixed fields — and rewriting it on the client would duplicate the definition
/// that the `attest` crate exists to hold exactly once. One byte of divergence and every chain
/// looks broken, which reads as "the server is lying" rather than "we disagree about a length
/// prefix".
///
/// `previous_identity_key` and not the new one: the signature attests that the holder of the
/// outgoing key designates the incoming one. Verifying against the incoming key would only prove
/// possession of it, which proves nothing about continuity.
#[wasm_bindgen(js_name = verifyRotation)]
pub fn verify_rotation(
    previous_identity_key: &[u8],
    account: &str,
    new_identity_key: &[u8],
    rotated_at: u64,
    rotation: &[u8],
) -> bool {
    let claim = attest::RotationClaim { account, new_identity_key, rotated_at };
    attest::verify_rotation(previous_identity_key, &claim, rotation).is_ok()
}

/// The account id an identity key would produce.
///
/// Exposed so the client can check the **anchor** of a chain — that its first key really does
/// fingerprint to the id the account is being served under — without reimplementing the
/// derivation. It is a truncated SHA-256 and would be four lines of TypeScript; the point is not
/// difficulty, it is that a second definition of an identifier is a second thing that can drift.
#[wasm_bindgen(js_name = accountId)]
pub fn account_id(identity_key: &[u8]) -> String {
    attest::account_id(identity_key)
}

// ---------------------------------------------------------------- anonymous post

/// Authenticates an envelope post without revealing who posts.
///
/// # What this MAC tells the server
///
/// That the poster holds the group key, hence that they are a member. Nothing more. The server
/// never needed to know **who** posts — only that the poster is allowed to, so it does not act
/// as an open mailbox. Those are two distinct things, and the second one is enough.
///
/// The real sender stays authenticated **by MLS**, inside the ciphertext: the recipients read
/// it, the server does not.
///
/// # Why the computation happens here and not in JavaScript
///
/// The authenticated message has a canonical format, shared with the verifier. Rewriting it on
/// the client would duplicate the definition — exactly what the `attest` crate exists to
/// remove. One byte of divergence and every post is refused.
#[wasm_bindgen(js_name = postMac)]
pub fn post_mac(
    posting_key: &[u8],
    group_id: &[u8],
    nonce: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, JsError> {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    let message = attest::post_message(group_id, nonce, &Sha256::digest(body))
        .map_err(|_| JsError::new("malformed post"))?;

    let mut mac = <Hmac<Sha256>>::new_from_slice(posting_key)
        .map_err(|_| JsError::new("invalid posting key"))?;
    mac.update(&message);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// MAC accompanying the post of an **ephemeral signal**.
///
/// Twin of [`post_mac`], up to the domain — see `attest::signal_message` for the reason behind
/// that separation. It proves the same thing: group membership, not identity.
#[wasm_bindgen(js_name = signalMac)]
pub fn signal_mac(
    posting_key: &[u8],
    group_id: &[u8],
    nonce: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, JsError> {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    let message = attest::signal_message(group_id, nonce, &Sha256::digest(body))
        .map_err(|_| JsError::new("malformed signal"))?;

    let mut mac = <Hmac<Sha256>>::new_from_slice(posting_key)
        .map_err(|_| JsError::new("invalid posting key"))?;
    mac.update(&message);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Message to sign in order to open a gateway session.
///
/// Returns the bytes to sign, **not the signature**: the device's authentication key is a
/// non-extractable WebCrypto key that never leaves the browser and therefore never enters this
/// module. The split is deliberate — it is what stops a bug here from leaking the key.
///
/// Same argument as [`post_mac`] about where the computation lives: the canonical format is in
/// the `attest` crate, and rewriting it in JavaScript would duplicate it. One byte of
/// divergence and no session opens.
#[wasm_bindgen(js_name = gatewayChallenge)]
pub fn gateway_challenge(device_id: &str, nonce: &[u8]) -> Result<Vec<u8>, JsError> {
    attest::gateway_message(device_id, nonce).map_err(|_| JsError::new("malformed challenge"))
}

// ---------------------------------------------------------------- transparency log

/// Leaf hash of a log entry, as the server must have computed it.
///
/// The client recomputes it from the handle and the key it is served: accepting the hash the
/// server provides would amount to asking it to prove what it claims with what it claims.
#[wasm_bindgen(js_name = logLeaf)]
pub fn log_leaf(handle: &str, identity_key: &[u8]) -> Vec<u8> {
    transparency::leaf_hash(&transparency::entry(handle, identity_key)).to_vec()
}

/// Checks that a key really is in the log, at the announced index.
///
/// **This is what closes the first-contact hole.** Attestations stop the server from adding a
/// device; they do not stop it from serving its own account key to someone with nothing to
/// compare against. An inclusion proof, by contrast, cannot be forged.
#[wasm_bindgen(js_name = verifyInclusion)]
pub fn verify_inclusion(
    leaf: &[u8],
    index: usize,
    size: usize,
    proof: Vec<js_sys::Uint8Array>,
    root: &[u8],
) -> bool {
    let (Ok(leaf), Ok(root)) = (to_hash(leaf), to_hash(root)) else { return false };
    let Some(proof) = to_hashes(&proof) else { return false };

    transparency::verify_inclusion(&leaf, index, size, &proof, &root).is_ok()
}

/// Checks that the current log **extends** the one already seen, with no rewriting.
///
/// Without this check, the server could replace an already published key and serve a log just
/// as coherent: the log would no longer prove anything about the past.
#[wasm_bindgen(js_name = verifyConsistency)]
pub fn verify_consistency(
    from: usize,
    old_root: &[u8],
    to: usize,
    new_root: &[u8],
    proof: Vec<js_sys::Uint8Array>,
) -> bool {
    let (Ok(old_root), Ok(new_root)) = (to_hash(old_root), to_hash(new_root)) else {
        return false;
    };
    let Some(proof) = to_hashes(&proof) else { return false };

    transparency::verify_consistency(from, &old_root, to, &new_root, &proof).is_ok()
}

/// Checks that a tree head really was signed by the log.
///
/// **What this proves is narrow**: that the head comes from the log. Not that it is the only
/// head the log ever emitted. A server running two logs signs two equally valid heads; only
/// comparison between clients catches it.
#[wasm_bindgen(js_name = verifyTreeHead)]
pub fn verify_tree_head(
    log_key: &[u8],
    size: u64,
    root: &[u8],
    timestamp: u64,
    signature: &[u8],
) -> bool {
    let Ok(root) = to_hash(root) else { return false };
    transparency::TreeHead { size, root, timestamp }.verify(log_key, signature).is_ok()
}

fn to_hash(bytes: &[u8]) -> Result<transparency::Hash, ()> {
    bytes.try_into().map_err(|_| ())
}

fn to_hashes(values: &[js_sys::Uint8Array]) -> Option<Vec<transparency::Hash>> {
    values.iter().map(|v| to_hash(&v.to_vec()).ok()).collect()
}

/// Fingerprint of an account we only hold the public key of.
#[wasm_bindgen(js_name = accountFingerprint)]
pub fn account_fingerprint(identity_key: &[u8]) -> String {
    attest::fingerprint(identity_key)
}


/// Pairing offer held by the **new** device.
///
/// The new device shows the QR, the old one scans it. That direction is mandatory: a QR can be
/// photographed, so it must contain no secret. Here it carries only an ephemeral public key
/// and a drop address.
#[wasm_bindgen]
pub struct Pairing {
    offer: Option<PairingOffer>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedJs {
    #[serde(with = "serde_bytes")]
    plaintext: Vec<u8>,
    /// Short code to compare by eye on both screens.
    confirmation: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedJs {
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    confirmation: String,
}

#[wasm_bindgen]
impl Pairing {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Pairing {
        Self { offer: Some(PairingOffer::generate()) }
    }

    /// Pairing id: the drop address on the server. Public, worthless on its own.
    pub fn id(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.expect()?.id().to_vec())
    }

    /// Ephemeral public key to publish in the QR.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.expect()?.public_key().to_vec())
    }

    /// Opens the packet dropped by the original device.
    ///
    /// Consumes the offer: the ephemeral secret is single-use, which forbids replaying an old
    /// packet against the same key. A second call fails, deliberately.
    pub fn open(&mut self, sealed: &[u8]) -> Result<JsValue, JsError> {
        let offer = self
            .offer
            .take()
            .ok_or_else(|| JsError::new("pairing offer already consumed"))?;

        let opened = offer.open(sealed).map_err(to_js)?;
        to_value(&OpenedJs { plaintext: opened.plaintext, confirmation: opened.confirmation })
    }

    fn expect(&self) -> Result<&PairingOffer, JsError> {
        self.offer.as_ref().ok_or_else(|| JsError::new("pairing offer already consumed"))
    }
}

impl Default for Pairing {
    fn default() -> Self {
        Self::new()
    }
}

/// Seals a packet for the new device, from the values read in the QR.
///
/// Returns `{payload, confirmation}`. The confirmation code must be **displayed on both sides
/// and compared by the user**: that is what attests that the two devices are talking about the
/// same exchange.
#[wasm_bindgen(js_name = sealPairing)]
pub fn seal_pairing(
    offer_public: &[u8],
    offer_id: &[u8],
    plaintext: &[u8],
) -> Result<JsValue, JsError> {
    let (payload, confirmation) = seal(offer_public, offer_id, plaintext).map_err(to_js)?;
    to_value(&SealedJs { payload, confirmation })
}


/// Derives the local unlock key from a password.
///
/// Argon2id, 64 MiB, 3 passes. **About one second**: that is the price paid once per unlock,
/// and on every attempt by an attacker who got hold of the database.
///
/// This function does not exist in WebCrypto. PBKDF2 does — but it only costs computation,
/// which a GPU does by the billion. Argon2id's memory cost is what brings a parallel attack
/// back down to the level of an ordinary processor.
///
/// Calling this function freezes the thread of execution for its duration. Run it from a
/// Worker if the interface must stay responsive.
#[wasm_bindgen(js_name = deriveUnlockKey)]
pub fn derive_unlock_key_js(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(derive_unlock_key(password, salt).map_err(to_js)?.to_vec())
}
