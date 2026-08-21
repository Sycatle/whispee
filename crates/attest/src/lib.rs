//! Attestation that a device belongs to an account.
//!
//! # The problem this crate solves
//!
//! In MLS the unit of group membership is the device. A multi-device account is therefore, as
//! far as the protocol is concerned, a set of unrelated devices. Someone has to declare that
//! those devices form an account — and that "someone" is, in practice, who decides who can read
//! the conversations.
//!
//! If it is the server, it only has to add a device it controls to Bob's list to be invited into
//! every conversation he has. No cryptography is broken: the message is still end-to-end
//! encrypted, one of the ends simply happens to be the server. That is the attack WhatsApp was
//! accused of in 2019, and it is undetectable without this crate.
//!
//! Here the **account** signs its own devices, with a key the server does not hold. The server
//! can then only **omit** a device from the list — censorship, visible and useless to an
//! eavesdropper — never **add** one.
//!
//! # Why a separate crate
//!
//! The signer is `crypto-core`, the verifier is `server`. Two implementations of the canonical
//! format would diverge sooner or later, and the benign divergence (rejected signatures) is not
//! the only possible one: that is also how field confusion gets introduced. One definition,
//! here, tested here.
//!
//! `server` does not speak MLS and must not start: this crate therefore does not depend on
//! OpenMLS.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Domain separation label.
///
/// It guarantees a signature produced here cannot be replayed as a valid signature in another
/// context of the project, and vice versa. The version in the label is what will allow the
/// format to evolve without an old signature staying acceptable under the new rules.
///
/// **v2 is that mechanism being used.** The first field of every claim used to be a handle and is
/// now an account id, and the two are not distinguishable by shape: `abcdef0123456789abcdef0123456789`
/// satisfies the handle rule in `server::handle` and looks exactly like an id. Without the bump,
/// an attestation signed over the handle `bob` would verify as an attestation over the account
/// whose id happens to be `bob` — a field confusion between two versions of the same protocol,
/// which is the failure this label exists to make impossible.
const DOMAIN: &[u8] = b"wac-attest-v2";

/// Revocation domain, distinct from the attestation one.
///
/// This distinction is what stops a legitimately obtained attestation from being presented as a
/// revocation certificate for the same device — which would let anyone get any already attested
/// device evicted.
const DOMAIN_REVOKE: &[u8] = b"wac-revoke-v2";

/// Account rotation domain.
///
/// Another distinct domain, for the same reason as the previous two: a signature produced to
/// revoke a device must not be usable to change the account key, which would amount to taking
/// the account over.
const DOMAIN_ROTATE: &[u8] = b"wac-rotate-v2";

/// Domain of the anonymous envelope post.
///
/// Distinct from the other three, and for a reason that is not theoretical: this message is
/// authenticated by a **symmetric MAC** whose key is shared with the server, where the others
/// carry signatures the server cannot produce. Conflating the domains would let whoever holds
/// the post key forge whatever it wants elsewhere.
const DOMAIN_POST: &[u8] = b"wac-post-v1";

/// Domain of the MAC accompanying an **ephemeral signal** (typing indicator).
///
/// Distinct from [`DOMAIN_POST`] even though the key is the same: without this separation a MAC
/// captured on a signal — which has no replay protection, because a stale signal has no effect —
/// could be presented as the MAC of an envelope post. The body formats differ enough for the
/// attack to fail in practice, which is exactly the kind of reasoning that stops being true at
/// the first change to the format.
const DOMAIN_SIGNAL: &[u8] = b"wac-signal-mac-v1";

/// Domain for opening a gateway session.
///
/// Distinct from all the previous ones, and above all from what [`crate::message`] signs: the
/// opening signature proves possession of a device's authentication key, the same one that signs
/// HTTP requests. Without domain separation a signature captured on an HTTP request would open a
/// session, and vice versa — making the nonce, whose whole purpose is precisely that, useless.
const DOMAIN_GATEWAY: &[u8] = b"wac-gateway-v1";

/// Maximum accepted length for a variable-length field.
///
/// The length prefix is a `u16`: beyond that, serialisation would silently truncate, making two
/// distinct entries indistinguishable.
pub const MAX_FIELD_LEN: usize = u16::MAX as usize;

#[derive(Debug, PartialEq, Eq)]
pub enum AttestError {
    /// A field exceeds what a `u16` prefix can describe.
    FieldTooLong,
    /// The account public key is not a valid Ed25519 key.
    BadIdentityKey,
    /// The signature has the wrong size, or does not verify.
    BadSignature,
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldTooLong => write!(f, "field too long to be attested"),
            Self::BadIdentityKey => write!(f, "invalid account identity key"),
            Self::BadSignature => write!(f, "invalid attestation"),
        }
    }
}

impl std::error::Error for AttestError {}

/// What a device claims: belonging to `account`, with these two public keys.
///
/// Both keys are attested together, not separately. Separating them would allow recombining the
/// attestation of one authentication key with the MLS key of another device.
#[derive(Debug, Clone, Copy)]
pub struct DeviceClaim<'a> {
    /// The account id — see [`account_id`]. Carried in the clear, as the credential already is.
    ///
    /// It used to be the handle, and the change is the point of the whole batch: a handle is a
    /// name and a name has to be able to move. Binding an attestation to one meant every
    /// attestation an account ever made was tied to whatever it was called at the time.
    pub account: &'a str,
    pub device_id: &'a str,
    /// Ed25519 HTTP authentication key (32 bytes).
    pub auth_key: &'a [u8],
    /// This device's MLS signature public key.
    pub mls_key: &'a [u8],
}

/// Serialises the claim into the exact form that is signed.
///
/// Every variable-length field is preceded by its length. Without those prefixes,
/// `account="ab", device_id="c"` and `account="a", device_id="bc"` would produce identical bytes:
/// an attestation obtained for one would hold for the other. That is exactly the kind of flaw
/// that review does not catch, and that the `two_different_splits_do_not_collide` test pins down.
pub fn message(claim: &DeviceClaim<'_>) -> Result<Vec<u8>, AttestError> {
    encode(
        DOMAIN,
        &[claim.account.as_bytes(), claim.device_id.as_bytes(), claim.auth_key, claim.mls_key],
    )
}

/// Canonical serialisation shared by every signed message of this crate.
///
/// One implementation of the prefixing, shared by attestation and revocation. Two copies would
/// diverge: that is the whole point of this crate, reproducing the problem inside it would be
/// absurd.
///
/// The domain label opens the message, so no message of one kind can be read as a message of
/// another kind — that is what forbids replaying an attestation as a revocation.
fn encode(domain: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>, AttestError> {
    if parts.iter().any(|part| part.len() > MAX_FIELD_LEN) {
        return Err(AttestError::FieldTooLong);
    }

    let mut out = Vec::with_capacity(domain.len() + parts.iter().map(|p| p.len() + 2).sum::<usize>());
    out.extend_from_slice(domain);
    for part in parts {
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// Shared Ed25519 verification. See the note on [`verify`] about how much to trust the result
/// produced by the server.
fn verify_signature(identity_key: &[u8], message: &[u8], sig: &[u8]) -> Result<(), AttestError> {
    let identity_key: [u8; 32] = identity_key.try_into().map_err(|_| AttestError::BadIdentityKey)?;
    let verifying =
        VerifyingKey::from_bytes(&identity_key).map_err(|_| AttestError::BadIdentityKey)?;

    let sig: [u8; 64] = sig.try_into().map_err(|_| AttestError::BadSignature)?;

    verifying
        .verify(message, &Signature::from_bytes(&sig))
        .map_err(|_| AttestError::BadSignature)
}

/// Checks that an attestation was indeed produced by the account.
///
/// Free and stateless: it needs no secret, which lets the server call it as an access control
/// and the client redo it for itself.
///
/// **The client must never rely on the verification done by the server.** A server that lies
/// about the result is precisely the scenario all of this exists against: server-side
/// verification only rejects early what is unusable anyway, it is not a guarantee.
pub fn verify(
    identity_key: &[u8],
    claim: &DeviceClaim<'_>,
    attestation: &[u8],
) -> Result<(), AttestError> {
    verify_signature(identity_key, &message(claim)?, attestation)
}

/// What an account declares when revoking one of its devices.
///
/// # Why a certificate, and not just a row in the database
///
/// Removing a device from an MLS group is an act **other accounts** have to perform: if Alice
/// loses her phone, it is Bob, present in the group, who commits the removal. Without a
/// certificate Bob's only source is the server — which then regains exactly the power [`verify`]
/// denies it, deciding who belongs to an account, except that it works the other way round:
/// getting someone evicted rather than let in.
///
/// The certificate makes revocation verifiable by anyone holding the account key. The server can
/// still *withhold* a revocation; it can no longer *invent* one.
#[derive(Debug, Clone, Copy)]
pub struct RevocationClaim<'a> {
    pub account: &'a str,
    pub device_id: &'a str,
    /// Revocation instant, in Unix seconds.
    ///
    /// It is **inside the signed message**, so the server cannot backdate a genuine revocation to
    /// pretend a device was already excluded at the time of a message.
    pub revoked_at: u64,
}

/// Serialises the revocation into the exact form that is signed.
///
/// The timestamp goes through the same prefixing as the rest even though its length is fixed:
/// an exception to the format would be an opportunity to diverge for nothing.
pub fn revocation_message(claim: &RevocationClaim<'_>) -> Result<Vec<u8>, AttestError> {
    encode(
        DOMAIN_REVOKE,
        &[claim.account.as_bytes(), claim.device_id.as_bytes(), &claim.revoked_at.to_be_bytes()],
    )
}

/// Checks that a revocation certificate really comes from the account owning the device.
///
/// Like [`verify`], it needs no secret: that is what lets a third party — another group member —
/// observe the revocation without trusting the server relaying it.
pub fn verify_revocation(
    identity_key: &[u8],
    claim: &RevocationClaim<'_>,
    revocation: &[u8],
) -> Result<(), AttestError> {
    verify_signature(identity_key, &revocation_message(claim)?, revocation)
}

/// What an account declares when changing its identity key.
///
/// # Why rotation exists
///
/// Every device of an account holds the seed — that is the condition for **parity**: each device
/// can attest, revoke and read like the others, with no hierarchy. The counterpart is that a
/// stolen device holds the whole account. Revoking it is then pointless: whoever carries it
/// attests a new one right away.
///
/// The only answer is to change the account key. It has a mechanical effect that makes any other
/// measure unnecessary: **all existing attestations become unverifiable**, since clients check
/// them against the current key. Total revocation is not a separate mechanism, it is a
/// consequence.
///
/// # What signing with the old key proves, and what it does not
///
/// It proves continuity: without it, anyone could take over someone else's handle. It does
/// **not** prove the rotation is legitimate — the thief holds the same key and can rotate first.
/// It is a race, and an inherent one: nothing in the protocol distinguishes the owner from the
/// bearer. Hence the importance of the fingerprint-change alert on the other side, which is the
/// only recourse here.
#[derive(Debug, Clone, Copy)]
pub struct RotationClaim<'a> {
    pub account: &'a str,
    /// New account public key (32 bytes).
    pub new_identity_key: &'a [u8],
    /// Rotation instant, in Unix seconds.
    pub rotated_at: u64,
}

pub fn rotation_message(claim: &RotationClaim<'_>) -> Result<Vec<u8>, AttestError> {
    encode(
        DOMAIN_ROTATE,
        &[claim.account.as_bytes(), claim.new_identity_key, &claim.rotated_at.to_be_bytes()],
    )
}

/// Verifies a rotation against the **old** account key.
///
/// The old one indeed: the signature attests that the holder of the outgoing key designates the
/// incoming one. Verifying against the new key would only prove possession of it, that is,
/// nothing.
pub fn verify_rotation(
    previous_identity_key: &[u8],
    claim: &RotationClaim<'_>,
    rotation: &[u8],
) -> Result<(), AttestError> {
    verify_signature(previous_identity_key, &rotation_message(claim)?, rotation)
}

/// Message authenticated when anonymously posting an envelope.
///
/// # What this MAC proves, and what it does not
///
/// It proves the poster **holds the group key**, hence is a member. It says nothing about who
/// they are, and that is exactly the point: the server does not need to know who posts, only
/// that they are allowed to.
///
/// The nonce makes each post unique and lets the server reject replays. Without it, an
/// intercepted MAC would stay valid forever.
///
/// The body digest is included rather than the body: an attacker able to modify the envelope
/// afterwards would post whatever it wanted under a legitimate MAC.
pub fn post_message(group_id: &[u8], nonce: &[u8], body_digest: &[u8]) -> Result<Vec<u8>, AttestError> {
    encode(DOMAIN_POST, &[group_id, nonce, body_digest])
}

/// Message authenticated when posting an ephemeral signal.
///
/// Twin of [`post_message`], up to the domain. It proves the same thing — group membership, not
/// identity — for content that will never be written to disk.
pub fn signal_message(
    group_id: &[u8],
    nonce: &[u8],
    body_digest: &[u8],
) -> Result<Vec<u8>, AttestError> {
    encode(DOMAIN_SIGNAL, &[group_id, nonce, body_digest])
}

/// Message signed to open a gateway session.
///
/// # Why a challenge, where HTTP settles for a timestamp
///
/// This project's HTTP authentication accepts any signature whose timestamp falls within a
/// sixty-second window, for lack of remembering the nonces already seen — the limit documented in
/// `server::auth`. A captured signature therefore stays replayable there for a minute.
///
/// Here the nonce is **issued by the server** and consumed on first use: there is no window. This
/// is not gratuitous refinement, it is the counterpart of a change of model — a gateway session
/// authenticates once then lives long, where an HTTP request authenticates on every call. A
/// replay would cost far more.
///
/// The device identifier is in the signed message: without it, a nonce served to Alice could be
/// returned along with Bob's signature captured elsewhere.
pub fn gateway_message(device_id: &str, nonce: &[u8]) -> Result<Vec<u8>, AttestError> {
    encode(DOMAIN_GATEWAY, &[device_id.as_bytes(), nonce])
}

/// Length of an account id, in hexadecimal characters. 128 bits.
pub const ID_HEX_LEN: usize = 32;

/// How much of an id is shown inline, in hexadecimal characters. 64 bits.
///
/// # This number is the only real trade-off in the identity design
///
/// A truncated fingerprint is **grindable**: an attacker generates account keys until the first
/// *n* characters of theirs match their target's, then presents an account that reads as the
/// right one anywhere the short form is shown alone. The work is `2^(4n/2)` by the birthday
/// bound for a collision and `2^(4n)` to hit a chosen target, and it is the second one that
/// matters here — the attacker has somebody specific in mind.
///
/// At 32 bits that is minutes on a laptop. At 64 bits it is roughly `2^64` key generations,
/// which is out of reach of anyone who would be attacking a chat handle. At 128 there is nothing
/// to grind and also nothing that fits beside a name.
///
/// So: 64 inline, 128 in the verification panel, and the panel is the proof. The inline form is a
/// convenience and `docs/THREAT-MODEL.md` says so.
pub const ID_SHORT_HEX_LEN: usize = 16;

/// The canonical account id: the fingerprint of the account's **genesis** identity key.
///
/// # Why derived and not assigned
///
/// A server that mints ids can forge one, reassign one, or serve two people two different
/// answers about the same name. A server that merely lists them can do none of those, because
/// the id is checkable against key material the verifier already holds — it is `sha256` of a key
/// that is in the credential being verified. That single property is what makes a renameable
/// handle safe: the directory may lie, and lying gains it nothing that an out-of-band
/// fingerprint comparison does not already catch.
///
/// # Genesis, not current
///
/// [`RotationClaim`] exists, so the identity key moves. An id derived from the *current* key
/// would move with it, which is the problem this design removes, reappearing in a rarer and more
/// confusing form. The anchor is the first key the account ever had; the rotation chain is the
/// evidence tying it to whatever key is current, and each of its links is already checkable with
/// [`verify_rotation`].
///
/// # Why lowercase hex and not the spaced form
///
/// [`fingerprint`] groups in blocks of four because a human is going to compare it by eye. An id
/// is compared by machine, travels in a credential and keys a database row: it gets one
/// representation with no whitespace to normalise away. The two are the same 128 bits.
pub fn account_id(genesis_identity_key: &[u8]) -> String {
    let digest = Sha256::digest(genesis_identity_key);
    digest[..ID_HEX_LEN / 2].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether a string is shaped like an account id.
///
/// Shape only — it says nothing about whether such an account exists, and nothing about whether
/// the id matches the key it is presented with. Both of those are the caller's job. This exists
/// so that a malformed id is refused at a boundary rather than becoming a row nobody can ever
/// match.
pub fn is_account_id(value: &str) -> bool {
    value.len() == ID_HEX_LEN && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The inline form: the first [`ID_SHORT_HEX_LEN`] characters, grouped in fours.
///
/// Grouped for the same reason [`fingerprint`] is — comparing two continuous hex strings by eye
/// is unreliable, and the attack consists precisely of producing something that *looks like* the
/// right value. Returns the input untouched if it is not an id, so a caller cannot silently turn
/// a malformed value into a plausible-looking one.
pub fn short_id(id: &str) -> String {
    if !is_account_id(id) {
        return id.to_owned();
    }
    id.as_bytes()[..ID_SHORT_HEX_LEN]
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Account fingerprint, to be compared out of band with the other party.
///
/// Computed on the identity key alone, hence **stable when the account gains or loses a
/// device**. That is deliberate: a fingerprint changing on every added device would force a
/// re-check after every legitimate event, and would be ignored within weeks. Detecting a hostile
/// device goes through the add notification, not the fingerprint.
pub fn fingerprint(identity_key: &[u8]) -> String {
    let digest = Sha256::digest(identity_key);
    digest[..16]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}
