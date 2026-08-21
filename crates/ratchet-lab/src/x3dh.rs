//! X3DH — asynchronous session establishment.
//!
//! The key point: Alice derives a shared secret with Bob **without Bob being online**, using
//! only the bundle he left on the server. That is what makes asynchronous messaging
//! possible; the rest of the protocol follows from it.
//!
//! Each of the four DHs plays a distinct role:
//!   DH1 = IK_A · SPK_B  authenticates Alice to Bob
//!   DH2 = EK_A · IK_B   authenticates Bob to Alice
//!   DH3 = EK_A · SPK_B  provides forward secrecy
//!   DH4 = EK_A · OPK_B  strengthens the FS of the very first message (if an OPK is available)
//!
//! No DH is signed: the secret is provable by nobody except the two participants. That is
//! deniability, and it is deliberate.

use rand_core::{CryptoRng, RngCore};
use x25519_dalek::PublicKey;

use crate::error::RatchetError;
use crate::kdf::{RootKey, kdf_x3dh};
use crate::keys::{EphemeralKeyPair, IdentityKeyPair, IdentityPublic, PreKeyBundle, PreKeyStore};

/// What Alice attaches to her first message so Bob can replay the same computation.
#[derive(Clone)]
#[derive(Debug)]
pub struct InitialMessage {
    pub identity: IdentityPublic,
    pub ephemeral: PublicKey,
    /// Tells Bob whether he must include his one-time prekey in the computation.
    pub used_one_time_prekey: bool,
}

pub struct X3dhOutcome {
    pub shared_secret: RootKey,
    /// Bound to every message through the AEAD: an attacker cannot replay a ciphertext into
    /// a conversation between other identities.
    pub associated_data: Vec<u8>,
}

fn associated_data(initiator: &IdentityPublic, responder: &IdentityPublic) -> Vec<u8> {
    let mut ad = Vec::with_capacity(128);
    ad.extend_from_slice(&initiator.encode());
    ad.extend_from_slice(&responder.encode());
    ad
}

/// Alice's side.
pub fn initiate<R: RngCore + CryptoRng>(
    rng: &mut R,
    identity: &IdentityKeyPair,
    bundle: &PreKeyBundle,
) -> Result<(X3dhOutcome, InitialMessage), RatchetError> {
    // Without this check, a malicious server substitutes its own signed prekey and reads the
    // whole conversation.
    bundle.verify()?;

    let ephemeral = EphemeralKeyPair::generate(rng);

    let mut dhs = vec![
        identity.dh.diffie_hellman(&bundle.signed_prekey).to_bytes(),
        ephemeral.secret.diffie_hellman(&bundle.identity.dh).to_bytes(),
        ephemeral.secret.diffie_hellman(&bundle.signed_prekey).to_bytes(),
    ];
    if let Some(opk) = &bundle.one_time_prekey {
        dhs.push(ephemeral.secret.diffie_hellman(opk).to_bytes());
    }

    let shared_secret = kdf_x3dh(&dhs);
    let outcome = X3dhOutcome {
        shared_secret,
        associated_data: associated_data(&identity.public(), &bundle.identity),
    };
    let initial = InitialMessage {
        identity: identity.public(),
        ephemeral: ephemeral.public(),
        used_one_time_prekey: bundle.one_time_prekey.is_some(),
    };

    Ok((outcome, initial))
}

/// Bob's side. Replays the same DHs in the same order, each pair taken the other way round.
pub fn respond(store: &PreKeyStore, initial: &InitialMessage) -> Result<X3dhOutcome, RatchetError> {
    let mut dhs = vec![
        store.signed_prekey.secret.diffie_hellman(&initial.identity.dh).to_bytes(),
        store.identity.dh.diffie_hellman(&initial.ephemeral).to_bytes(),
        store.signed_prekey.secret.diffie_hellman(&initial.ephemeral).to_bytes(),
    ];
    if initial.used_one_time_prekey {
        let opk = store
            .one_time_prekey
            .as_ref()
            .ok_or(RatchetError::Malformed("one-time prekey claimed but missing"))?;
        dhs.push(opk.secret.diffie_hellman(&initial.ephemeral).to_bytes());
    }

    Ok(X3dhOutcome {
        shared_secret: kdf_x3dh(&dhs),
        associated_data: associated_data(&initial.identity, &store.identity.public()),
    })
}
