//! Assembly: X3DH to establish the session, Double Ratchet to keep it alive.

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::error::RatchetError;
use crate::keys::{IdentityKeyPair, IdentityPublic, PreKeyBundle, PreKeyStore};
use crate::ratchet::{DoubleRatchet, Message};
use crate::x3dh::{self, InitialMessage};

pub struct Session {
    ratchet: DoubleRatchet,
    peer: IdentityPublic,
}

impl Session {
    /// Alice opens a session from Bob's bundle alone. Bob may be offline.
    pub fn initiate<R: RngCore + CryptoRng>(
        rng: &mut R,
        identity: &IdentityKeyPair,
        bundle: &PreKeyBundle,
    ) -> Result<(Self, InitialMessage), RatchetError> {
        let (outcome, initial) = x3dh::initiate(rng, identity, bundle)?;

        // Bob's signed prekey serves as the first ratchet key: it is the only public key of
        // Bob's that Alice already holds, which is what lets her write first.
        let ratchet = DoubleRatchet::init_initiator(
            rng,
            outcome.shared_secret,
            outcome.associated_data,
            bundle.signed_prekey,
        );

        Ok((
            Self { ratchet, peer: bundle.identity },
            initial,
        ))
    }

    /// Bob accepts the session by replaying X3DH from his own material.
    ///
    /// In production, the consumed one-time prekey must be deleted from the store right here:
    /// reusing it would cancel the forward secrecy it provides.
    pub fn accept(store: &PreKeyStore, initial: &InitialMessage) -> Result<Self, RatchetError> {
        let outcome = x3dh::respond(store, initial)?;
        let ratchet = DoubleRatchet::init_responder(
            outcome.shared_secret,
            outcome.associated_data,
            store.signed_prekey.clone(),
        );

        Ok(Self { ratchet, peer: initial.identity })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Message, RatchetError> {
        self.ratchet.encrypt(plaintext)
    }

    pub fn decrypt<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<u8>, RatchetError> {
        self.ratchet.decrypt(rng, message)
    }

    pub fn peer_identity(&self) -> &IdentityPublic {
        &self.peer
    }

    pub fn skipped_count(&self) -> usize {
        self.ratchet.skipped_count()
    }
}

/// Number of hash iterations in the fingerprint computation. Signal does 5200: the cost is
/// negligible for the user but makes the search for a partial collision — a key whose
/// fingerprint *looks like* the real one — markedly more expensive for an attacker.
const FINGERPRINT_ITERATIONS: u32 = 5_200;

/// Displayable fingerprint of a pair of identities, "safety number" style.
///
/// The two participants compare this string out of band (by eye, or by QR code). Without that
/// comparison, nothing stops the server from serving each of them an identity it controls and
/// relaying in the clear: the encryption works perfectly, but with the attacker in the middle.
/// This is the real weak link of most deployments, because almost nobody performs the
/// comparison.
///
/// Sorting makes the result independent of who is looking: both screens show the same thing.
pub fn safety_number(a: &IdentityPublic, b: &IdentityPublic) -> String {
    let (first, second) = if a.encode() <= b.encode() { (a, b) } else { (b, a) };

    let digits = |identity: &IdentityPublic| -> String {
        let encoded = identity.encode();
        let mut hash = Sha256::digest(encoded).to_vec();
        for _ in 1..FINGERPRINT_ITERATIONS {
            let mut hasher = Sha256::new();
            hasher.update(&hash);
            hasher.update(encoded);
            hash = hasher.finalize().to_vec();
        }

        // 6 groups of 5 digits per identity, i.e. 60 digits in total for the pair.
        hash[..30]
            .chunks(5)
            .map(|chunk| {
                let n = chunk.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
                format!("{:05}", n % 100_000)
            })
            .collect::<Vec<_>>()
            .join(" ")
    };

    format!("{} {}", digits(first), digits(second))
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("peer", &self.peer)
            .field("ratchet", &self.ratchet)
            .finish()
    }
}
