//! Key types and the material published on the server.
//!
//! Signal derives the signing key from the DH key through XEdDSA. Here we keep two distinct
//! pairs (X25519 for key agreement, Ed25519 for signing): more verbose, but the intent of
//! each key stays readable, which is the point of this crate.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::RatchetError;

/// A user's long-term identity. It never changes: it is what the fingerprints displayed on
/// screen authenticate.
pub struct IdentityKeyPair {
    pub(crate) dh: StaticSecret,
    pub(crate) sign: SigningKey,
}

/// The public half of an identity, as served by the server.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IdentityPublic {
    pub dh: PublicKey,
    pub sign: VerifyingKey,
}

impl IdentityKeyPair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            dh: StaticSecret::random_from_rng(&mut *rng),
            sign: SigningKey::generate(rng),
        }
    }

    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            dh: PublicKey::from(&self.dh),
            sign: self.sign.verifying_key(),
        }
    }
}

impl IdentityPublic {
    /// Stable encoding used in the AEAD associated data and in the fingerprint computation.
    /// It must stay identical on both sides, otherwise every decryption fails.
    pub fn encode(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.dh.as_bytes());
        out[32..].copy_from_slice(self.sign.as_bytes());
        out
    }
}

/// Ephemeral or semi-static pair (signed prekey, one-time prekey, ratchet key).
#[derive(Clone)]
pub struct EphemeralKeyPair {
    pub(crate) secret: StaticSecret,
    pub(crate) public: PublicKey,
}

impl EphemeralKeyPair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }
}

/// What Bob leaves on the server so that Alice can write to him while he is offline.
///
/// The `signed_prekey` is signed by Bob's Ed25519 identity: that is what stops the server
/// from substituting its own key. That signature says nothing, however, about the
/// authenticity of `identity` itself — that is the job of fingerprint verification.
pub struct PreKeyBundle {
    pub identity: IdentityPublic,
    pub signed_prekey: PublicKey,
    pub signed_prekey_sig: Signature,
    /// Consumed on use. Its absence degrades the forward secrecy of the very first message.
    pub one_time_prekey: Option<PublicKey>,
}

impl PreKeyBundle {
    pub fn verify(&self) -> Result<(), RatchetError> {
        self.identity
            .sign
            .verify(self.signed_prekey.as_bytes(), &self.signed_prekey_sig)
            .map_err(|_| RatchetError::BadPreKeySignature)
    }
}

/// The full state Bob keeps locally, matching the bundle he published.
pub struct PreKeyStore {
    pub identity: IdentityKeyPair,
    pub signed_prekey: EphemeralKeyPair,
    pub one_time_prekey: Option<EphemeralKeyPair>,
}

impl PreKeyStore {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R, with_one_time: bool) -> Self {
        Self {
            identity: IdentityKeyPair::generate(rng),
            signed_prekey: EphemeralKeyPair::generate(rng),
            one_time_prekey: with_one_time.then(|| EphemeralKeyPair::generate(rng)),
        }
    }

    pub fn bundle(&self) -> PreKeyBundle {
        PreKeyBundle {
            identity: self.identity.public(),
            signed_prekey: self.signed_prekey.public(),
            signed_prekey_sig: self.identity.sign.sign(self.signed_prekey.public.as_bytes()),
            one_time_prekey: self.one_time_prekey.as_ref().map(|k| k.public()),
        }
    }
}
