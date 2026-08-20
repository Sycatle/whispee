//! Types de clés et matériel publié sur le serveur.
//!
//! Signal dérive la clé de signature de la clé DH via XEdDSA. On garde ici deux paires
//! distinctes (X25519 pour l'accord de clé, Ed25519 pour la signature) : c'est plus verbeux
//! mais l'intention de chaque clé reste lisible, ce qui est le but de cette crate.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::RatchetError;

/// Identité long terme d'un utilisateur. Ne change jamais : c'est elle que les empreintes
/// affichées à l'écran authentifient.
pub struct IdentityKeyPair {
    pub(crate) dh: StaticSecret,
    pub(crate) sign: SigningKey,
}

/// La moitié publique d'une identité, telle que servie par le serveur.
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
    /// Encodage stable utilisé dans les données associées de l'AEAD et dans le calcul
    /// d'empreinte. Doit rester identique des deux côtés, sans quoi tout déchiffrement échoue.
    pub fn encode(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.dh.as_bytes());
        out[32..].copy_from_slice(self.sign.as_bytes());
        out
    }
}

/// Paire éphémère ou semi-statique (signed prekey, one-time prekey, clé de ratchet).
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

/// Ce que Bob dépose sur le serveur pour qu'Alice puisse lui écrire hors ligne.
///
/// La `signed_prekey` est signée par l'identité Ed25519 de Bob : c'est ce qui empêche
/// le serveur de substituer sa propre clé. Cette signature ne dit en revanche rien de
/// l'authenticité de `identity` elle-même — c'est le rôle de la vérification d'empreinte.
pub struct PreKeyBundle {
    pub identity: IdentityPublic,
    pub signed_prekey: PublicKey,
    pub signed_prekey_sig: Signature,
    /// Consommée à l'usage. Son absence dégrade la forward secrecy du tout premier message.
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

/// L'état complet que Bob conserve localement en regard du bundle qu'il a publié.
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
