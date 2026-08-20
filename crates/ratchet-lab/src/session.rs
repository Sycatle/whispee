//! Assemblage : X3DH pour établir la session, Double Ratchet pour la faire vivre.

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
    /// Alice ouvre une session à partir du seul bundle de Bob. Bob peut être hors ligne.
    pub fn initiate<R: RngCore + CryptoRng>(
        rng: &mut R,
        identity: &IdentityKeyPair,
        bundle: &PreKeyBundle,
    ) -> Result<(Self, InitialMessage), RatchetError> {
        let (outcome, initial) = x3dh::initiate(rng, identity, bundle)?;

        // La signed prekey de Bob sert de première clé de ratchet : c'est la seule clé
        // publique de Bob qu'Alice possède déjà, ce qui lui permet d'écrire en premier.
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

    /// Bob accepte la session en rejouant X3DH depuis son propre matériel.
    ///
    /// En production, la one-time prekey consommée doit être supprimée du store ici même :
    /// la réutiliser annulerait la forward secrecy qu'elle apporte.
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

/// Nombre d'itérations de hachage dans le calcul d'empreinte. Signal en fait 5200 : le coût
/// est négligeable pour l'utilisateur mais rend la recherche d'une collision partielle —
/// une clé dont l'empreinte *ressemble* à la vraie — nettement plus chère pour un attaquant.
const FINGERPRINT_ITERATIONS: u32 = 5_200;

/// Empreinte affichable d'une paire d'identités, façon « safety number ».
///
/// Les deux participants comparent cette chaîne hors bande (de visu, ou par QR code). Sans
/// cette comparaison, rien n'empêche le serveur de servir à chacun une identité qu'il contrôle
/// et de relayer en clair : le chiffrement fonctionne parfaitement, mais avec l'attaquant au
/// milieu. C'est le maillon faible réel de la plupart des déploiements, parce que presque
/// personne ne fait la comparaison.
///
/// Le tri rend le résultat indépendant de qui regarde : les deux écrans affichent la même chose.
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

        // 6 groupes de 5 chiffres par identité, soit 60 chiffres au total pour la paire.
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
