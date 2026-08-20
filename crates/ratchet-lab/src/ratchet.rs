//! Double Ratchet.
//!
//! Deux ratchets s'imbriquent :
//!
//! * le **ratchet symétrique** avance d'un cran par message et donne une clé unique par
//!   message, détruite après usage → forward secrecy ;
//! * le **ratchet DH** régénère une paire éphémère à chaque changement de sens de la
//!   conversation et réamorce la clé racine → post-compromise security.
//!
//! Le second est ce qui distingue vraiment le Double Ratchet : un attaquant ayant volé
//! l'état complet perd l'accès dès qu'un aller-retour lui échappe.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use crate::error::RatchetError;
use crate::kdf::{ChainKey, MessageKey, RootKey, derive_message_keys, kdf_ck, kdf_rk};
use crate::keys::EphemeralKeyPair;

/// Plafond de messages sautés conservés. Sans plafond, un pair malveillant annonce
/// `n = u32::MAX` et force l'allocation de milliards de clés : déni de service trivial.
const MAX_SKIP: u32 = 1_000;

/// En clair dans le message : le destinataire en a besoin avant de pouvoir déchiffrer.
/// Le header est authentifié par l'AEAD, donc non modifiable, mais il est lisible par le
/// serveur — il fait partie des métadonnées que le E2EE ne protège pas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub dh: PublicKey,
    /// Longueur de la chaîne d'envoi précédente : dit au destinataire combien de clés
    /// sauter avant de tourner le ratchet.
    pub pn: u32,
    /// Position dans la chaîne courante.
    pub n: u32,
}

impl Header {
    pub const LEN: usize = 40;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..32].copy_from_slice(self.dh.as_bytes());
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RatchetError> {
        if bytes.len() != Self::LEN {
            return Err(RatchetError::Malformed("taille de header invalide"));
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&bytes[..32]);
        Ok(Self {
            dh: PublicKey::from(dh),
            pn: u32::from_be_bytes(bytes[32..36].try_into().unwrap()),
            n: u32::from_be_bytes(bytes[36..].try_into().unwrap()),
        })
    }
}

#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

pub struct DoubleRatchet {
    /// Notre paire de ratchet courante.
    dhs: EphemeralKeyPair,
    /// Celle du pair. `None` tant qu'on n'a rien reçu.
    dhr: Option<PublicKey>,
    rk: RootKey,
    cks: Option<ChainKey>,
    ckr: Option<ChainKey>,
    ns: u32,
    nr: u32,
    pn: u32,
    /// Clés des messages arrivés hors-ordre ou pas encore arrivés. Indexées par
    /// (clé de ratchet de l'émetteur, index). Chaque entrée est une clé vivante :
    /// c'est du matériel sensible, et sa durée de vie doit rester bornée.
    skipped: HashMap<([u8; 32], u32), MessageKey>,
    ad: Vec<u8>,
}

impl DoubleRatchet {
    /// Côté initiateur. Alice connaît déjà la clé publique de ratchet de Bob — c'est sa
    /// signed prekey — donc elle peut tourner le ratchet DH immédiatement et écrire en premier.
    pub fn init_initiator<R: RngCore + CryptoRng>(
        rng: &mut R,
        shared_secret: RootKey,
        associated_data: Vec<u8>,
        responder_ratchet_key: PublicKey,
    ) -> Self {
        let dhs = EphemeralKeyPair::generate(rng);
        let dh_out = dhs.secret.diffie_hellman(&responder_ratchet_key).to_bytes();
        let (rk, cks) = kdf_rk(&shared_secret, &dh_out);

        Self {
            dhs,
            dhr: Some(responder_ratchet_key),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            ad: associated_data,
        }
    }

    /// Côté répondeur. Bob n'a pas encore vu de clé de ratchet d'Alice : il n'a pas de
    /// chaîne d'envoi et ne peut donc pas écrire avant d'avoir reçu. La première réception
    /// déclenche le premier ratchet DH.
    pub fn init_responder(
        shared_secret: RootKey,
        associated_data: Vec<u8>,
        signed_prekey: EphemeralKeyPair,
    ) -> Self {
        Self {
            dhs: signed_prekey,
            dhr: None,
            rk: shared_secret,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            ad: associated_data,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Message, RatchetError> {
        let cks = self.cks.as_ref().ok_or(RatchetError::NoSession)?;
        let (next_cks, mut mk) = kdf_ck(cks);
        self.cks = Some(next_cks);

        let header = Header {
            dh: self.dhs.public(),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let ciphertext = aead_seal(&mk, plaintext, &self.aad_for(&header))?;
        mk.zeroize();

        Ok(Message { header, ciphertext })
    }

    pub fn decrypt<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<u8>, RatchetError> {
        // Cas 1 : le message avait été sauté. Sa clé nous attend.
        if let Some(mut mk) = self.skipped.remove(&(*message.header.dh.as_bytes(), message.header.n))
        {
            let plaintext = aead_open(&mk, &message.ciphertext, &self.aad_for(&message.header))?;
            mk.zeroize();
            return Ok(plaintext);
        }

        // Cas 2 : le pair a tourné son ratchet. On solde l'ancienne chaîne avant de suivre.
        if self.dhr.as_ref().map(|k| k.as_bytes()) != Some(message.header.dh.as_bytes()) {
            self.skip_message_keys(message.header.pn)?;
            self.dh_ratchet(rng, &message.header);
        }

        // Cas 3 : chaîne courante, éventuellement en avance sur nous.
        self.skip_message_keys(message.header.n)?;

        let ckr = self.ckr.as_ref().ok_or(RatchetError::NoSession)?;
        let (next_ckr, mut mk) = kdf_ck(ckr);
        self.ckr = Some(next_ckr);
        self.nr += 1;

        let plaintext = aead_open(&mk, &message.ciphertext, &self.aad_for(&message.header))?;
        mk.zeroize();
        Ok(plaintext)
    }

    /// Nombre de clés en attente. Exposé pour que les tests puissent vérifier que les clés
    /// sautées sont bien consommées et non accumulées indéfiniment.
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Empreinte de la clé de ratchet courante. Sert uniquement au débogage : l'empreinte
    /// affichée à l'utilisateur doit porter sur l'identité long terme, pas sur celle-ci.
    pub fn ratchet_public(&self) -> PublicKey {
        self.dhs.public()
    }

    fn aad_for(&self, header: &Header) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.ad.len() + Header::LEN);
        aad.extend_from_slice(&self.ad);
        aad.extend_from_slice(&header.encode());
        aad
    }

    /// Avance la chaîne de réception jusqu'à `until` en mettant les clés de côté, pour que
    /// les messages en retard restent déchiffrables à leur arrivée.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        let Some(ckr) = self.ckr.as_ref() else {
            // Pas encore de chaîne de réception : rien à sauter. Ce n'est une erreur que si
            // le pair prétend qu'on a déjà reçu des messages.
            return if until == 0 {
                Ok(())
            } else {
                Err(RatchetError::NoSession)
            };
        };

        if until < self.nr {
            // Le message est antérieur à la position courante et n'était pas en attente :
            // sa clé a déjà été consommée et détruite. Rejeu ou doublon.
            return Err(RatchetError::MessageKeyGone);
        }

        let to_skip = until - self.nr;
        if to_skip > MAX_SKIP {
            return Err(RatchetError::TooManySkipped(to_skip, MAX_SKIP));
        }

        let dhr = *self.dhr.as_ref().ok_or(RatchetError::NoSession)?.as_bytes();
        let mut chain = *ckr;
        for n in self.nr..until {
            let (next, mk) = kdf_ck(&chain);
            self.skipped.insert((dhr, n), mk);
            chain = next;
        }

        self.ckr = Some(chain);
        self.nr = until;
        Ok(())
    }

    /// Le ratchet DH proprement dit : deux dérivations de racine, une pour la chaîne de
    /// réception (avec l'ancienne paire), une pour la chaîne d'envoi (avec la nouvelle).
    fn dh_ratchet<R: RngCore + CryptoRng>(&mut self, rng: &mut R, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);

        let dh_out = self.dhs.secret.diffie_hellman(&header.dh).to_bytes();
        let (rk, ckr) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dhs = EphemeralKeyPair::generate(rng);
        let dh_out = self.dhs.secret.diffie_hellman(&header.dh).to_bytes();
        let (rk, cks) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk;
        self.cks = Some(cks);
    }
}

fn aead_seal(mk: &MessageKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let (key, nonce) = derive_message_keys(mk);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| RatchetError::DecryptionFailed)
}

fn aead_open(mk: &MessageKey, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let (key, nonce) = derive_message_keys(mk);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| RatchetError::DecryptionFailed)
}

/// Debug volontairement muet sur l'état secret.
///
/// Dériver `Debug` ici recracherait clés racine, clés de chaîne et clés de message dans le
/// premier `dbg!` ou la première ligne de log venue. C'est une façon banale et discrète de
/// réduire à néant tout le protocole, et elle passe les revues de code parce que personne
/// ne regarde un derive.
impl std::fmt::Debug for DoubleRatchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoubleRatchet")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped", &self.skipped.len())
            .field("has_sending_chain", &self.cks.is_some())
            .field("has_receiving_chain", &self.ckr.is_some())
            .finish_non_exhaustive()
    }
}
