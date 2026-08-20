//! Appairage d'un nouvel appareil, par canal visuel.
//!
//! # Le problème
//!
//! Un appareil neuf doit obtenir la clé racine du compte pour attester lui-même et attester
//! plus tard d'autres appareils. Ce secret ne peut ni transiter en clair par le serveur, ni
//! s'afficher à l'écran une seconde fois — une phrase relue est une phrase photographiable.
//!
//! # Le sens du QR code, et pourquoi il n'est pas arbitraire
//!
//! C'est le **nouvel** appareil qui affiche, l'**ancien** qui scanne. Le QR ne contient donc
//! aucun secret : seulement une clé publique éphémère et de quoi identifier l'appareil. Un QR
//! est photographiable par construction ; y mettre un secret reviendrait à le publier.
//!
//! L'ancien appareil scelle ensuite le paquet sous le secret X25519 partagé et le dépose sur
//! le serveur, qui n'en voit qu'un blob opaque : il ne détient aucune des deux moitiés
//! privées.
//!
//! # Ce que cela ne protège pas
//!
//! La sécurité du canal est **physique** : elle tient à ce que l'utilisateur ne scanne que
//! l'écran qu'il a en main. Un attaquant qui lui présente son propre QR est appairé, et aucune
//! cryptographie ne peut l'en empêcher. C'est le même modèle que WhatsApp et Signal.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};

/// Longueur de l'identifiant d'appairage. Aléatoire, il sert d'adresse de dépôt sur le serveur.
pub const PAIRING_ID_LEN: usize = 16;

const NONCE_LEN: usize = 12;
const INFO_SEAL: &[u8] = b"wac-pairing-seal-v1";
const INFO_CONFIRM: &[u8] = b"wac-pairing-confirm-v1";

/// Ce que le nouvel appareil publie dans son QR code.
///
/// Rien de secret : la clé éphémère est publique, et l'identifiant d'appairage n'est qu'une
/// adresse de dépôt. Un tiers qui photographie ce QR n'obtient rien — il ne peut pas ouvrir le
/// paquet, faute de la moitié privée.
pub struct PairingOffer {
    secret: EphemeralSecret,
    public: PublicKey,
    id: [u8; PAIRING_ID_LEN],
}

impl PairingOffer {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);

        let mut id = [0u8; PAIRING_ID_LEN];
        rand_core::OsRng.fill_bytes(&mut id);

        Self { secret, public, id }
    }

    pub fn id(&self) -> [u8; PAIRING_ID_LEN] {
        self.id
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Ouvre le paquet déposé par l'appareil d'origine.
    ///
    /// Consomme l'offre : le secret éphémère est détruit après un seul usage, ce qui interdit
    /// de rejouer un ancien paquet contre la même clé.
    pub fn open(self, sealed: &[u8]) -> Result<Opened> {
        if sealed.len() < 32 + NONCE_LEN {
            return Err(CryptoError::Malformed("paquet d'appairage tronqué"));
        }

        let mut peer = [0u8; 32];
        peer.copy_from_slice(&sealed[..32]);
        let peer = PublicKey::from(peer);

        let shared = self.secret.diffie_hellman(&peer);
        let (key, confirmation) = derive(shared.as_bytes(), &peer, &self.public, &self.id);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| CryptoError::Malformed("clé d'appairage invalide"))?;
        let nonce = Nonce::from_slice(&sealed[32..32 + NONCE_LEN]);

        let plaintext = cipher
            .decrypt(nonce, Payload { msg: &sealed[32 + NONCE_LEN..], aad: &self.id })
            .map_err(|_| CryptoError::Malformed("paquet d'appairage illisible ou altéré"))?;

        Ok(Opened { plaintext, confirmation })
    }
}

pub struct Opened {
    pub plaintext: Vec<u8>,
    /// Code court à comparer de visu sur les deux écrans.
    pub confirmation: String,
}

/// Scelle un paquet à destination du nouvel appareil.
///
/// `offer_public` et `offer_id` viennent du QR code, donc d'un canal hors bande que le serveur
/// ne voit pas. C'est ce qui rend le dépôt sûr malgré un serveur hostile.
pub fn seal(
    offer_public: &[u8],
    offer_id: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, String)> {
    let offer_public: [u8; 32] = offer_public
        .try_into()
        .map_err(|_| CryptoError::Malformed("clé d'appairage de taille invalide"))?;
    let offer_public = PublicKey::from(offer_public);

    // `StaticSecret` plutôt qu'`EphemeralSecret` : il faut la clé publique correspondante
    // dans le message, et dériver deux fois du même secret. Il est effacé juste après.
    let mut ours = StaticSecret::random_from_rng(rand_core::OsRng);
    let ours_public = PublicKey::from(&ours);
    let shared = ours.diffie_hellman(&offer_public);
    ours.zeroize();

    let (key, confirmation) = derive(shared.as_bytes(), &ours_public, &offer_public, offer_id);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| CryptoError::Malformed("clé d'appairage invalide"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: offer_id })
        .map_err(|_| CryptoError::Malformed("chiffrement d'appairage impossible"))?;

    let mut out = Vec::with_capacity(32 + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(ours_public.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok((out, confirmation))
}

/// Dérive la clé de scellement et le code de confirmation.
///
/// Les deux clés publiques entrent dans la dérivation **dans un ordre fixe** — celle de
/// l'appareil d'origine puis celle du nouvel appareil. Sans cet ordre, les deux côtés
/// calculeraient des valeurs différentes ; sans les inclure du tout, un attaquant pourrait
/// rejouer un secret partagé obtenu dans un autre échange.
fn derive(
    shared: &[u8],
    sender: &PublicKey,
    receiver: &PublicKey,
    pairing_id: &[u8],
) -> ([u8; 32], String) {
    let mut transcript = Vec::with_capacity(80);
    transcript.extend_from_slice(sender.as_bytes());
    transcript.extend_from_slice(receiver.as_bytes());
    transcript.extend_from_slice(pairing_id);

    let hkdf = Hkdf::<Sha256>::new(Some(&transcript), shared);

    let mut key = [0u8; 32];
    hkdf.expand(INFO_SEAL, &mut key).expect("32 octets valides pour HKDF-SHA256");

    let mut digest = [0u8; 4];
    hkdf.expand(INFO_CONFIRM, &mut digest).expect("4 octets valides pour HKDF-SHA256");

    // Six chiffres : assez pour qu'une collision accidentelle soit improbable, assez court
    // pour qu'un humain le compare réellement au lieu de cliquer « oui » sans regarder.
    let code = u32::from_be_bytes(digest) % 1_000_000;
    (key, format!("{code:06}"))
}
