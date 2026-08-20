//! Fonctions de dérivation. Toutes les clés du protocole sortent d'ici.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Les chaînes `info` séparent les domaines d'usage : deux dérivations distinctes ne doivent
/// jamais pouvoir produire la même clé, même à entrée identique.
const INFO_X3DH: &[u8] = b"ratchet-lab/x3dh/v1";
const INFO_ROOT: &[u8] = b"ratchet-lab/root/v1";
const INFO_MESSAGE: &[u8] = b"ratchet-lab/message/v1";

/// Octets constants préfixant l'entrée de X3DH. Pour X25519, Signal utilise 32 octets 0xFF.
/// Ils empêchent une confusion entre l'IKM de X3DH et une sortie DH brute.
const X3DH_PREFIX: [u8; 32] = [0xFF; 32];

/// Clé racine du Double Ratchet.
pub type RootKey = [u8; 32];
/// Clé de chaîne : avance d'un cran par message envoyé ou reçu.
pub type ChainKey = [u8; 32];
/// Clé d'un message unique. Détruite après usage — c'est ce qui donne la forward secrecy.
pub type MessageKey = [u8; 32];

/// KDF de X3DH : concatène les sorties DH et en tire le secret partagé initial.
pub fn kdf_x3dh(dh_outputs: &[[u8; 32]]) -> RootKey {
    let mut ikm = Vec::with_capacity(32 + dh_outputs.len() * 32);
    ikm.extend_from_slice(&X3DH_PREFIX);
    for dh in dh_outputs {
        ikm.extend_from_slice(dh);
    }

    let mut sk = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm)
        .expand(INFO_X3DH, &mut sk)
        .expect("32 octets est une longueur valide pour HKDF-SHA256");

    ikm.zeroize();
    sk
}

/// Ratchet DH : la clé racine courante et une nouvelle sortie DH produisent la racine
/// suivante et une chaîne neuve. C'est cette étape qui donne la post-compromise security :
/// un attaquant qui a volé l'état ne peut pas suivre s'il rate un seul aller-retour.
pub fn kdf_rk(rk: &RootKey, dh_out: &[u8; 32]) -> (RootKey, ChainKey) {
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(rk), dh_out)
        .expand(INFO_ROOT, &mut okm)
        .expect("64 octets est une longueur valide pour HKDF-SHA256");

    let mut next_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    next_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);

    okm.zeroize();
    (next_rk, ck)
}

/// Ratchet symétrique : un cran de chaîne produit une clé de message et la chaîne suivante.
/// Les constantes 0x01/0x02 rendent les deux sorties indépendantes.
pub fn kdf_ck(ck: &ChainKey) -> (ChainKey, MessageKey) {
    let mk = hmac_once(ck, &[0x01]);
    let next_ck = hmac_once(ck, &[0x02]);
    (next_ck, mk)
}

/// Éclate une clé de message en matériel AEAD. Le nonce est dérivé et non aléatoire : chaque
/// clé de message étant utilisée exactement une fois, la réutilisation de nonce — fatale en
/// GCM — est structurellement impossible.
pub fn derive_message_keys(mk: &MessageKey) -> ([u8; 32], [u8; 12]) {
    let mut okm = [0u8; 44];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk)
        .expand(INFO_MESSAGE, &mut okm)
        .expect("44 octets est une longueur valide pour HKDF-SHA256");

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);

    okm.zeroize();
    (key, nonce)
}

fn hmac_once(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepte toute longueur de clé");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
