//! Tests de non-régression sur les dérivations et le format des messages.
//!
//! **Ces vecteurs ne sont pas des vecteurs de conformité.** Il n'existe pas de vecteurs
//! officiels publiés pour X3DH et le Double Ratchet, et les chaînes `info` utilisées ici
//! sont propres au projet : aucun vecteur externe ne pourrait s'y appliquer. Ils ne
//! démontrent donc pas la correction du protocole, seulement sa **stabilité** — toute
//! modification involontaire d'une KDF, d'une chaîne `info` ou d'un encodage casse ces
//! tests, ce qui est exactement leur rôle.
//!
//! Une modification volontaire du protocole rend ces valeurs obsolètes : il faut alors les
//! régénérer *et* considérer que les sessions existantes deviennent indéchiffrables.

mod common;

use common::TestRng;
use ratchet_lab::kdf::{derive_message_keys, kdf_ck, kdf_rk, kdf_x3dh};
use ratchet_lab::{IdentityKeyPair, PreKeyStore, Session, safety_number};

#[test]
fn kdf_x3dh_stable() {
    let sk = kdf_x3dh(&[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);
    assert_eq!(
        hex::encode(sk),
        "7ba90c8693c70d96ef1e74987dd927cd01b1eafe929fd76c5684a71514dc2841"
    );
}

#[test]
fn kdf_rk_stable() {
    let (rk, ck) = kdf_rk(&[7u8; 32], &[9u8; 32]);
    assert_eq!(
        hex::encode(rk),
        "a8ab7079000bc32228478acaacd573722a0ab332c81dc43ab5fe7e73de7b9456"
    );
    assert_eq!(
        hex::encode(ck),
        "5e4124e85c7c0b11e72e9d213f3a415d55328c960291f86ff2f6a632056eeec2"
    );
    // La racine et la chaîne sortent du même HKDF : elles doivent être indépendantes.
    assert_ne!(rk, ck);
}

#[test]
fn kdf_ck_stable() {
    let (next, mk) = kdf_ck(&[5u8; 32]);
    assert_eq!(
        hex::encode(next),
        "d1d4e2a94a095ae5327b9a660032c22225ae7710823f997cc250f31e5d3aeb50"
    );
    assert_eq!(
        hex::encode(mk),
        "0d8b1b5bd928a4cfab6708b6af6fe15d5d41b3268e6dd8ed9c5b0ecde10ca4a2"
    );
    // Les constantes 0x01/0x02 doivent séparer les deux sorties. Si elles se confondaient,
    // la clé de message serait la chaîne suivante et toute la forward secrecy tomberait.
    assert_ne!(next, mk);
}

#[test]
fn derive_message_keys_stable() {
    let (key, nonce) = derive_message_keys(&[6u8; 32]);
    assert_eq!(
        hex::encode(key),
        "6e60fe394662a0f0a1f0579079edd7892c0f3596b2a77a1733b76808d2351e7f"
    );
    assert_eq!(hex::encode(nonce), "3f5f5307d007c1c598fb3a73");
}

#[test]
fn nonce_unique_par_cle_de_message() {
    // AES-GCM casse catastrophiquement si un nonce est réutilisé sous la même clé. Ici le
    // nonce est dérivé de la clé de message, et chaque clé de message est utilisée une seule
    // fois : la réutilisation est structurellement impossible. Ce test verrouille la partie
    // vérifiable de cet argument — deux clés distinctes ne doivent pas colliding.
    let (k1, n1) = derive_message_keys(&[1u8; 32]);
    let (k2, n2) = derive_message_keys(&[2u8; 32]);
    assert_ne!(k1, k2);
    assert_ne!(n1, n2);
}

#[test]
fn format_de_message_stable() {
    let mut rng = TestRng::seed("kat-v1");
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let bob_store = PreKeyStore::generate(&mut rng, true);

    let (mut alice, initial) =
        Session::initiate(&mut rng, &alice_identity, &bob_store.bundle()).unwrap();
    let mut bob = Session::accept(&bob_store, &initial).unwrap();

    let msg = alice.encrypt(b"kat").unwrap();
    assert_eq!(
        hex::encode(msg.header.encode()),
        "636814bfa7457a53977cb7459d28ac8fcd29ae38607dde2986489f97aa992a790000000000000000"
    );
    assert_eq!(hex::encode(&msg.ciphertext), "85896d65b928dbc47efc42c029484dda1d1f5f");

    // 3 octets de clair + 16 octets de tag GCM. La longueur du clair fuit : c'est une
    // métadonnée que seul du padding masquerait.
    assert_eq!(msg.ciphertext.len(), 3 + 16);

    assert_eq!(bob.decrypt(&mut rng, &msg).unwrap(), b"kat");
}

#[test]
fn safety_number_stable() {
    let mut rng = TestRng::seed("kat-v1");
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let bob_store = PreKeyStore::generate(&mut rng, true);

    assert_eq!(
        safety_number(&alice_identity.public(), &bob_store.identity.public()),
        "88555 35116 70307 42839 78804 52916 39112 31605 32156 72106 24601 31290"
    );
}
