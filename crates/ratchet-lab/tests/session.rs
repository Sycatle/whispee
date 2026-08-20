//! Tests de bout en bout d'une session : établissement, conversation, désynchronisation.

mod common;

use common::TestRng;
use ratchet_lab::{IdentityKeyPair, PreKeyStore, RatchetError, Session, safety_number};

/// Monte une session Alice → Bob prête à l'emploi.
fn pair(with_one_time: bool) -> (TestRng, Session, Session, PreKeyStore) {
    let mut rng = TestRng::seed("session");
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let bob_store = PreKeyStore::generate(&mut rng, with_one_time);

    let (alice, initial) =
        Session::initiate(&mut rng, &alice_identity, &bob_store.bundle()).expect("bundle valide");
    let bob = Session::accept(&bob_store, &initial).expect("X3DH rejoué");

    (rng, alice, bob, bob_store)
}

#[test]
fn premier_message_dans_les_deux_sens() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let msg = alice.encrypt("salut Bob".as_bytes()).unwrap();
    assert_eq!(bob.decrypt(&mut rng, &msg).unwrap(), "salut Bob".as_bytes());

    // Bob ne peut répondre qu'après avoir reçu : c'est sa première réception qui lui donne
    // une chaîne d'envoi.
    let reply = bob.encrypt("salut Alice".as_bytes()).unwrap();
    assert_eq!(alice.decrypt(&mut rng, &reply).unwrap(), "salut Alice".as_bytes());
}

#[test]
fn bob_ne_peut_pas_ecrire_avant_de_recevoir() {
    let (_, _, mut bob, _) = pair(true);
    assert_eq!(bob.encrypt("trop tôt".as_bytes()).unwrap_err(), RatchetError::NoSession);
}

#[test]
fn session_sans_one_time_prekey() {
    // Cas réel : le stock de one-time prekeys de Bob est épuisé. La session doit tout de même
    // s'établir, avec une forward secrecy légèrement dégradée sur le premier message.
    let (mut rng, mut alice, mut bob, _) = pair(false);
    let msg = alice.encrypt("stock épuisé".as_bytes()).unwrap();
    assert_eq!(bob.decrypt(&mut rng, &msg).unwrap(), "stock épuisé".as_bytes());
}

#[test]
fn conversation_alternee_tourne_le_ratchet_dh() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let mut previous = alice.encrypt("tour 0".as_bytes()).unwrap().header.dh;
    bob.decrypt(&mut rng, &alice.encrypt("amorce".as_bytes()).unwrap()).ok();

    for tour in 0..10u32 {
        let from_alice = alice.encrypt(format!("A{tour}").as_bytes()).unwrap();
        assert_eq!(bob.decrypt(&mut rng, &from_alice).unwrap(), format!("A{tour}").as_bytes());

        let from_bob = bob.encrypt(format!("B{tour}").as_bytes()).unwrap();
        // Chaque changement de sens doit produire une nouvelle clé de ratchet : c'est
        // exactement ce qui donne la post-compromise security.
        assert_ne!(from_bob.header.dh.as_bytes(), previous.as_bytes());
        previous = from_bob.header.dh;

        assert_eq!(alice.decrypt(&mut rng, &from_bob).unwrap(), format!("B{tour}").as_bytes());
    }
}

#[test]
fn messages_hors_ordre() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let m0 = alice.encrypt("zéro".as_bytes()).unwrap();
    let m1 = alice.encrypt("un".as_bytes()).unwrap();
    let m2 = alice.encrypt("deux".as_bytes()).unwrap();

    // Le réseau les livre à l'envers.
    assert_eq!(bob.decrypt(&mut rng, &m2).unwrap(), "deux".as_bytes());
    assert_eq!(bob.skipped_count(), 2, "les clés de m0 et m1 doivent être mises de côté");

    assert_eq!(bob.decrypt(&mut rng, &m0).unwrap(), "zéro".as_bytes());
    assert_eq!(bob.decrypt(&mut rng, &m1).unwrap(), "un".as_bytes());
    assert_eq!(bob.skipped_count(), 0, "toutes les clés en attente doivent être consommées");
}

#[test]
fn message_definitivement_perdu_ne_bloque_pas_la_suite() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let _perdu = alice.encrypt("jamais livré".as_bytes()).unwrap();
    let suivant = alice.encrypt("celui-ci arrive".as_bytes()).unwrap();

    assert_eq!(bob.decrypt(&mut rng, &suivant).unwrap(), "celui-ci arrive".as_bytes());
    // La clé du message perdu reste en attente indéfiniment. C'est le compromis du Double
    // Ratchet : la robustesse au réseau se paie en clés vivantes conservées en mémoire.
    assert_eq!(bob.skipped_count(), 1);
}

#[test]
fn rejeu_refuse() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let msg = alice.encrypt("une seule fois".as_bytes()).unwrap();
    assert_eq!(bob.decrypt(&mut rng, &msg).unwrap(), "une seule fois".as_bytes());

    // La clé a été consommée puis détruite : le même chiffré ne doit plus jamais passer.
    assert_eq!(
        bob.decrypt(&mut rng, &msg).unwrap_err(),
        RatchetError::MessageKeyGone
    );
}

#[test]
fn saut_excessif_refuse() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let mut msg = alice.encrypt("charge".as_bytes()).unwrap();
    // Un pair malveillant annonce un index absurde pour forcer l'allocation de milliards
    // de clés. Le plafond MAX_SKIP doit couper.
    msg.header.n = 500_000;

    assert!(matches!(
        bob.decrypt(&mut rng, &msg).unwrap_err(),
        RatchetError::TooManySkipped(_, _)
    ));
}

#[test]
fn header_altere_rejete() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let m0 = alice.encrypt("zéro".as_bytes()).unwrap();
    let mut m1 = alice.encrypt("un".as_bytes()).unwrap();
    bob.decrypt(&mut rng, &m0).unwrap();

    // Le header est en clair mais authentifié par l'AEAD : le modifier doit casser le
    // déchiffrement, pas produire un autre texte.
    m1.header.pn = m1.header.pn.wrapping_add(1);
    assert_eq!(
        bob.decrypt(&mut rng, &m1).unwrap_err(),
        RatchetError::DecryptionFailed
    );
}

#[test]
fn ciphertext_altere_rejete() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let mut msg = alice.encrypt("intègre".as_bytes()).unwrap();
    msg.ciphertext[0] ^= 0x01;
    assert_eq!(
        bob.decrypt(&mut rng, &msg).unwrap_err(),
        RatchetError::DecryptionFailed
    );
}

#[test]
fn bundle_mal_signe_refuse() {
    let mut rng = TestRng::seed("mitm");
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let bob_store = PreKeyStore::generate(&mut rng, true);
    let attaquant = PreKeyStore::generate(&mut rng, true);

    // Le serveur substitue la signed prekey de Bob par celle d'un attaquant, en gardant
    // l'identité de Bob. La signature ne colle plus.
    let mut bundle = bob_store.bundle();
    bundle.signed_prekey = attaquant.signed_prekey.public();

    assert_eq!(
        Session::initiate(&mut rng, &alice_identity, &bundle).unwrap_err(),
        RatchetError::BadPreKeySignature
    );
}

#[test]
fn safety_number_identique_des_deux_cotes() {
    let mut rng = TestRng::seed("empreinte");
    let alice = IdentityKeyPair::generate(&mut rng).public();
    let bob = IdentityKeyPair::generate(&mut rng).public();

    // Les deux écrans doivent afficher la même chaîne, sans quoi la comparaison hors bande
    // est impossible.
    assert_eq!(safety_number(&alice, &bob), safety_number(&bob, &alice));
    assert_eq!(safety_number(&alice, &bob).chars().filter(|c| c.is_ascii_digit()).count(), 60);
}

#[test]
fn safety_number_change_si_lidentite_change() {
    let mut rng = TestRng::seed("empreinte-mitm");
    let alice = IdentityKeyPair::generate(&mut rng).public();
    let bob = IdentityKeyPair::generate(&mut rng).public();
    let attaquant = IdentityKeyPair::generate(&mut rng).public();

    // C'est la propriété qui rend la vérification utile : si le serveur substitue une
    // identité, l'empreinte affichée diffère et la comparaison hors bande le révèle.
    assert_ne!(safety_number(&alice, &bob), safety_number(&alice, &attaquant));
}
