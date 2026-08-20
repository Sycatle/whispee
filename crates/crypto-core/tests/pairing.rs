//! L'appairage transporte la clé racine du compte. Une faille ici cède le compte entier.

use crypto_core::pairing::{PairingOffer, seal};

const SECRET: &[u8] = b"graine de compte, vaut le compte entier";

#[test]
fn le_paquet_scelle_est_ouvert_par_son_destinataire() {
    let offre = PairingOffer::generate();
    let (public, id) = (offre.public_key(), offre.id());

    let (paquet, code_emetteur) = seal(&public, &id, SECRET).unwrap();
    let ouvert = offre.open(&paquet).unwrap();

    assert_eq!(ouvert.plaintext, SECRET);
    // Le code doit concorder des deux côtés, sinon il ne sert à rien de le comparer.
    assert_eq!(ouvert.confirmation, code_emetteur);
    assert_eq!(code_emetteur.len(), 6);
}

/// Le serveur relaie le paquet. Il ne détient aucune des deux moitiés privées, donc il ne
/// peut pas l'ouvrir — pas plus qu'un tiers ayant photographié le QR code.
#[test]
fn un_tiers_ne_peut_pas_ouvrir_le_paquet() {
    let offre = PairingOffer::generate();
    let (public, id) = (offre.public_key(), offre.id());
    let (paquet, _) = seal(&public, &id, SECRET).unwrap();

    // L'intrus connaît tout ce qui a transité en clair : le QR et le paquet. Il lui manque
    // la clé privée éphémère, qui n'a jamais quitté le nouvel appareil.
    let intrus = PairingOffer::generate();

    assert!(intrus.open(&paquet).is_err());
}

/// L'identifiant d'appairage est l'AAD du chiffrement : un paquet destiné à une session ne
/// doit pas pouvoir être rejoué dans une autre.
#[test]
fn un_paquet_destine_a_une_autre_session_est_rejete() {
    let offre = PairingOffer::generate();
    let public = offre.public_key();

    let (paquet, _) = seal(&public, &[0u8; 16], SECRET).unwrap();

    // Même paire de clés, identifiant différent : l'AEAD refuse.
    assert!(offre.open(&paquet).is_err());
}

#[test]
fn un_paquet_altere_est_rejete() {
    let offre = PairingOffer::generate();
    let (public, id) = (offre.public_key(), offre.id());
    let (mut paquet, _) = seal(&public, &id, SECRET).unwrap();

    let dernier = paquet.len() - 1;
    paquet[dernier] ^= 0x01;

    assert!(offre.open(&paquet).is_err());
}

#[test]
fn un_paquet_tronque_est_rejete_sans_paniquer() {
    let offre = PairingOffer::generate();
    assert!(offre.open(&[0u8; 10]).is_err());
}

/// Deux appairages successifs ne doivent pas produire le même code de confirmation, sinon
/// comparer les codes ne prouve rien.
#[test]
fn deux_appairages_ont_des_codes_differents() {
    let mut codes = std::collections::HashSet::new();

    for _ in 0..20 {
        let offre = PairingOffer::generate();
        let (public, id) = (offre.public_key(), offre.id());
        codes.insert(seal(&public, &id, SECRET).unwrap().1);
    }

    assert!(codes.len() > 18, "les codes de confirmation se répètent");
}

/// Le QR ne doit contenir aucun secret : il est photographiable par construction.
#[test]
fn l_offre_ne_publie_que_des_valeurs_publiques() {
    let offre = PairingOffer::generate();
    let (public, id) = (offre.public_key(), offre.id());

    // Ce qui sort de l'offre, c'est exactement ce qui part dans le QR. Deux offres n'ont rien
    // en commun : aucune valeur fixe ne pourrait servir de secret partagé implicite.
    let autre = PairingOffer::generate();
    assert_ne!(public, autre.public_key());
    assert_ne!(id, autre.id());
}
