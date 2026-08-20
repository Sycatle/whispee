//! Le verrou est ce qui sépare un état chiffré au repos d'un état lisible par quiconque
//! obtient le disque. Ces tests figent son comportement.

use crypto_core::lock::{SALT_LEN, derive_unlock_key};

const SEL: [u8; SALT_LEN] = [7u8; SALT_LEN];

#[test]
fn la_derivation_est_deterministe() {
    let a = derive_unlock_key("un mot de passe assez long", &SEL).unwrap();
    let b = derive_unlock_key("un mot de passe assez long", &SEL).unwrap();
    assert_eq!(a, b);
}

#[test]
fn deux_mots_de_passe_donnent_des_cles_differentes() {
    let a = derive_unlock_key("un mot de passe assez long", &SEL).unwrap();
    let b = derive_unlock_key("un mot de passe assez longs", &SEL).unwrap();
    assert_ne!(a, b);
}

/// Le sel interdit les tables précalculées : le même mot de passe sur deux appareils ne doit
/// pas produire la même clé, sinon casser l'un revient à casser tous les autres.
#[test]
fn le_sel_separe_les_appareils() {
    let a = derive_unlock_key("un mot de passe assez long", &SEL).unwrap();
    let b = derive_unlock_key("un mot de passe assez long", &[9u8; SALT_LEN]).unwrap();
    assert_ne!(a, b);
}

#[test]
fn un_sel_de_mauvaise_taille_est_refuse() {
    assert!(derive_unlock_key("peu importe", &[0u8; 8]).is_err());
}

/// Non-régression sur les paramètres.
///
/// Ce n'est pas un vecteur de conformité — c'est un garde-fou. Si ce test casse, le coût de
/// dérivation a changé, et **tous les états chiffrés existants deviennent illisibles** : leur
/// clé ne sera plus la même. Baisser ces paramètres affaiblit silencieusement chaque appareil
/// déjà déployé ; les augmenter casse le déverrouillage. Les deux méritent une décision
/// explicite, pas une mise à jour distraite de ce test.
#[test]
fn les_parametres_sont_figes() {
    let key = derive_unlock_key("mot de passe de reference", &SEL).unwrap();
    assert_eq!(hex::encode(key), "593cf6a8b414b58943847e366561d9a4004a8da42869d0c549a9bb4ffe1a9dcc");
}
