//! Le compte est la racine de confiance de tout le multi-appareils. Ces tests figent sa
//! dérivation et vérifient qu'il ne peut pas signer pour autrui.

use crypto_core::Account;

/// Phrase de test publique et notoire. **Ne jamais s'en servir ailleurs qu'ici.**
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn la_meme_phrase_redonne_le_meme_compte() {
    let a = Account::from_phrase(PHRASE).unwrap();
    let b = Account::from_phrase(PHRASE).unwrap();

    assert_eq!(a.identity_key(), b.identity_key());
    assert_eq!(a.fingerprint(), b.fingerprint());
}

/// Non-régression sur le format de dérivation.
///
/// Ce n'est **pas** un vecteur de conformité : il n'existe aucun standard pour dériver une
/// clé d'identité de messagerie depuis une graine BIP-39. C'est un garde-fou : si ce test
/// casse, la dérivation a changé, et tous les comptes existants sont devenus irrécupérables
/// avec leur phrase. C'est donc un changement de format à assumer explicitement, jamais un
/// test à mettre à jour distraitement.
#[test]
fn la_derivation_est_figee() {
    let account = Account::from_phrase(PHRASE).unwrap();
    let key = hex::encode(account.identity_key());

    assert_eq!(key, "001cb5f77239887d8bffef1f23ecb9ff237c730419b0104fc19affe61be83acc");
}

/// La clé du coffre doit être indépendante de la clé d'identité : compromettre l'une ne doit
/// rien apprendre sur l'autre. C'est ce que garantit la séparation des `info` HKDF.
#[test]
fn la_cle_du_coffre_est_distincte_de_la_cle_d_identite() {
    let account = Account::from_phrase(PHRASE).unwrap();
    assert_ne!(account.vault_key(), account.identity_key());
}

#[test]
fn deux_comptes_generes_sont_differents() {
    let (a, phrase_a) = Account::generate().unwrap();
    let (b, phrase_b) = Account::generate().unwrap();

    assert_ne!(a.identity_key(), b.identity_key());
    assert_ne!(phrase_a, phrase_b);
    assert_eq!(phrase_a.split_whitespace().count(), crypto_core::account::PHRASE_WORDS);
}

#[test]
fn la_phrase_generee_reconstruit_le_meme_compte() {
    let (account, phrase) = Account::generate().unwrap();
    let restaure = Account::from_phrase(&phrase).unwrap();

    assert_eq!(account.identity_key(), restaure.identity_key());
}

/// La somme de contrôle de BIP-39 attrape un mot mal recopié. Sans elle, l'utilisateur
/// obtiendrait un compte différent, parfaitement valide et parfaitement vide — le pire des
/// messages d'erreur possible.
#[test]
fn un_mot_mal_recopie_est_refuse() {
    let faute = PHRASE.replace("about", "abandon");
    assert!(Account::from_phrase(&faute).is_err());
}

#[test]
fn une_phrase_trop_courte_est_refusee() {
    assert!(Account::from_phrase("abandon abandon abandon").is_err());
}

/// Les espaces en trop viennent d'un copier-coller, pas d'une attaque. Les tolérer évite un
/// échec incompréhensible sur une phrase pourtant correcte.
#[test]
fn les_espaces_superflus_sont_tolerés() {
    let account = Account::from_phrase(&format!("  {PHRASE}\n")).unwrap();
    assert_eq!(account.identity_key(), Account::from_phrase(PHRASE).unwrap().identity_key());
}

#[test]
fn le_compte_atteste_ses_propres_appareils() {
    let account = Account::from_phrase(PHRASE).unwrap();
    let auth_key = [1u8; 32];
    let mls_key = [2u8; 32];

    let signature = account.attest("alice", "portable", &auth_key, &mls_key).unwrap();
    let claim = attest::DeviceClaim {
        handle: "alice",
        device_id: "portable",
        auth_key: &auth_key,
        mls_key: &mls_key,
    };

    assert!(attest::verify(&account.identity_key(), &claim, &signature).is_ok());
}

/// Un compte ne peut pas attester pour un autre handle : l'attestation qu'il produit ne
/// vérifie que sous son propre pseudonyme.
#[test]
fn un_compte_ne_peut_pas_attester_pour_un_autre_handle() {
    let account = Account::from_phrase(PHRASE).unwrap();
    let signature = account.attest("alice", "portable", &[1u8; 32], &[2u8; 32]).unwrap();

    let usurpe = attest::DeviceClaim {
        handle: "bob",
        device_id: "portable",
        auth_key: &[1u8; 32],
        mls_key: &[2u8; 32],
    };

    assert!(attest::verify(&account.identity_key(), &usurpe, &signature).is_err());
}

/// L'appairage transmet la graine, pas la phrase : l'appareil appairé doit obtenir exactement
/// le même pouvoir, y compris celui d'attester à son tour.
#[test]
fn la_graine_transmise_reconstruit_un_compte_equivalent() {
    let source = Account::from_phrase(PHRASE).unwrap();
    let appaire = Account::from_seed(source.export_seed());

    assert_eq!(source.identity_key(), appaire.identity_key());
    assert_eq!(source.vault_key(), appaire.vault_key());

    let signature = appaire.attest("alice", "tablette", &[3u8; 32], &[4u8; 32]).unwrap();
    let claim = attest::DeviceClaim {
        handle: "alice",
        device_id: "tablette",
        auth_key: &[3u8; 32],
        mls_key: &[4u8; 32],
    };
    assert!(attest::verify(&source.identity_key(), &claim, &signature).is_ok());
}

/// `Debug` ne doit jamais laisser fuir la clé privée dans un journal.
#[test]
fn le_debug_ne_divulgue_pas_le_secret() {
    let account = Account::from_phrase(PHRASE).unwrap();
    let rendu = format!("{account:?}");

    assert!(rendu.contains(&account.fingerprint()));
    assert!(!rendu.contains(&hex::encode(account.export_seed())));
}

/// Le certificat de révocation produit par le compte doit être vérifiable par un tiers qui ne
/// détient que la clé publique — c'est toute sa raison d'être : permettre à un autre membre du
/// groupe de commiter le retrait sans croire le serveur.
#[test]
fn un_certificat_de_revocation_est_verifiable_par_un_tiers() {
    let (account, _) = Account::generate().unwrap();
    let certificat = account.revoke("alice", "alice:portable", 1_700_000_000).unwrap();

    let claim =
        attest::RevocationClaim { handle: "alice", device_id: "alice:portable", revoked_at: 1_700_000_000 };

    assert!(attest::verify_revocation(&account.identity_key(), &claim, &certificat).is_ok());
}

/// Un compte ne révoque que ses propres appareils. Sans cette propriété, révoquer reviendrait
/// à pouvoir évincer n'importe qui du réseau.
#[test]
fn un_compte_ne_peut_pas_revoquer_pour_un_autre_handle() {
    let (alice, _) = Account::generate().unwrap();
    let (bob, _) = Account::generate().unwrap();

    let certificat = alice.revoke("bob", "bob:portable", 1_700_000_000).unwrap();
    let claim =
        attest::RevocationClaim { handle: "bob", device_id: "bob:portable", revoked_at: 1_700_000_000 };

    // Signé par Alice, donc invalide sous la clé de Bob : le serveur comme les autres clients
    // vérifient contre la clé du compte *nommé* dans le certificat.
    assert!(attest::verify_revocation(&bob.identity_key(), &claim, &certificat).is_err());
}
