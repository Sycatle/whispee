//! Le format canonique est le seul endroit du projet où une erreur de sérialisation devient
//! une faille d'authentification. Ces tests le figent.

use attest::{AttestError, DeviceClaim, message, verify};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;

fn claim<'a>(handle: &'a str, device_id: &'a str) -> DeviceClaim<'a> {
    DeviceClaim { handle, device_id, auth_key: &[7u8; 32], mls_key: &[9u8; 32] }
}

fn account() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

#[test]
fn une_attestation_produite_par_le_compte_est_acceptee() {
    let key = account();
    let claim = claim("alice", "portable");
    let signature = key.sign(&message(&claim).unwrap());

    assert!(verify(key.verifying_key().as_bytes(), &claim, &signature.to_bytes()).is_ok());
}

#[test]
fn un_autre_compte_ne_peut_pas_attester_a_notre_place() {
    let legitime = account();
    let imposteur = account();
    let claim = claim("alice", "portable");

    let signature = imposteur.sign(&message(&claim).unwrap());

    assert_eq!(
        verify(legitime.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// Le cœur du sujet : une attestation obtenue pour un appareil ne doit pas valoir pour un
/// autre. C'est ce qui empêche de recycler l'attestation d'un appareil légitime révoqué.
#[test]
fn une_attestation_ne_vaut_que_pour_son_appareil() {
    let key = account();
    let signature = key.sign(&message(&claim("alice", "portable")).unwrap());

    assert_eq!(
        verify(key.verifying_key().as_bytes(), &claim("alice", "tablette"), &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// Une attestation pour le compte d'Alice ne doit pas valoir dans le compte de Bob, même si
/// l'appareil est le même. Sans cela, Bob rattache à son compte un appareil d'Alice.
#[test]
fn une_attestation_ne_vaut_que_pour_son_compte() {
    let key = account();
    let signature = key.sign(&message(&claim("alice", "portable")).unwrap());

    assert_eq!(
        verify(key.verifying_key().as_bytes(), &claim("bob", "portable"), &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// La raison d'être des préfixes de longueur.
///
/// Concaténés sans préfixe, `("ab", "c")` et `("a", "bc")` donnent les mêmes octets : une
/// attestation obtenue pour l'un serait valide pour l'autre. Un attaquant choisissant son
/// handle et son identifiant d'appareil peut fabriquer une telle collision à volonté.
#[test]
fn deux_decoupages_differents_ne_collisionnent_pas() {
    assert_ne!(
        message(&claim("ab", "c")).unwrap(),
        message(&claim("a", "bc")).unwrap(),
    );
}

/// Les deux clés sont attestées ensemble. Les traiter séparément permettrait de combiner la
/// clé d'authentification d'un appareil légitime avec la clé MLS d'un appareil hostile.
#[test]
fn substituer_la_cle_mls_invalide_l_attestation() {
    let key = account();
    let original = claim("alice", "portable");
    let signature = key.sign(&message(&original).unwrap());

    let substitue = DeviceClaim { mls_key: &[0xff; 32], ..original };

    assert_eq!(
        verify(key.verifying_key().as_bytes(), &substitue, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

#[test]
fn une_signature_tronquee_est_rejetee_sans_paniquer() {
    let key = account();
    let claim = claim("alice", "portable");
    let signature = key.sign(&message(&claim).unwrap());

    assert_eq!(
        verify(key.verifying_key().as_bytes(), &claim, &signature.to_bytes()[..63]),
        Err(AttestError::BadSignature),
    );
}

#[test]
fn une_cle_d_identite_mal_dimensionnee_est_rejetee_sans_paniquer() {
    let claim = claim("alice", "portable");
    assert_eq!(verify(&[0u8; 31], &claim, &[0u8; 64]), Err(AttestError::BadIdentityKey));
}

/// L'empreinte ne bouge pas quand le compte gagne un appareil : c'est ce qui permet de ne pas
/// redemander une vérification hors bande à chaque événement légitime.
#[test]
fn l_empreinte_ne_depend_que_de_la_cle_de_compte() {
    let key = account();
    let a = attest::fingerprint(key.verifying_key().as_bytes());
    let b = attest::fingerprint(key.verifying_key().as_bytes());

    assert_eq!(a, b);
    assert_ne!(a, attest::fingerprint(account().verifying_key().as_bytes()));
}

// ---------------------------------------------------------------------------------------
// Certificats de révocation
// ---------------------------------------------------------------------------------------

use attest::{RevocationClaim, revocation_message, verify_revocation};

fn revocation<'a>(handle: &'a str, device_id: &'a str, revoked_at: u64) -> RevocationClaim<'a> {
    RevocationClaim { handle, device_id, revoked_at }
}

#[test]
fn un_certificat_de_revocation_produit_par_le_compte_est_accepte() {
    let key = account();
    let claim = revocation("alice", "alice:portable", 1_700_000_000);
    let signature = key.sign(&revocation_message(&claim).unwrap());

    assert_eq!(
        verify_revocation(key.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Ok(()),
    );
}

/// Sans quoi n'importe quel compte ferait évincer les appareils de n'importe qui.
#[test]
fn un_autre_compte_ne_peut_pas_revoquer_a_notre_place() {
    let victime = account();
    let attaquant = account();
    let claim = revocation("alice", "alice:portable", 1_700_000_000);
    let signature = attaquant.sign(&revocation_message(&claim).unwrap());

    assert_eq!(
        verify_revocation(victime.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// Un certificat ne vaut que pour l'appareil qu'il nomme : sinon révoquer son propre vieux
/// téléphone permettrait d'évincer n'importe lequel de ses autres appareils.
#[test]
fn un_certificat_ne_vaut_que_pour_son_appareil() {
    let key = account();
    let emis = revocation("alice", "alice:portable", 1_700_000_000);
    let signature = key.sign(&revocation_message(&emis).unwrap());

    let autre = revocation("alice", "alice:desktop", 1_700_000_000);
    assert_eq!(
        verify_revocation(key.verifying_key().as_bytes(), &autre, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// L'horodatage est couvert par la signature. Un serveur qui pourrait le modifier antidaterait
/// une révocation authentique pour prétendre qu'un appareil était déjà écarté au moment où il
/// a légitimement reçu un message.
#[test]
fn l_horodatage_est_couvert_par_la_signature() {
    let key = account();
    let emis = revocation("alice", "alice:portable", 1_700_000_000);
    let signature = key.sign(&revocation_message(&emis).unwrap());

    let antidate = revocation("alice", "alice:portable", 1_600_000_000);
    assert_eq!(
        verify_revocation(key.verifying_key().as_bytes(), &antidate, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// **Le test qui justifie la séparation de domaine.**
///
/// Sans étiquette distincte, l'attestation d'un appareil — que tout le monde détient, puisque
/// le serveur la sert publiquement — serait présentable comme certificat de révocation du même
/// appareil. N'importe qui pourrait alors faire évincer n'importe quel appareil du réseau.
#[test]
fn une_attestation_ne_peut_pas_etre_rejouee_comme_revocation() {
    let key = account();
    let device = claim("alice", "alice:portable");
    let attestation = key.sign(&message(&device).unwrap());

    // Toutes les valeurs d'horodatage possibles échouent ; on en teste une, la structure du
    // message suffit à l'expliquer : les octets de domaine diffèrent dès le premier.
    let comme_revocation = revocation("alice", "alice:portable", 1_700_000_000);
    assert_eq!(
        verify_revocation(
            key.verifying_key().as_bytes(),
            &comme_revocation,
            &attestation.to_bytes(),
        ),
        Err(AttestError::BadSignature),
    );

    // Et la réciproque : un certificat de révocation ne vaut pas attestation.
    let certificat = key.sign(&revocation_message(&comme_revocation).unwrap());
    assert_eq!(
        verify(key.verifying_key().as_bytes(), &device, &certificat.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// Même raison que pour l'attestation : `("ab", "c")` et `("a", "bc")` doivent différer.
#[test]
fn deux_decoupages_differents_ne_collisionnent_pas_en_revocation() {
    assert_ne!(
        revocation_message(&revocation("ab", "c", 1)).unwrap(),
        revocation_message(&revocation("a", "bc", 1)).unwrap(),
    );
}

// ---------------------------------------------------------------------------------------
// Rotation de compte
// ---------------------------------------------------------------------------------------

use attest::{RotationClaim, rotation_message, verify_rotation};

fn rotation<'a>(handle: &'a str, nouvelle: &'a [u8], at: u64) -> RotationClaim<'a> {
    RotationClaim { handle, new_identity_key: nouvelle, rotated_at: at }
}

/// La rotation se vérifie contre l'**ancienne** clé : c'est elle qui désigne la nouvelle.
#[test]
fn une_rotation_se_verifie_contre_l_ancienne_cle() {
    let ancienne = account();
    let nouvelle = account();
    let nouvelle_pub = nouvelle.verifying_key().to_bytes();

    let claim = rotation("alice", &nouvelle_pub, 1_700_000_000);
    let signature = ancienne.sign(&rotation_message(&claim).unwrap());

    assert_eq!(
        verify_rotation(ancienne.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Ok(()),
    );

    // Vérifier contre la nouvelle clé ne prouverait que la possession de celle-ci, soit rien.
    assert_eq!(
        verify_rotation(&nouvelle_pub, &claim, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// Sans continuité prouvée, n'importe qui reprendrait le handle d'autrui.
#[test]
fn un_tiers_ne_peut_pas_faire_tourner_un_compte() {
    let victime = account();
    let attaquant = account();
    let cible = account().verifying_key().to_bytes();

    let claim = rotation("alice", &cible, 1_700_000_000);
    let signature = attaquant.sign(&rotation_message(&claim).unwrap());

    assert_eq!(
        verify_rotation(victime.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// La clé entrante est couverte par la signature : la substituer permettrait de détourner une
/// rotation légitime vers une clé choisie par l'attaquant.
#[test]
fn substituer_la_cle_entrante_invalide_la_rotation() {
    let ancienne = account();
    let voulue = account().verifying_key().to_bytes();
    let substituee = account().verifying_key().to_bytes();

    let claim = rotation("alice", &voulue, 1_700_000_000);
    let signature = ancienne.sign(&rotation_message(&claim).unwrap());

    assert_eq!(
        verify_rotation(
            ancienne.verifying_key().as_bytes(),
            &rotation("alice", &substituee, 1_700_000_000),
            &signature.to_bytes(),
        ),
        Err(AttestError::BadSignature),
    );
}

/// **Les trois domaines sont étanches deux à deux.** Une signature de révocation qui vaudrait
/// rotation permettrait à quiconque a vu passer une révocation de prendre le compte.
#[test]
fn les_trois_domaines_ne_se_recouvrent_pas() {
    let key = account();
    let cible = [3u8; 32];

    let device = claim("alice", "alice:portable");
    let revoc = revocation("alice", "alice:portable", 1_700_000_000);
    let rot = rotation("alice", &cible, 1_700_000_000);

    let sig_attest = key.sign(&message(&device).unwrap()).to_bytes();
    let sig_revoc = key.sign(&revocation_message(&revoc).unwrap()).to_bytes();
    let sig_rot = key.sign(&rotation_message(&rot).unwrap()).to_bytes();

    let pk = key.verifying_key();
    let pk = pk.as_bytes();

    // Chaque signature ne vaut que dans son propre domaine.
    assert!(verify(pk, &device, &sig_attest).is_ok());
    assert!(verify(pk, &device, &sig_revoc).is_err());
    assert!(verify(pk, &device, &sig_rot).is_err());

    assert!(verify_revocation(pk, &revoc, &sig_revoc).is_ok());
    assert!(verify_revocation(pk, &revoc, &sig_attest).is_err());
    assert!(verify_revocation(pk, &revoc, &sig_rot).is_err());

    assert!(verify_rotation(pk, &rot, &sig_rot).is_ok());
    assert!(verify_rotation(pk, &rot, &sig_attest).is_err());
    assert!(verify_rotation(pk, &rot, &sig_revoc).is_err());
}

use attest::{post_message, signal_message};

/// Le MAC d'un signal éphémère n'est pas rejouable en dépôt d'enveloppe.
///
/// Les signaux n'ont volontairement pas d'anti-rejeu — un indicateur de frappe périmé est sans
/// effet. Cette dispense ne doit pas s'étendre aux enveloppes, qui, elles, sont conservées.
#[test]
fn un_signal_ne_vaut_pas_un_depot() {
    let group_id = b"groupe";
    let nonce = [7u8; 16];
    let digest = [9u8; 32];

    let depot = post_message(group_id, &nonce, &digest).unwrap();
    let signal = signal_message(group_id, &nonce, &digest).unwrap();

    assert_ne!(depot, signal, "même clé, mêmes champs : seul le domaine les sépare");
}
