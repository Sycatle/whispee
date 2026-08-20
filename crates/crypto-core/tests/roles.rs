//! La politique d'administration, testée comme une fonction pure.
//!
//! Elle est isolée du protocole précisément pour être testable ainsi : couvrir ces cas en
//! montant de vrais groupes MLS coûterait dix fois plus et en couvrirait moins. Le test
//! d'intégration correspondant vit dans `conversation.rs` et vérifie que la traduction commit
//! → résumé est fidèle ; c'est ici qu'on vérifie la règle elle-même.
//!
//! Rappel de l'enjeu : deux clients qui n'appliquent pas la même règle ne produisent pas une
//! erreur, ils forkent le groupe en silence.

use crypto_core::CryptoError;
use crypto_core::roles::{CommitSummary, Context, Removal, Roster, authorize};

fn roster(admin: &str, moderators: &[&str]) -> Roster {
    Roster::new(admin.to_string(), moderators.iter().map(|m| m.to_string()).collect()).unwrap()
}

fn commit<'a>(committer: &'a str, remaining: Vec<&'a str>) -> CommitSummary<'a> {
    CommitSummary { committer, removals: Vec::new(), adds: 0, changes_roster: false, remaining }
}

fn retrait<'a>(target: &'a str, key: &'a [u8]) -> Removal<'a> {
    Removal { target, target_key: key, self_requested: false }
}

// ------------------------------------------------------------------ groupe plat

/// Un groupe sans roster n'a pas de rôles : c'est la forme d'un 1-to-1, et celle des groupes
/// créés avant l'extension. Y appliquer des règles rendrait toute conversation existante
/// illisible.
#[test]
fn sans_roster_tout_est_autorise() {
    let mut c = commit("nimporte-qui", vec!["alice"]);
    c.adds = 3;
    c.changes_roster = true;
    c.removals.push(retrait("bob", &[1]));

    assert!(authorize(None, &c, &Context::default()).is_ok());
}

// ------------------------------------------------------------------ l'admin

#[test]
fn l_admin_peut_tout_faire() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("alice", vec!["alice", "bob"]);
    c.adds = 1;
    c.changes_roster = true;
    c.removals.push(retrait("carol", &[9]));

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

/// **La règle qui donne son sens à la racine unique.** Si un modérateur pouvait modifier les
/// rôles, il se promouvrait admin et il n'y aurait plus d'autorité — seulement une course.
#[test]
fn un_moderateur_ne_touche_pas_aux_roles() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("bob", vec!["alice", "bob"]);
    c.changes_roster = true;

    assert!(matches!(
        authorize(Some(&r), &c, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

/// Un groupe sans admin est définitivement gelé : plus personne ne peut nommer, révoquer, ni
/// transmettre. Le départ légitime passe par une transmission préalable.
#[test]
fn l_admin_ne_peut_pas_etre_retire() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("alice", vec!["bob"]);
    c.removals.push(retrait("alice", &[1]));

    assert!(matches!(
        authorize(Some(&r), &c, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

/// La règle vaut aussi pour un départ volontaire : la cause du gel importe peu, le résultat
/// est le même.
#[test]
fn l_admin_ne_peut_pas_partir_sans_transmettre() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("bob", vec!["bob"]);
    c.removals.push(Removal { target: "alice", target_key: &[1], self_requested: true });

    assert!(matches!(
        authorize(Some(&r), &c, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

/// **Le piège évité.** Un compte a plusieurs appareils : retirer le téléphone de l'admin ne
/// retire pas l'admin. Raisonner sur les cibles ferait refuser ce commit légitime, et l'admin
/// ne pourrait plus révoquer son propre appareil.
#[test]
fn retirer_un_appareil_de_l_admin_ne_le_retire_pas_du_groupe() {
    let r = roster("alice", &[]);
    let mut c = commit("alice", vec!["alice"]);
    c.removals.push(retrait("alice", &[2]));

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

// ------------------------------------------------------------------ les modérateurs

#[test]
fn un_moderateur_ajoute_et_retire_des_membres_ordinaires() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("bob", vec!["alice", "bob"]);
    c.adds = 1;
    c.removals.push(retrait("carol", &[9]));

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

/// Sinon deux modérateurs se retirent mutuellement et le résultat dépend de qui commite le
/// premier : une course, pas une règle.
#[test]
fn un_moderateur_ne_retire_pas_un_autre_moderateur() {
    let r = roster("alice", &["bob", "carol"]);
    let mut c = commit("bob", vec!["alice", "bob", "carol"]);
    c.removals.push(retrait("carol", &[9]));

    assert!(matches!(
        authorize(Some(&r), &c, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

#[test]
fn l_admin_retire_un_moderateur() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("alice", vec!["alice"]);
    c.removals.push(retrait("bob", &[2]));

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

// ------------------------------------------------------------------ les membres ordinaires

#[test]
fn un_membre_ordinaire_ne_peut_ni_ajouter_ni_retirer() {
    let r = roster("alice", &["bob"]);

    let mut ajout = commit("carol", vec!["alice", "bob", "carol"]);
    ajout.adds = 1;
    assert!(matches!(
        authorize(Some(&r), &ajout, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));

    let mut retirer = commit("carol", vec!["alice", "bob", "carol"]);
    retirer.removals.push(retrait("dave", &[9]));
    assert!(matches!(
        authorize(Some(&r), &retirer, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

// ------------------------------------------------------------------ les deux exceptions

/// Un membre ne peut pas se retirer lui-même dans un commit (RFC 9420) : il propose, un autre
/// commite. Réserver ce commit aux porteurs de rôle rendrait la sortie impossible quand aucun
/// n'est en ligne — un groupe dont on ne peut pas sortir.
#[test]
fn n_importe_qui_peut_commiter_un_depart_volontaire() {
    let r = roster("alice", &[]);
    let mut c = commit("dave", vec!["alice", "dave"]);
    c.removals.push(Removal { target: "carol", target_key: &[9], self_requested: true });

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

/// **L'exception qui compte.** Sans elle, le téléphone volé d'un membre ordinaire reste dans
/// le groupe, à lire, jusqu'au retour en ligne d'un modérateur — soit exactement le délai que
/// la révocation existe pour supprimer.
///
/// Elle n'ouvre rien : le certificat n'est produisible que par le compte propriétaire.
#[test]
fn n_importe_qui_peut_retirer_un_appareil_revoque() {
    let r = roster("alice", &[]);
    let mut c = commit("dave", vec!["alice", "carol", "dave"]);
    c.removals.push(retrait("carol", &[9]));

    let context = Context { revoked: vec![vec![9]] };
    assert!(authorize(Some(&r), &c, &context).is_ok());
}

/// L'exception est indexée sur la clé de l'appareil, pas sur le compte : révoquer un appareil
/// ne rend pas les autres expulsables.
#[test]
fn la_revocation_d_un_appareil_n_expose_pas_les_autres() {
    let r = roster("alice", &[]);
    let mut c = commit("dave", vec!["alice", "carol", "dave"]);
    c.removals.push(retrait("carol", &[8]));

    let context = Context { revoked: vec![vec![9]] };
    assert!(matches!(
        authorize(Some(&r), &c, &context),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

/// L'exception ne contourne pas la protection de l'admin : un appareil révoqué de l'admin
/// s'évince, mais pas l'admin lui-même.
#[test]
fn la_revocation_ne_permet_pas_d_evincer_l_admin() {
    let r = roster("alice", &[]);
    let mut c = commit("dave", vec!["dave"]);
    c.removals.push(retrait("alice", &[9]));

    let context = Context { revoked: vec![vec![9]] };
    assert!(matches!(
        authorize(Some(&r), &c, &context),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

// ------------------------------------------------------------------ sérialisation

#[test]
fn le_roster_survit_a_un_aller_retour() {
    let r = roster("alice", &["bob-le-long-handle", "c"]);
    assert_eq!(Roster::decode(&r.encode().unwrap()).unwrap(), r);
}

#[test]
fn un_roster_sans_moderateur_survit_a_un_aller_retour() {
    let r = roster("alice", &[]);
    assert_eq!(Roster::decode(&r.encode().unwrap()).unwrap(), r);
}

/// L'admin est déjà au-dessus : l'y répéter rendrait `is_moderator` ambigu à la lecture.
#[test]
fn l_admin_n_est_pas_aussi_moderateur() {
    let r = roster("alice", &["alice", "bob"]);
    assert_eq!(r.moderators(), ["bob"]);
    assert!(r.is_admin("alice"));
    assert!(!r.is_moderator("alice"));
}

/// Deux encodages du même roster feraient diverger le hash du group context, donc les clients.
#[test]
fn des_octets_excedentaires_sont_refuses() {
    let mut bytes = roster("alice", &["bob"]).encode().unwrap();
    bytes.push(0);
    assert!(Roster::decode(&bytes).is_err());
}

#[test]
fn un_roster_tronque_est_refuse_sans_paniquer() {
    let bytes = roster("alice", &["bob"]).encode().unwrap();
    for n in 0..bytes.len() {
        assert!(Roster::decode(&bytes[..n]).is_err(), "longueur {n} acceptée");
    }
}

/// Un groupe sans admin ne pourrait plus jamais être administré.
#[test]
fn un_roster_sans_admin_est_refuse() {
    assert!(Roster::new(String::new(), Vec::new()).is_err());
    assert!(Roster::decode(&[0, 0, 0, 0]).is_err());
}
