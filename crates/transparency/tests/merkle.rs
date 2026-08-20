//! Le journal ne vaut que par ses preuves : une preuve acceptée à tort donne au serveur
//! exactement le pouvoir qu'on cherche à lui retirer. Ces tests balaient exhaustivement les
//! petites tailles, là où les erreurs de découpage se cachent.

use transparency::*;

fn feuilles(n: usize) -> Vec<Hash> {
    (0..n).map(|i| leaf_hash(&entry(&format!("compte{i}"), &[i as u8; 32]))).collect()
}

/// Une racine sur une seule feuille est la feuille elle-même : sans cela, un arbre à une
/// feuille et un arbre à deux feuilles identiques seraient confondus.
#[test]
fn une_feuille_est_sa_propre_racine() {
    let f = feuilles(1);
    assert_eq!(root(&f), f[0]);
}

/// **Exhaustif.** Toute feuille de tout arbre jusqu'à 33 doit produire une preuve qui
/// reconstruit la racine.
#[test]
fn toute_inclusion_se_verifie() {
    for n in 1..=33 {
        let f = feuilles(n);
        let r = root(&f);
        for i in 0..n {
            let proof = inclusion_proof(&f, i).unwrap();
            assert_eq!(
                verify_inclusion(&f[i], i, n, &proof, &r),
                Ok(()),
                "arbre de {n} feuilles, indice {i}",
            );
        }
    }
}

/// **Exhaustif.** Tout arbre prolonge tout arbre plus petit.
#[test]
fn toute_coherence_se_verifie() {
    for to in 1..=33 {
        let f = feuilles(to);
        let new_root = root(&f);
        for from in 1..=to {
            let old_root = root(&f[..from]);
            let proof = consistency_proof(&f, from).unwrap();
            assert_eq!(
                verify_consistency(from, &old_root, to, &new_root, &proof),
                Ok(()),
                "cohérence de {from} vers {to}",
            );
        }
    }
}

/// **Le test qui compte.** Un journal qui réécrit une entrée déjà publiée ne doit pas pouvoir
/// produire de preuve de cohérence — c'est toute la différence entre un journal auditable et
/// une base de données.
#[test]
fn un_journal_reecrit_ne_passe_pas_la_coherence() {
    let ancien = feuilles(5);
    let old_root = root(&ancien);

    // Le serveur remplace la troisième entrée, puis ajoute des feuilles par-dessus.
    let mut reecrit = ancien.clone();
    reecrit[2] = leaf_hash(&entry("compte2", &[0xFFu8; 32]));
    reecrit.extend(feuilles(8).into_iter().skip(5));

    let new_root = root(&reecrit);
    let proof = consistency_proof(&reecrit, 5).unwrap();

    assert_eq!(
        verify_consistency(5, &old_root, reecrit.len(), &new_root, &proof),
        Err(LogError::BadProof),
        "une réécriture a produit une preuve de cohérence valide : le journal ne prouve rien",
    );
}

/// Une preuve d'inclusion pour une feuille qui n'est pas là ne doit pas passer. C'est la
/// substitution de clé au premier contact, exactement.
#[test]
fn une_feuille_etrangere_ne_passe_pas() {
    let f = feuilles(7);
    let r = root(&f);
    let proof = inclusion_proof(&f, 3).unwrap();

    let intruse = leaf_hash(&entry("compte3", &[0xAAu8; 32]));
    assert_eq!(
        verify_inclusion(&intruse, 3, 7, &proof, &r),
        Err(LogError::BadProof),
    );
}

/// Déplacer une preuve valide vers un autre indice ne doit pas la rendre valide ailleurs.
#[test]
fn une_preuve_ne_vaut_que_pour_son_indice() {
    let f = feuilles(7);
    let r = root(&f);
    let proof = inclusion_proof(&f, 3).unwrap();

    for autre in 0..7 {
        if autre == 3 {
            continue;
        }
        assert!(
            verify_inclusion(&f[3], autre, 7, &proof, &r).is_err(),
            "la preuve de l'indice 3 a été acceptée à l'indice {autre}",
        );
    }
}

/// Une preuve rallongée est refusée plutôt qu'ignorée : le surplus serait choisi par
/// l'attaquant.
#[test]
fn une_preuve_trop_longue_est_refusee() {
    let f = feuilles(4);
    let r = root(&f);
    let mut proof = inclusion_proof(&f, 1).unwrap();
    proof.push([0u8; 32]);

    assert_eq!(verify_inclusion(&f[1], 1, 4, &proof, &r), Err(LogError::BadProof));
}

#[test]
fn une_preuve_tronquee_est_refusee() {
    let f = feuilles(8);
    let r = root(&f);
    let mut proof = inclusion_proof(&f, 5).unwrap();
    proof.pop();

    assert_eq!(verify_inclusion(&f[5], 5, 8, &proof, &r), Err(LogError::BadProof));
}

/// **La séparation feuille/nœud de la RFC 6962.** Sans elle, le hash d'un nœud interne serait
/// présentable comme celui d'une feuille, et un attaquant fabriquerait une preuve d'inclusion
/// pour une entrée de son choix.
#[test]
fn un_noeud_interne_ne_peut_pas_se_faire_passer_pour_une_feuille() {
    let f = feuilles(2);
    let interne = node_hash(&f[0], &f[1]);

    // Le nœud interne existe dans l'arbre, mais comme nœud — pas comme feuille. Le contenu
    // qui produirait cette feuille n'est pas calculable, et c'est bien l'objectif.
    assert_ne!(leaf_hash(&[]), interne);
    assert_ne!(root(&f), leaf_hash(&node_bytes(&f[0], &f[1])));
}

fn node_bytes(left: &Hash, right: &Hash) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(left);
    out.extend_from_slice(right);
    out
}

/// Le préfixage de longueur, même raison que dans `attest` : sans lui, deux entrées distinctes
/// produiraient la même feuille.
#[test]
fn deux_decoupages_differents_ne_collisionnent_pas() {
    assert_ne!(entry("ab", b"c"), entry("a", b"bc"));
}

#[test]
fn un_intervalle_invalide_est_refuse() {
    let f = feuilles(4);
    assert_eq!(consistency_proof(&f, 0), Err(LogError::BadRange));
    assert_eq!(consistency_proof(&f, 5), Err(LogError::BadRange));
    assert_eq!(inclusion_proof(&f, 4), Err(LogError::OutOfRange));
}

// ------------------------------------------------------------------ têtes signées

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

#[test]
fn une_tete_signee_par_le_journal_est_acceptee() {
    let key = SigningKey::generate(&mut OsRng);
    let head = TreeHead { size: 12, root: [7u8; 32], timestamp: 1_700_000_000 };
    let sig = head.sign(&key);

    assert_eq!(head.verify(key.verifying_key().as_bytes(), &sig), Ok(()));
}

/// Chaque champ est couvert : altérer la taille ou la racine doit invalider la signature.
#[test]
fn tous_les_champs_de_la_tete_sont_couverts() {
    let key = SigningKey::generate(&mut OsRng);
    let head = TreeHead { size: 12, root: [7u8; 32], timestamp: 1_700_000_000 };
    let sig = head.sign(&key);
    let pk = key.verifying_key();
    let pk = pk.as_bytes();

    for altere in [
        TreeHead { size: 13, ..head },
        TreeHead { root: [8u8; 32], ..head },
        TreeHead { timestamp: 1_600_000_000, ..head },
    ] {
        assert_eq!(altere.verify(pk, &sig), Err(LogError::BadSignature));
    }
}

/// Un tiers ne peut pas fabriquer de tête : sinon n'importe qui publierait un faux journal.
#[test]
fn un_tiers_ne_peut_pas_signer_une_tete() {
    let journal = SigningKey::generate(&mut OsRng);
    let intrus = SigningKey::generate(&mut OsRng);
    let head = TreeHead { size: 12, root: [7u8; 32], timestamp: 1_700_000_000 };

    assert_eq!(
        head.verify(journal.verifying_key().as_bytes(), &head.sign(&intrus)),
        Err(LogError::BadSignature),
    );
}
