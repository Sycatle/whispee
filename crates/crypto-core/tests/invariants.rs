//! Invariants d'architecture, vérifiés par la CI.

/// `crypto-core` est le seul chemin de production. `ratchet-lab` est du code pédagogique
/// non audité, écrit pour comprendre le protocole, pas pour protéger qui que ce soit.
///
/// Ce test échoue si quelqu'un ajoute la dépendance — probablement pour réutiliser une
/// fonction « juste pour un test » ou « en attendant ». C'est exactement comme ça que de
/// la crypto maison finit en production.
#[test]
fn crypto_core_ne_depend_jamais_de_ratchet_lab() {
    let manifest = include_str!("../Cargo.toml");

    let fautives: Vec<_> = manifest
        .lines()
        .map(str::trim)
        // Le manifeste mentionne `ratchet-lab` dans le commentaire qui énonce l'invariant.
        .filter(|line| !line.starts_with('#'))
        .filter(|line| line.contains("ratchet-lab") || line.contains("ratchet_lab"))
        .collect();

    assert!(
        fautives.is_empty(),
        "crypto-core ne doit jamais dépendre de ratchet-lab ; lignes fautives : {fautives:?}"
    );
}
