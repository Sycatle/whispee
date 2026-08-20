//! Persistance de la session, côté natif.
//!
//! # Pourquoi ce module existe
//!
//! Le client range son état MLS dans IndexedDB. Sur mobile, ce stockage **n'est pas garanti** :
//! iOS évince les données de WKWebView après sept jours d'inactivité, Android purge sous pression
//! mémoire. Et la perte est définitive — le ratchet MLS détruit ses clés au fur et à mesure, donc
//! l'historique devient illisible et les conversations sont à recréer.
//!
//! Le répertoire privé de l'application, lui, n'est purgé qu'à la désinstallation.
//!
//! # L'écriture atomique n'est pas un détail d'implémentation
//!
//! C'est **l'exigence centrale**, et le seul risque que ce module introduit qui n'existait pas
//! avec IndexedDB. Une transaction IndexedDB interrompue laisse la base intacte ; un
//! `File::write` interrompu laisse un fichier tronqué, c'est-à-dire un état MLS illisible,
//! c'est-à-dire exactement la perte définitive qu'on cherche à éviter.
//!
//! D'où `écrire dans un temporaire → fsync → renommer → fsync du répertoire`. Le renommage est
//! atomique sur POSIX comme sur NTFS : à tout instant, le fichier final est soit l'ancien
//! contenu, soit le nouveau, jamais un mélange. Les deux `fsync` comptent autant que le
//! renommage — sans eux, le contenu peut n'atteindre le disque qu'après le renommage, et une
//! coupure de courant laisse un fichier renommé mais vide.
//!
//! # Pas de génération précédente, délibérément
//!
//! Garder une copie N-1 pour « pouvoir revenir » est tentant et **faux**. Le client le documente
//! déjà à propos de sa propre sauvegarde : un état MLS restauré en retard fait reculer les
//! epochs et rejoue des clés déjà utilisées. Un état périmé restauré silencieusement est une
//! faute cryptographique, pas un filet de sécurité. Le renommage atomique est la seule protection
//! acceptable.
//!
//! # Deux fichiers, pas un
//!
//! `state.bin` porte le blob chiffré — gros, réécrit à chaque tour. `meta.json` porte les
//! curseurs, les empreintes vérifiées et les réglages — petit, et dont **rien n'est secret**.
//! Les séparer évite de réécrire des dizaines de kilooctets pour changer un booléen, et rend le
//! second inspectable en cas d'incident sans rien exposer.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Écrit un fichier de telle sorte qu'un lecteur ne voie jamais d'état intermédiaire.
///
/// Le temporaire est créé dans le **même répertoire** que la cible : `rename` n'est atomique
/// qu'à l'intérieur d'un système de fichiers, et un temporaire placé dans `/tmp` traverserait
/// souvent une frontière de montage — le renommage deviendrait alors une copie, qui peut
/// s'interrompre.
pub fn ecrire_atomiquement(cible: &Path, contenu: &[u8]) -> std::io::Result<()> {
    let repertoire = cible.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "chemin sans répertoire parent")
    })?;

    fs::create_dir_all(repertoire)?;

    let temporaire = cible.with_extension("tmp");

    {
        let mut fichier = fs::File::create(&temporaire)?;
        fichier.write_all(contenu)?;
        // Le contenu doit être sur le disque **avant** que le renommage ne le rende visible.
        // Sans ce `sync_all`, une coupure entre les deux laisse un fichier renommé et vide.
        fichier.sync_all()?;
    }

    fs::rename(&temporaire, cible)?;

    // Le renommage lui-même est une écriture de répertoire, et elle aussi peut rester en cache.
    // Sur Windows, ouvrir un répertoire échoue ; l'omission y est sans conséquence, `rename`
    // étant déjà transactionnel sur NTFS.
    #[cfg(unix)]
    if let Ok(handle) = fs::File::open(repertoire) {
        let _ = handle.sync_all();
    }

    Ok(())
}

/// Emplacement des fichiers de session.
pub struct Emplacement {
    racine: PathBuf,
}

impl Emplacement {
    pub fn new(racine: PathBuf) -> Self {
        Self { racine }
    }

    pub fn etat(&self) -> PathBuf {
        self.racine.join("state.bin")
    }

    pub fn meta(&self) -> PathBuf {
        self.racine.join("meta.json")
    }

    /// Lit un fichier, ou `None` s'il n'existe pas.
    ///
    /// L'absence n'est pas une erreur : c'est l'état d'une installation neuve, et le distinguer
    /// d'une erreur de lecture est ce qui permet à l'appelant de choisir entre « créer une
    /// session » et « alerter ». Les confondre ferait passer un disque en panne pour un premier
    /// lancement, et effacerait un compte au lieu de le signaler.
    pub fn lire(chemin: &Path) -> std::io::Result<Option<Vec<u8>>> {
        match fs::read(chemin) {
            Ok(contenu) => Ok(Some(contenu)),
            Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(erreur) => Err(erreur),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repertoire_temporaire(nom: &str) -> PathBuf {
        let chemin = std::env::temp_dir().join(format!("wac-store-test-{nom}"));
        let _ = fs::remove_dir_all(&chemin);
        chemin
    }

    #[test]
    fn une_ecriture_est_relisible() {
        let racine = repertoire_temporaire("relire");
        let emplacement = Emplacement::new(racine.clone());

        ecrire_atomiquement(&emplacement.etat(), b"un etat chiffre").unwrap();

        assert_eq!(
            Emplacement::lire(&emplacement.etat()).unwrap().as_deref(),
            Some(b"un etat chiffre".as_slice()),
        );

        fs::remove_dir_all(&racine).unwrap();
    }

    /// **Le test qui porte la propriété du module.**
    ///
    /// Une seconde écriture ne doit jamais laisser un mélange des deux contenus. C'est ce que le
    /// renommage garantit, et c'est ce qu'un `File::create` suivi d'un `write_all` ne garantit
    /// pas — il tronque d'abord, puis écrit.
    #[test]
    fn une_reecriture_plus_courte_ne_laisse_aucun_residu() {
        let racine = repertoire_temporaire("residu");
        let emplacement = Emplacement::new(racine.clone());

        ecrire_atomiquement(&emplacement.etat(), b"un contenu tres long a remplacer").unwrap();
        ecrire_atomiquement(&emplacement.etat(), b"court").unwrap();

        assert_eq!(
            Emplacement::lire(&emplacement.etat()).unwrap().as_deref(),
            Some(b"court".as_slice()),
            "la queue de l'ancien contenu a survécu",
        );

        fs::remove_dir_all(&racine).unwrap();
    }

    /// Un fichier absent n'est pas une erreur : c'est une installation neuve.
    ///
    /// Les confondre ferait passer un disque en panne pour un premier lancement, et créerait un
    /// compte par-dessus un état encore présent.
    #[test]
    fn un_fichier_absent_se_distingue_d_une_erreur() {
        let emplacement = Emplacement::new(repertoire_temporaire("absent"));

        assert!(Emplacement::lire(&emplacement.etat()).unwrap().is_none());
    }

    /// Le répertoire est créé au besoin : au premier lancement, il n'existe pas.
    #[test]
    fn le_repertoire_est_cree_au_besoin() {
        let racine = repertoire_temporaire("cree").join("un").join("deux");
        let emplacement = Emplacement::new(racine.clone());

        ecrire_atomiquement(&emplacement.meta(), b"{}").unwrap();

        assert!(emplacement.meta().exists());
        fs::remove_dir_all(racine.parent().unwrap().parent().unwrap()).unwrap();
    }

    /// Aucun temporaire ne doit survivre à une écriture réussie.
    ///
    /// Un `.tmp` oublié n'est pas dangereux en soi, mais il contient l'état **en clair du point
    /// de vue du renommage** — c'est-à-dire une copie de plus du blob, que rien ne nettoie.
    #[test]
    fn le_temporaire_ne_survit_pas() {
        let racine = repertoire_temporaire("temporaire");
        let emplacement = Emplacement::new(racine.clone());

        ecrire_atomiquement(&emplacement.etat(), b"contenu").unwrap();

        assert!(!emplacement.etat().with_extension("tmp").exists());
        fs::remove_dir_all(&racine).unwrap();
    }
}
