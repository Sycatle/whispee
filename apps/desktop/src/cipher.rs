//! Les secrets de l'appareil, tenus par le processus natif.
//!
//! # Ce que ce module déplace, et ce qu'il ne déplace pas
//!
//! Il déplace deux choses hors de la webview : la clé qui **chiffre l'état au repos** et la clé
//! qui **signe les requêtes**. Il ne déplace **pas** les clés MLS, qui vivent toujours dans la
//! mémoire linéaire du module WebAssembly — cette limite est écrite dans `lib.rs` et reste
//! entière.
//!
//! La clé de signature comptait autant que l'autre, et c'est moins évident : un état MLS sauvé
//! dont la clé d'authentification a disparu ne sert à rien, puisque l'appareil ne peut plus
//! émettre une seule requête. Le serveur refuse par ailleurs d'en changer — voir la clause sur
//! `auth_key` dans `register_device`. La perdre est donc aussi définitif que perdre l'état.
//!
//! # Ce que « la clé ne quitte pas le Rust » vaut réellement
//!
//! Sur le web, les clés sont des `CryptoKey` non extractables : le navigateur refuse d'en
//! exporter le matériel, y compris à notre propre code. Ici, le processus Rust voit la clé en
//! clair. Ce n'est pas une régression pratique — un script hostile dans la webview pouvait déjà
//! *utiliser* la clé sans l'extraire, et il pourra toujours appeler `sceller`/`signer` — mais
//! c'est une propriété qu'on abandonne, et la taire serait malhonnête.
//!
//! Ce qu'on gagne en échange : la durabilité. Le répertoire privé de l'application n'est purgé
//! qu'à la désinstallation, là où le stockage d'une webview mobile est évincé sans préavis.
//!
//! # Ce que la phase actuelle ne protège pas
//!
//! **La clé est dans un fichier, en clair, lisible par le propriétaire du compte.** Les
//! permissions `0600` empêchent un autre utilisateur du même système de la lire ; elles
//! n'empêchent ni un appareil rooté, ni une sauvegarde du disque, ni un autre processus du même
//! utilisateur.
//!
//! La protection réelle au repos viendra du trousseau du système — Keychain sur iOS, Keystore
//! sur Android — qui demande du code natif par plateforme. Ce n'est **pas** ce qui apporte la
//! durabilité, et c'est pourquoi on peut le livrer après : le répertoire privé suffit à ne plus
//! perdre l'état. Séparer les deux chantiers évite de retarder l'urgent par le difficile.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::store;

/// Version du format du fichier de secrets.
///
/// Présente dès la première version, parce qu'un format sans version ne peut pas évoluer sans
/// deviner : le jour où la clé passe au trousseau, il faudra distinguer un fichier ancien d'un
/// fichier absent.
const VERSION: u8 = 1;

/// Longueur du nonce AES-GCM, en octets.
///
/// Douze, comme côté web : AES-GCM casse catastrophiquement si un nonce est réutilisé sous la
/// même clé, et 96 bits aléatoires rendent la collision négligeable au rythme où un client
/// sauvegarde son état.
const NONCE_LEN: usize = 12;

/// Les deux secrets d'un appareil.
///
/// `ZeroizeOnDrop` efface le matériel à la libération. Contrairement au JavaScript — où un
/// `Uint8Array` mis à zéro peut avoir été recopié par le ramasse-miettes — l'effacement est ici
/// réel, ce qui est l'un des rares gains concrets du passage en natif.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecrets {
    /// Chiffre l'état au repos.
    seal: [u8; 32],
    /// Graine Ed25519. Stockée plutôt que la `SigningKey`, qui n'est pas `Zeroize`.
    signing: [u8; 32],
}

impl DeviceSecrets {
    /// Charge les secrets, ou les crée au premier lancement.
    ///
    /// La distinction entre « fichier absent » et « erreur de lecture » vient de
    /// [`store::Emplacement::lire`], et elle compte ici plus qu'ailleurs : traiter un disque en
    /// panne comme un premier lancement produirait des secrets neufs par-dessus un compte
    /// existant, c'est-à-dire une identité perdue et un état devenu illisible.
    pub fn charger_ou_creer(chemin: &Path) -> std::io::Result<Self> {
        if let Some(contenu) = store::Emplacement::lire(chemin)? {
            return Self::decoder(&contenu);
        }

        let mut secrets = Self { seal: [0u8; 32], signing: [0u8; 32] };
        OsRng.fill_bytes(&mut secrets.seal);
        OsRng.fill_bytes(&mut secrets.signing);

        secrets.ecrire(chemin)?;
        Ok(secrets)
    }

    fn decoder(contenu: &[u8]) -> std::io::Result<Self> {
        let invalide = |raison: &str| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, raison.to_owned())
        };

        if contenu.len() != 1 + 32 + 32 {
            return Err(invalide("fichier de secrets de taille inattendue"));
        }
        if contenu[0] != VERSION {
            return Err(invalide("version de fichier de secrets inconnue"));
        }

        let mut secrets = Self { seal: [0u8; 32], signing: [0u8; 32] };
        secrets.seal.copy_from_slice(&contenu[1..33]);
        secrets.signing.copy_from_slice(&contenu[33..65]);
        Ok(secrets)
    }

    fn ecrire(&self, chemin: &Path) -> std::io::Result<()> {
        let mut contenu = Vec::with_capacity(65);
        contenu.push(VERSION);
        contenu.extend_from_slice(&self.seal);
        contenu.extend_from_slice(&self.signing);

        store::ecrire_atomiquement(chemin, &contenu)?;
        contenu.zeroize();

        // Avant tout autre utilisateur du système, et avant que le fichier ne contienne quoi que
        // ce soit d'utile. Poser les permissions après l'écriture laisserait une fenêtre où le
        // fichier est lisible par tous — courte, mais réelle, et évitable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Clé publique de signature — la seule moitié qui quitte l'appareil.
    pub fn cle_publique(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.signing).verifying_key().to_bytes()
    }

    /// Signe un message de requête.
    pub fn signer(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.signing).sign(message).to_bytes()
    }

    /// Chiffre pour la persistance locale. Rend `nonce || chiffré`.
    pub fn sceller(&self, clair: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let chiffre = Aes256Gcm::new(&self.seal.into())
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: clair, aad: &[] })?;

        let mut sortie = Vec::with_capacity(NONCE_LEN + chiffre.len());
        sortie.extend_from_slice(&nonce);
        sortie.extend_from_slice(&chiffre);
        Ok(sortie)
    }

    /// Déchiffre ce que [`Self::sceller`] a produit.
    pub fn ouvrir(&self, blob: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        if blob.len() <= NONCE_LEN {
            return Err(aes_gcm::Error);
        }

        Aes256Gcm::new(&self.seal.into()).decrypt(
            Nonce::from_slice(&blob[..NONCE_LEN]),
            Payload { msg: &blob[NONCE_LEN..], aad: &[] },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chemin_temporaire(nom: &str) -> std::path::PathBuf {
        let chemin = std::env::temp_dir().join(format!("wac-cipher-{nom}"));
        let _ = std::fs::remove_dir_all(&chemin);
        chemin.join("secrets.bin")
    }

    #[test]
    fn un_scelle_se_rouvre() {
        let secrets = DeviceSecrets::charger_ou_creer(&chemin_temporaire("rouvrir")).unwrap();

        let blob = secrets.sceller(b"un etat mls").unwrap();
        assert_eq!(secrets.ouvrir(&blob).unwrap(), b"un etat mls");
    }

    /// Le clair ne doit pas transparaître dans le scellé.
    ///
    /// Trivial en apparence, et c'est exactement le genre d'invariant qu'un jour quelqu'un casse
    /// en « optimisant » l'encodage.
    #[test]
    fn le_scelle_ne_contient_pas_le_clair() {
        let secrets = DeviceSecrets::charger_ou_creer(&chemin_temporaire("opaque")).unwrap();
        let clair = b"phrase reconnaissable";

        let blob = secrets.sceller(clair).unwrap();

        assert!(!blob.windows(clair.len()).any(|f| f == clair));
    }

    /// **Le test qui justifie le nonce aléatoire.**
    ///
    /// Deux scellés du même clair doivent différer. Un nonce fixe — ou un compteur remis à zéro
    /// au redémarrage — casserait AES-GCM catastrophiquement, et le symptôme serait invisible :
    /// tout continuerait de fonctionner.
    #[test]
    fn deux_scelles_du_meme_clair_different() {
        let secrets = DeviceSecrets::charger_ou_creer(&chemin_temporaire("nonce")).unwrap();

        assert_ne!(secrets.sceller(b"identique").unwrap(), secrets.sceller(b"identique").unwrap());
    }

    /// Un octet modifié doit faire échouer l'ouverture, pas rendre un clair douteux.
    #[test]
    fn un_scelle_altere_est_refuse() {
        let secrets = DeviceSecrets::charger_ou_creer(&chemin_temporaire("altere")).unwrap();

        let mut blob = secrets.sceller(b"un etat mls").unwrap();
        let dernier = blob.len() - 1;
        blob[dernier] ^= 0x01;

        assert!(secrets.ouvrir(&blob).is_err());
    }

    /// **Le test qui compte pour la durabilité.**
    ///
    /// Les secrets doivent survivre au redémarrage : c'est toute la raison d'être du fichier. Un
    /// second chargement qui produirait de nouvelles clés rendrait l'état illisible et l'appareil
    /// muet, sans aucun message d'erreur.
    #[test]
    fn les_secrets_survivent_a_un_rechargement() {
        let chemin = chemin_temporaire("persistance");

        let premier = DeviceSecrets::charger_ou_creer(&chemin).unwrap();
        let blob = premier.sceller(b"etat").unwrap();
        let publique = premier.cle_publique();
        drop(premier);

        let second = DeviceSecrets::charger_ou_creer(&chemin).unwrap();

        assert_eq!(second.cle_publique(), publique, "la clé de signature a changé");
        assert_eq!(second.ouvrir(&blob).unwrap(), b"etat", "l'état n'est plus déchiffrable");
    }

    /// Une signature vérifie sous la clé publique annoncée.
    #[test]
    fn une_signature_verifie_sous_la_cle_publique() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let secrets = DeviceSecrets::charger_ou_creer(&chemin_temporaire("signature")).unwrap();
        let message = b"POST\n/v1/envelopes\n";

        let signature = secrets.signer(message);
        let publique = VerifyingKey::from_bytes(&secrets.cle_publique()).unwrap();

        assert!(publique.verify(message, &Signature::from_bytes(&signature)).is_ok());
    }

    /// Un fichier tronqué est refusé plutôt que réinterprété.
    ///
    /// Sans cette garde, un fichier corrompu donnerait des clés silencieusement fausses — donc un
    /// état indéchiffrable présenté comme un mot de passe erroné.
    #[test]
    fn un_fichier_tronque_est_refuse() {
        assert!(DeviceSecrets::decoder(&[VERSION, 0, 0]).is_err());
    }

    /// Une version inconnue est refusée plutôt que lue de travers.
    #[test]
    fn une_version_inconnue_est_refusee() {
        let mut contenu = vec![VERSION + 1];
        contenu.extend_from_slice(&[0u8; 64]);

        assert!(DeviceSecrets::decoder(&contenu).is_err());
    }
}
