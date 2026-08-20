//! Compte pseudonyme, et son unique secret racine.
//!
//! Un compte est une clé Ed25519 — l'*account identity key*, AIK — et un pseudonyme. C'est
//! l'AIK qui signe les attestations d'appareil (voir la crate [`attest`]), donc elle qui
//! décide quels appareils peuvent lire les conversations du compte.
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne stocke rien. Le secret vit en mémoire le temps d'une session et c'est à l'appelant
//! de décider où il le range — trousseau système, IndexedDB chiffré, ou nulle part.
//!
//! Il ne connaît pas non plus les appareils du compte : la liste vient du serveur et se
//! revérifie à chaque lecture. Un compte n'est pas un annuaire, c'est une clé de signature.

use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};

/// Nombre de mots de la phrase de récupération.
///
/// Douze mots valent 128 bits d'entropie. Vingt-quatre en vaudraient 256, ce qui ne protège
/// contre rien de plus : 128 bits sont déjà hors d'atteinte, et la seule différence mesurable
/// serait le nombre d'utilisateurs qui recopient la phrase de travers.
pub const PHRASE_WORDS: usize = 12;

/// Entropie correspondante, en octets.
const ENTROPY_BYTES: usize = 16;

/// Étiquettes de dérivation.
///
/// Deux clés issues de la même graine doivent être indépendantes : connaître la clé du coffre
/// ne doit rien apprendre sur la clé d'identité. C'est ce que garantit HKDF **à condition**
/// que les `info` diffèrent — d'où ces constantes, plutôt que des littéraux dispersés.
const INFO_IDENTITY: &[u8] = b"wac-account-identity-v1";
const INFO_VAULT: &[u8] = b"wac-vault-v1";

/// Clé racine d'un compte.
///
/// `Zeroize` est manuel plutôt que dérivé : `SigningKey` ne l'implémente pas, et le laisser
/// traîner dans la pile après un `drop` irait à l'encontre de tout le reste.
pub struct Account {
    signing: SigningKey,
    seed: [u8; 64],
}

impl Drop for Account {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Volontairement redigé. Dériver `Debug` recopierait la clé privée dans le premier
/// `println!` de débogage venu, et de là dans les journaux.
impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account").field("identity_key", &self.fingerprint()).finish_non_exhaustive()
    }
}

impl Account {
    /// Crée un compte et retourne la phrase de récupération qui le reconstruit.
    ///
    /// **C'est le seul moment où la phrase existe.** Elle n'est pas conservée : la redemander
    /// plus tard est impossible par construction, ce qui est le comportement voulu — une
    /// phrase qu'on peut réafficher est une phrase qu'un attaquant ayant l'appareil déverrouillé
    /// peut réafficher aussi.
    pub fn generate() -> Result<(Self, String)> {
        let mut entropy = [0u8; ENTROPY_BYTES];
        rand_core::OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| CryptoError::Malformed(leak(e)))?;
        entropy.zeroize();

        let phrase = mnemonic.to_string();
        Ok((Self::from_mnemonic(&mnemonic), phrase))
    }

    /// Reconstruit un compte depuis sa phrase de récupération.
    ///
    /// La phrase porte sa propre somme de contrôle : un mot mal recopié est refusé ici plutôt
    /// que de produire silencieusement un compte différent et vide.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase.trim())
            .map_err(|_| CryptoError::Malformed("phrase de récupération invalide"))?;

        if mnemonic.word_count() != PHRASE_WORDS {
            return Err(CryptoError::Malformed("phrase de récupération de longueur inattendue"));
        }

        Ok(Self::from_mnemonic(&mnemonic))
    }

    fn from_mnemonic(mnemonic: &Mnemonic) -> Self {
        // `to_seed` applique PBKDF2-HMAC-SHA512, 2048 itérations. Ce n'est pas un durcissement
        // utile ici — la graine a déjà 128 bits, il n'y a rien à brute-forcer — mais c'est le
        // format standard, et s'en écarter n'apporterait rien qu'une incompatibilité.
        let seed = mnemonic.to_seed_normalized("");

        let mut identity = [0u8; 32];
        Hkdf::<Sha256>::new(None, &seed)
            .expand(INFO_IDENTITY, &mut identity)
            .expect("32 octets est une longueur valide pour HKDF-SHA256");

        let signing = SigningKey::from_bytes(&identity);
        identity.zeroize();

        Self { signing, seed }
    }

    /// Clé publique du compte : ce que les autres vérifient, et ce que le serveur publie.
    pub fn identity_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Empreinte à comparer hors bande avec son correspondant.
    pub fn fingerprint(&self) -> String {
        attest::fingerprint(&self.identity_key())
    }

    /// Signe l'appartenance d'un appareil à ce compte.
    ///
    /// Le résultat est ce qui empêche le serveur d'inventer un appareil : il ne détient pas
    /// l'AIK et ne peut donc pas produire cette signature.
    pub fn attest(
        &self,
        handle: &str,
        device_id: &str,
        auth_key: &[u8],
        mls_key: &[u8],
    ) -> Result<[u8; 64]> {
        let claim = attest::DeviceClaim { handle, device_id, auth_key, mls_key };
        let message = attest::message(&claim).map_err(|_| CryptoError::Malformed("champ trop long"))?;
        Ok(self.signing.sign(&message).to_bytes())
    }

    /// Signe la révocation d'un appareil de ce compte.
    ///
    /// Jumeau d'[`Account::attest`], et son contraire exact : l'attestation fait entrer un
    /// appareil, le certificat de révocation le fait sortir. Les deux sont vérifiables par
    /// n'importe qui détenant la clé publique du compte, ce qui est la condition pour qu'un
    /// **autre** membre d'un groupe puisse commiter le retrait sans croire le serveur sur
    /// parole.
    ///
    /// `revoked_at` est en secondes Unix et entre dans le message signé. L'appelant doit y
    /// mettre l'heure courante : elle sert au serveur à rejeter les certificats fabriqués à
    /// l'avance, et aux autres clients à ordonner les révocations successives d'un même
    /// appareil.
    pub fn revoke(&self, handle: &str, device_id: &str, revoked_at: u64) -> Result<[u8; 64]> {
        let claim = attest::RevocationClaim { handle, device_id, revoked_at };
        let message =
            attest::revocation_message(&claim).map_err(|_| CryptoError::Malformed("champ trop long"))?;
        Ok(self.signing.sign(&message).to_bytes())
    }

    /// Signe le passage de ce compte à une nouvelle clé d'identité.
    ///
    /// À appeler sur l'**ancien** compte : c'est lui qui désigne son successeur. Voir
    /// [`attest::RotationClaim`] pour ce que cette signature prouve, et surtout ce qu'elle ne
    /// prouve pas.
    pub fn rotate(
        &self,
        handle: &str,
        new_identity_key: &[u8],
        rotated_at: u64,
    ) -> Result<[u8; 64]> {
        let claim = attest::RotationClaim { handle, new_identity_key, rotated_at };
        let message =
            attest::rotation_message(&claim).map_err(|_| CryptoError::Malformed("champ trop long"))?;
        Ok(self.signing.sign(&message).to_bytes())
    }

    /// Clé symétrique du coffre de sauvegarde.
    ///
    /// Dérivée à la demande et jamais persistée : tant que l'utilisateur n'active pas le
    /// coffre, cette clé n'existe nulle part. Sa seule existence changerait le modèle de
    /// menace — un coffre chiffré par une clé long-terme n'est plus protégé par la forward
    /// secrecy, et la fuite de la phrase devient rétroactivement totale.
    pub fn vault_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, &self.seed)
            .expand(INFO_VAULT, &mut key)
            .expect("32 octets est une longueur valide pour HKDF-SHA256");
        key
    }

    /// Exporte la graine, pour la transmettre à un appareil qu'on appaire.
    ///
    /// **Ces octets valent le compte entier.** Ils ne doivent traverser qu'un canal déjà
    /// chiffré et authentifié — en pratique le blob d'appairage scellé sous le secret X25519
    /// partagé par le QR code, jamais le serveur en clair, jamais un journal.
    ///
    /// C'est la graine et non la phrase qui circule : l'appareil appairé obtient exactement le
    /// même pouvoir, sans qu'un secret lisible par un humain — donc photographiable — soit
    /// reconstitué une seconde fois.
    pub fn export_seed(&self) -> [u8; 64] {
        self.seed
    }

    /// Reconstruit un compte depuis une graine reçue lors d'un appairage.
    pub fn from_seed(seed: [u8; 64]) -> Self {
        let mut identity = [0u8; 32];
        Hkdf::<Sha256>::new(None, &seed)
            .expand(INFO_IDENTITY, &mut identity)
            .expect("32 octets est une longueur valide pour HKDF-SHA256");

        let signing = SigningKey::from_bytes(&identity);
        identity.zeroize();

        Self { signing, seed }
    }
}

/// `bip39::Error` n'est pas `'static` sous forme de `&str` ; on ne conserve que la catégorie.
fn leak(_: bip39::Error) -> &'static str {
    "entropie invalide pour une phrase de récupération"
}
