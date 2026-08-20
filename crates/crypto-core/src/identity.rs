//! Identité d'un appareil et matériel publié sur le serveur.
//!
//! En MLS, l'unité d'appartenance à un groupe est l'**appareil**, pas l'utilisateur. Un
//! utilisateur avec trois appareils est trois membres. C'est ce qui rend le multi-device
//! natif, là où la stack Signal exige une couche dédiée (Sesame).

use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};

use crate::error::{CryptoError, Result, mls};
use crate::provider::Provider;

/// Ciphersuite du projet : la seule que le RFC 9420 rend obligatoire, donc celle sur
/// laquelle toutes les implémentations interopèrent.
///
/// ChaCha20-Poly1305 serait préférable en WASM, où l'absence d'AES-NI rend AES à la fois
/// plus lent et plus difficile à garder constant-time. L'interopérabilité l'emporte ici,
/// mais le choix mérite d'être réexaminé si le web devient la plateforme principale.
/// Capacités déclarées par chaque feuille de l'arbre.
///
/// Elles doivent couvrir `ROSTER_EXTENSION`, faute de quoi MLS refuse toute feuille dans un
/// groupe administré. Deux endroits les consomment et doivent rester d'accord : les
/// KeyPackages, pour les membres qu'on ajoute, et la config de création, pour le créateur —
/// qui n'a pas de KeyPackage. D'où cette fonction plutôt que deux littéraux.
///
/// Les KeyPackages publiés avant cette version ne la portent pas et doivent être republiés.
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::Unknown(crate::roles::ROSTER_EXTENSION)]),
        None,
        None,
    )
}

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub struct Identity {
    pub(crate) provider: Provider,
    pub(crate) credential: CredentialWithKey,
    pub(crate) signer: SignatureKeyPair,
    /// Conservé explicitement : il faut le nom pour reconstruire le credential à la
    /// restauration, et l'extraire du credential demanderait de le désassembler.
    name: String,
}

impl Identity {
    /// Crée une identité d'appareil.
    ///
    /// `name` est un identifiant applicatif opaque (id d'appareil, id d'utilisateur). Il est
    /// transporté en clair dans le credential et visible de tous les membres du groupe **et**
    /// du serveur : n'y mettez rien que vous ne souhaitiez pas divulguer.
    pub fn create(name: &str) -> Result<Self> {
        let provider = Provider::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
        signer.store(provider.storage()).map_err(mls)?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };

        Ok(Self { provider, credential, signer, name: name.to_owned() })
    }

    /// Produit un KeyPackage à publier sur le serveur, sérialisé au format TLS.
    ///
    /// C'est l'équivalent MLS du prekey bundle de X3DH : il permet à quelqu'un de nous
    /// ajouter à un groupe alors que nous sommes hors ligne. **Chaque KeyPackage est à usage
    /// unique** — sa clé d'initialisation est consommée à l'ajout. Le serveur doit en tenir
    /// un stock par appareil et signaler l'épuisement, faute de quoi personne ne peut plus
    /// nous joindre.
    pub fn publish_key_package(&self) -> Result<Vec<u8>> {
        // La capacité `ROSTER_EXTENSION` doit être déclarée ici, dans la feuille, et pas
        // seulement posée dans le group context : MLS refuse d'ajouter un membre qui ne
        // déclare pas supporter les extensions requises par le groupe. Sans cette ligne, un
        // appareil ne pourrait rejoindre aucun groupe administré — et l'erreur ne se
        // manifesterait qu'à l'ajout, loin d'ici.
        //
        // Les KeyPackages publiés avant cette version ne la portent pas : ils doivent être
        // republiés.
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(mls)?;

        MlsMessageOut::from(bundle.key_package().clone())
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Empreinte de la clé de signature, à afficher pour vérification hors bande.
    ///
    /// Voir [`crate::conversation::Conversation::verify_peer`] pour ce que cette empreinte
    /// protège réellement — et ce qu'elle ne protège pas.
    pub fn fingerprint(&self) -> String {
        fingerprint(self.signer.public())
    }

    pub fn signature_key(&self) -> &[u8] {
        self.signer.public()
    }

    /// Sérialise tout ce qu'il faut pour reconstruire cette identité : le nom, la clé
    /// publique de signature, et l'état du provider.
    ///
    /// Le nom et la clé publique sont indispensables et ne se déduisent pas du blob de
    /// stockage seul : `SignatureKeyPair::read` a besoin de la clé publique pour retrouver
    /// la privée, et le credential a besoin du nom.
    ///
    /// **Ce blob contient les clés privées en clair.** Voir [`Provider::export_state`].
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let name = self.name.as_bytes();
        let public_key = self.signer.public();
        let storage = self.provider.export_state()?;

        let mut out = Vec::with_capacity(name.len() + public_key.len() + storage.len() + 24);
        out.extend_from_slice(&(name.len() as u64).to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(public_key.len() as u64).to_be_bytes());
        out.extend_from_slice(public_key);
        out.extend_from_slice(&(storage.len() as u64).to_be_bytes());
        out.extend_from_slice(&storage);
        Ok(out)
    }

    /// Reconstruit une identité depuis [`Identity::export_state`].
    ///
    /// Ne restaurez **jamais** un état plus ancien que le dernier exporté : les groupes
    /// reculeraient d'epoch et rejoueraient des clés déjà utilisées, ce qui détruit la
    /// forward secrecy. Un état MLS n'est pas une sauvegarde ordinaire — il ne doit exister
    /// qu'une seule copie vivante.
    pub fn restore(state: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(state);
        let name = String::from_utf8(reader.length_prefixed()?.to_vec())
            .map_err(|_| CryptoError::Storage("nom d'identité illisible".into()))?;
        let public_key = reader.length_prefixed()?.to_vec();
        let storage = reader.length_prefixed()?;

        let provider = Provider::import_state(storage)?;

        let signer =
            SignatureKeyPair::read(provider.storage(), &public_key, CIPHERSUITE.signature_algorithm())
                .ok_or_else(|| {
                    CryptoError::Storage("clé de signature absente de l'état restauré".into())
                })?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: public_key.into(),
        };

        Ok(Self { provider, credential, signer, name })
    }

    /// Identifiants des groupes présents dans l'état restauré.
    ///
    /// Le stockage ne fournit pas d'énumération : l'appelant doit conserver la liste des
    /// groupes qu'il a rejoints et la passer à [`crate::Conversation::load`].
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Lecteur longueur-préfixée tolérant aux entrées tronquées ou modifiées.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| CryptoError::Storage("état tronqué".into()))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn length_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
        let len = usize::try_from(len)
            .map_err(|_| CryptoError::Storage("longueur hors limites".into()))?;
        self.take(len)
    }
}

/// Empreinte affichable d'une clé publique de signature.
///
/// Groupée par blocs de 4 caractères : la comparaison visuelle de deux chaînes hexadécimales
/// continues est notoirement peu fiable, et l'attaque consiste précisément à produire une clé
/// dont l'empreinte *ressemble* à la bonne.
pub fn fingerprint(signature_key: &[u8]) -> String {
    let digest = Sha256::digest(signature_key);
    digest[..16]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Désérialise et valide un KeyPackage reçu du serveur.
///
/// `validate` vérifie la signature du KeyPackage, celle de son leaf node, sa durée de vie et
/// sa version. **Cela ne prouve rien sur l'identité derrière.** Un serveur malveillant peut
/// fabriquer un KeyPackage parfaitement valide portant le nom « bob » avec ses propres clés :
/// toutes ces vérifications passeront. Seule la comparaison hors bande de l'empreinte détecte
/// cette substitution. C'est le point faible réel de tout déploiement E2EE.
pub(crate) fn parse_key_package(provider: &Provider, bytes: &[u8]) -> Result<KeyPackage> {
    let message = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| CryptoError::Malformed("key package illisible"))?;

    let MlsMessageBodyIn::KeyPackage(key_package_in) = message.extract() else {
        return Err(CryptoError::UnexpectedMessage);
    };

    key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(mls)
}
