//! Attestation d'appartenance d'un appareil à un compte.
//!
//! # Le problème que cette crate résout
//!
//! En MLS, l'unité d'appartenance à un groupe est l'appareil. Un compte multi-appareils est
//! donc, du point de vue du protocole, un ensemble d'appareils sans lien entre eux. Quelqu'un
//! doit déclarer que ces appareils forment un compte — et c'est ce « quelqu'un » qui décide,
//! en pratique, qui peut lire les conversations.
//!
//! Si c'est le serveur, il lui suffit d'ajouter un appareil qu'il contrôle à la liste de Bob
//! pour être invité dans toutes ses conversations. Aucune ligne de cryptographie n'est cassée :
//! le message est chiffré de bout en bout, simplement l'une des bouts est le serveur. C'est
//! l'attaque reprochée à WhatsApp en 2019, et elle est indétectable sans la présente crate.
//!
//! Ici, c'est le **compte** qui signe ses appareils, avec une clé que le serveur ne détient
//! pas. Le serveur ne peut donc plus qu'**omettre** un appareil de la liste — de la censure,
//! visible et sans intérêt pour un espion — mais jamais en **ajouter** un.
//!
//! # Pourquoi une crate séparée
//!
//! Le signataire est `crypto-core`, le vérificateur est `server`. Deux implémentations du
//! format canonique divergeraient tôt ou tard, et la divergence bénigne (signatures refusées)
//! n'est pas la seule possible : c'est aussi ainsi qu'on introduit une confusion de champs.
//! Une seule définition, ici, testée ici.
//!
//! `server` ne parle pas MLS et ne doit pas commencer : cette crate ne dépend donc pas
//! d'OpenMLS.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Étiquette de séparation de domaine.
///
/// Elle garantit qu'une signature produite ici ne peut pas être rejouée comme signature
/// valide dans un autre contexte du projet, et réciproquement. La version dans l'étiquette
/// est ce qui permettra de faire évoluer le format sans qu'une ancienne signature reste
/// acceptable sous les nouvelles règles.
const DOMAIN: &[u8] = b"wac-attest-v1";

/// Domaine de la révocation, distinct de celui de l'attestation.
///
/// C'est cette distinction qui interdit qu'une attestation, obtenue légitimement, soit
/// représentée comme un certificat de révocation du même appareil — ce qui permettrait à
/// n'importe qui de faire évincer n'importe quel appareil déjà attesté.
const DOMAIN_REVOKE: &[u8] = b"wac-revoke-v1";

/// Domaine de la rotation de compte.
///
/// Encore un domaine distinct, pour la même raison que les deux précédents : une signature
/// produite pour révoquer un appareil ne doit pas pouvoir servir à changer la clé du compte,
/// ce qui reviendrait à en prendre le contrôle.
const DOMAIN_ROTATE: &[u8] = b"wac-rotate-v1";

/// Domaine du dépôt anonyme d'enveloppe.
///
/// Distinct des trois autres, et pour une raison qui n'est pas théorique : ce message est
/// authentifié par un **MAC symétrique** dont la clé est partagée avec le serveur, là où les
/// autres portent des signatures que le serveur ne peut pas produire. Confondre les domaines
/// laisserait le détenteur de la clé de dépôt fabriquer ce qu'il veut ailleurs.
const DOMAIN_POST: &[u8] = b"wac-post-v1";

/// Domaine du MAC accompagnant un **signal éphémère** (indicateur de frappe).
///
/// Distinct de [`DOMAIN_POST`] bien que la clé soit la même : sans cette séparation, un MAC
/// capté sur un signal — qui n'a pas d'anti-rejeu, parce qu'un signal périmé est sans effet —
/// pourrait être présenté comme le MAC d'un dépôt d'enveloppe. Le format du corps diffère
/// suffisamment pour que l'attaque échoue en pratique, ce qui est exactement le genre de
/// raisonnement qui cesse d'être vrai à la première évolution du format.
const DOMAIN_SIGNAL: &[u8] = b"wac-signal-mac-v1";

/// Longueur maximale acceptée pour un champ de longueur variable.
///
/// Le préfixe de longueur est un `u16` : au-delà, la sérialisation tronquerait silencieusement,
/// ce qui rendrait deux entrées distinctes indiscernables.
pub const MAX_FIELD_LEN: usize = u16::MAX as usize;

#[derive(Debug, PartialEq, Eq)]
pub enum AttestError {
    /// Un champ dépasse ce qu'un préfixe `u16` peut décrire.
    FieldTooLong,
    /// La clé publique du compte n'est pas une clé Ed25519 valide.
    BadIdentityKey,
    /// La signature n'a pas la bonne taille, ou ne vérifie pas.
    BadSignature,
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldTooLong => write!(f, "champ trop long pour être attesté"),
            Self::BadIdentityKey => write!(f, "clé d'identité de compte invalide"),
            Self::BadSignature => write!(f, "attestation invalide"),
        }
    }
}

impl std::error::Error for AttestError {}

/// Ce qu'un appareil revendique : appartenir à `handle`, avec ces deux clés publiques.
///
/// Les deux clés sont attestées ensemble et non séparément. Les séparer permettrait de
/// recombiner l'attestation d'une clé d'authentification avec la clé MLS d'un autre appareil.
#[derive(Debug, Clone, Copy)]
pub struct DeviceClaim<'a> {
    /// Pseudonyme du compte. Transporté en clair, comme l'est déjà le credential MLS.
    pub handle: &'a str,
    pub device_id: &'a str,
    /// Clé Ed25519 d'authentification HTTP (32 octets).
    pub auth_key: &'a [u8],
    /// Clé publique de signature MLS de cet appareil.
    pub mls_key: &'a [u8],
}

/// Sérialise la revendication sous la forme exacte qui est signée.
///
/// Chaque champ de longueur variable est précédé de sa longueur. Sans ces préfixes,
/// `handle="ab", device_id="c"` et `handle="a", device_id="bc"` produiraient des octets
/// identiques : une attestation obtenue pour l'un vaudrait pour l'autre. C'est exactement le
/// genre de faille qui ne se voit pas à la relecture et que le test
/// `deux_decoupages_differents_ne_collisionnent_pas` fige.
pub fn message(claim: &DeviceClaim<'_>) -> Result<Vec<u8>, AttestError> {
    encode(
        DOMAIN,
        &[claim.handle.as_bytes(), claim.device_id.as_bytes(), claim.auth_key, claim.mls_key],
    )
}

/// Sérialisation canonique commune à tous les messages signés de cette crate.
///
/// Une seule implémentation du préfixage, partagée par l'attestation et la révocation. Deux
/// copies divergeraient : c'est la raison d'être de la crate, il serait absurde de reproduire
/// le problème en son sein.
///
/// L'étiquette de domaine ouvre le message, donc aucun message d'un type ne peut être lu
/// comme un message d'un autre type — c'est ce qui interdit de rejouer une attestation comme
/// révocation.
fn encode(domain: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>, AttestError> {
    if parts.iter().any(|part| part.len() > MAX_FIELD_LEN) {
        return Err(AttestError::FieldTooLong);
    }

    let mut out = Vec::with_capacity(domain.len() + parts.iter().map(|p| p.len() + 2).sum::<usize>());
    out.extend_from_slice(domain);
    for part in parts {
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// Vérification Ed25519 commune. Voir la note de [`verify`] sur la confiance à accorder au
/// résultat produit par le serveur.
fn verify_signature(identity_key: &[u8], message: &[u8], sig: &[u8]) -> Result<(), AttestError> {
    let identity_key: [u8; 32] = identity_key.try_into().map_err(|_| AttestError::BadIdentityKey)?;
    let verifying =
        VerifyingKey::from_bytes(&identity_key).map_err(|_| AttestError::BadIdentityKey)?;

    let sig: [u8; 64] = sig.try_into().map_err(|_| AttestError::BadSignature)?;

    verifying
        .verify(message, &Signature::from_bytes(&sig))
        .map_err(|_| AttestError::BadSignature)
}

/// Vérifie qu'une attestation a bien été produite par le compte.
///
/// Fonction libre et sans état : elle ne demande aucun secret, ce qui permet au serveur de
/// l'appeler comme contrôle d'accès et au client de la rappeler pour son propre compte.
///
/// **Le client ne doit jamais se fier à la vérification faite par le serveur.** Un serveur
/// qui ment sur le résultat est précisément le scénario contre lequel tout ceci existe : la
/// vérification côté serveur n'est là que pour refuser tôt ce qui est de toute façon
/// inutilisable, pas pour constituer une garantie.
pub fn verify(
    identity_key: &[u8],
    claim: &DeviceClaim<'_>,
    attestation: &[u8],
) -> Result<(), AttestError> {
    verify_signature(identity_key, &message(claim)?, attestation)
}

/// Ce qu'un compte déclare en révoquant l'un de ses appareils.
///
/// # Pourquoi un certificat, et pas simplement une ligne en base
///
/// Retirer un appareil d'un groupe MLS est un acte que **d'autres comptes** doivent poser :
/// si Alice perd son téléphone, c'est Bob, présent dans le groupe, qui commite le retrait. Sans
/// certificat, Bob n'a pour seule source que le serveur — qui retrouve donc exactement le
/// pouvoir que [`verify`] lui refuse, celui de décider qui appartient à un compte, à ceci près
/// qu'il s'exerce dans l'autre sens : faire évincer plutôt que faire entrer.
///
/// Le certificat rend la révocation vérifiable par n'importe qui détenant la clé du compte.
/// Le serveur peut toujours *taire* une révocation ; il ne peut plus en *inventer* une.
#[derive(Debug, Clone, Copy)]
pub struct RevocationClaim<'a> {
    pub handle: &'a str,
    pub device_id: &'a str,
    /// Instant de la révocation, en secondes Unix.
    ///
    /// Il est **dans le message signé**, donc le serveur ne peut pas antidater une révocation
    /// authentique pour prétendre qu'un appareil était déjà écarté au moment d'un message.
    pub revoked_at: u64,
}

/// Sérialise la révocation sous la forme exacte qui est signée.
///
/// L'horodatage passe par le même préfixage que le reste bien que sa longueur soit fixe :
/// une exception au format serait une occasion de divergence pour rien.
pub fn revocation_message(claim: &RevocationClaim<'_>) -> Result<Vec<u8>, AttestError> {
    encode(
        DOMAIN_REVOKE,
        &[claim.handle.as_bytes(), claim.device_id.as_bytes(), &claim.revoked_at.to_be_bytes()],
    )
}

/// Vérifie qu'un certificat de révocation émane bien du compte propriétaire de l'appareil.
///
/// Comme [`verify`], elle ne demande aucun secret : c'est ce qui permet à un tiers — un autre
/// membre du groupe — de constater la révocation sans faire confiance au serveur qui la lui
/// transmet.
pub fn verify_revocation(
    identity_key: &[u8],
    claim: &RevocationClaim<'_>,
    revocation: &[u8],
) -> Result<(), AttestError> {
    verify_signature(identity_key, &revocation_message(claim)?, revocation)
}

/// Ce qu'un compte déclare en changeant de clé d'identité.
///
/// # Pourquoi la rotation existe
///
/// Tous les appareils d'un compte détiennent la graine — c'est la condition de la **parité** :
/// chaque appareil peut attester, révoquer et lire comme les autres, sans hiérarchie. La
/// contrepartie est qu'un appareil volé détient le compte entier. Le révoquer ne sert alors à
/// rien : son porteur en atteste un nouveau dans la foulée.
///
/// La seule réponse est de changer la clé du compte. Elle a un effet mécanique qui dispense de
/// toute autre mesure : **toutes les attestations existantes deviennent invérifiables**,
/// puisque les clients les vérifient contre la clé courante. La révocation totale n'est pas un
/// mécanisme séparé, c'est une conséquence.
///
/// # Ce que la signature par l'ancienne clé prouve, et ne prouve pas
///
/// Elle prouve la continuité : sans elle, n'importe qui reprendrait le handle d'autrui. Elle
/// ne prouve **pas** que la rotation est légitime — le voleur détient la même clé et peut
/// tourner le premier. C'est une course, et elle est inhérente : rien dans le protocole ne
/// distingue le propriétaire du porteur. D'où l'importance de l'alerte de changement
/// d'empreinte chez les correspondants, qui est ici le seul recours.
#[derive(Debug, Clone, Copy)]
pub struct RotationClaim<'a> {
    pub handle: &'a str,
    /// Nouvelle clé publique du compte (32 octets).
    pub new_identity_key: &'a [u8],
    /// Instant de la rotation, en secondes Unix.
    pub rotated_at: u64,
}

pub fn rotation_message(claim: &RotationClaim<'_>) -> Result<Vec<u8>, AttestError> {
    encode(
        DOMAIN_ROTATE,
        &[claim.handle.as_bytes(), claim.new_identity_key, &claim.rotated_at.to_be_bytes()],
    )
}

/// Vérifie une rotation contre l'**ancienne** clé du compte.
///
/// C'est bien l'ancienne : la signature atteste que le détenteur de la clé sortante désigne la
/// clé entrante. Vérifier contre la nouvelle ne prouverait que la possession de celle-ci,
/// c'est-à-dire rien.
pub fn verify_rotation(
    previous_identity_key: &[u8],
    claim: &RotationClaim<'_>,
    rotation: &[u8],
) -> Result<(), AttestError> {
    verify_signature(previous_identity_key, &rotation_message(claim)?, rotation)
}

/// Message authentifié lors d'un dépôt anonyme d'enveloppe.
///
/// # Ce que ce MAC prouve, et ce qu'il ne prouve pas
///
/// Il prouve que le déposant **détient la clé du groupe**, donc qu'il en est membre. Il ne dit
/// rien de qui il est, et c'est précisément l'objectif : le serveur n'a pas besoin de savoir
/// qui poste, seulement qu'il a le droit de le faire.
///
/// Le nonce rend chaque dépôt unique et permet au serveur de refuser les rejeux. Sans lui, un
/// MAC intercepté resterait valide indéfiniment.
///
/// L'empreinte du corps est incluse plutôt que le corps : un attaquant qui pourrait modifier
/// l'enveloppe après coup déposerait ce qu'il veut sous un MAC légitime.
pub fn post_message(group_id: &[u8], nonce: &[u8], body_digest: &[u8]) -> Result<Vec<u8>, AttestError> {
    encode(DOMAIN_POST, &[group_id, nonce, body_digest])
}

/// Message authentifié lors du dépôt d'un signal éphémère.
///
/// Jumeau de [`post_message`], au domaine près. Il prouve la même chose — l'appartenance au
/// groupe, pas l'identité — pour un contenu qui, lui, ne sera jamais écrit sur disque.
pub fn signal_message(
    group_id: &[u8],
    nonce: &[u8],
    body_digest: &[u8],
) -> Result<Vec<u8>, AttestError> {
    encode(DOMAIN_SIGNAL, &[group_id, nonce, body_digest])
}

/// Empreinte du compte, à comparer hors bande avec son correspondant.
///
/// Calculée sur la seule clé d'identité, donc **stable quand le compte gagne ou perd un
/// appareil**. C'est délibéré : une empreinte qui changerait à chaque appareil ajouté
/// obligerait à revérifier après chaque événement légitime, et serait ignorée en quelques
/// semaines. La détection d'un appareil hostile passe par la notification d'ajout, pas par
/// l'empreinte.
pub fn fingerprint(identity_key: &[u8]) -> String {
    let digest = Sha256::digest(identity_key);
    digest[..16]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}
