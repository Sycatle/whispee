//! Rôles d'administration d'un groupe.
//!
//! # MLS ne fournit aucune autorisation
//!
//! C'est le point à comprendre avant de lire la suite. La RFC 9420 décrit qui peut *prouver*
//! quoi, pas qui a le *droit* de faire quoi : n'importe quel membre peut commiter n'importe
//! quel ajout ou retrait, et le protocole l'acceptera. « Seuls les admins peuvent retirer »
//! est une règle applicative, et rien dans MLS ne l'impose à notre place.
//!
//! Conséquence directe : **chaque client doit appliquer la règle à l'identique**. Un client
//! qui accepte un commit que les autres refusent ne provoque pas une erreur, il provoque un
//! *fork* — deux moitiés du groupe avancent sur des epochs différentes, chacune persuadée
//! d'être le groupe, et plus rien ne passe entre elles. Aucun message d'erreur nulle part.
//!
//! C'est la raison pour laquelle la politique est ici une fonction **pure**, testée isolément,
//! et non une suite de conditions dispersées dans le code d'appel.
//!
//! # Pourquoi le roster vit dans le group context
//!
//! Le placer dans un message applicatif le laisserait rejouable et non authentifié : un membre
//! pourrait rediffuser un vieux roster où il était admin. Dans le group context, il est haché
//! dans chaque commit et fait partie de l'état sur lequel tous les membres s'accordent par
//! construction. Le modifier exige un commit, donc passe par la même politique que le reste.
//!
//! # Pourquoi des handles, et non des clés de signature
//!
//! Un handle couvre tous les appareils d'un compte. Ajouter un téléphone ne demande donc pas
//! de modifier le roster, et un admin l'est depuis n'importe lequel de ses appareils. C'est
//! aussi ce que le credential MLS transporte déjà — aucun lien supplémentaire à établir.

use crate::error::{CryptoError, Result};

/// Type d'extension du group context portant le roster.
///
/// `0xF100` est dans la plage d'usage privé de la RFC 9420 (`0xF000`–`0xFFFF`) : aucune
/// extension standardisée ne viendra jamais s'y heurter.
pub const ROSTER_EXTENSION: u16 = 0xF100;

/// Qui administre le groupe : **un** admin, et des modérateurs sous lui.
///
/// # Pourquoi un seul admin
///
/// Plusieurs admins de rang égal n'ont pas de départage : deux d'entre eux peuvent se
/// rétrograder mutuellement, se retirer l'un l'autre, ou se contredire sur la composition du
/// groupe. Rien dans le protocole ne dit lequel a raison, et le groupe se scinde. Une racine
/// unique supprime la question : il y a toujours exactement une autorité.
///
/// Les modérateurs entretiennent le groupe — ajouter, retirer des membres ordinaires — sans
/// pouvoir toucher aux rôles. Seul l'admin distribue le pouvoir, y compris le sien.
///
/// # L'absence de roster n'est pas un roster vide
///
/// C'est un **groupe plat**, où tout le monde peut tout faire. C'est le cas des conversations
/// 1-to-1, où des rôles n'auraient aucun sens, et celui des groupes créés avant cette
/// extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    admin: String,
    moderators: Vec<String>,
}

impl Roster {
    /// Crée un roster. L'admin ne peut pas figurer parmi les modérateurs : il est déjà
    /// au-dessus, et l'y répéter rendrait `is_moderator` ambigu à la lecture.
    pub fn new(admin: String, moderators: Vec<String>) -> Result<Self> {
        if admin.is_empty() {
            return Err(CryptoError::PolicyViolation("un groupe administré exige un admin"));
        }
        let moderators: Vec<String> = moderators.into_iter().filter(|m| *m != admin).collect();
        Ok(Self { admin, moderators })
    }

    pub fn admin(&self) -> &str {
        &self.admin
    }

    pub fn moderators(&self) -> &[String] {
        &self.moderators
    }

    pub fn is_admin(&self, handle: &str) -> bool {
        self.admin == handle
    }

    pub fn is_moderator(&self, handle: &str) -> bool {
        self.moderators.iter().any(|m| m == handle)
    }

    /// Peut ajouter et retirer des membres ordinaires.
    pub fn can_moderate(&self, handle: &str) -> bool {
        self.is_admin(handle) || self.is_moderator(handle)
    }

    /// A un rôle, quel qu'il soit. Un porteur de rôle ne peut être retiré que par l'admin.
    pub fn has_role(&self, handle: &str) -> bool {
        self.can_moderate(handle)
    }

    /// Sérialisation canonique :
    ///   `u16 len ‖ admin ‖ u16 count ‖ count × (u16 len ‖ modérateur)`
    ///
    /// Même discipline de longueur-préfixage que la crate `attest`, et pour la même raison :
    /// deux rosters distincts ne doivent jamais produire les mêmes octets, sans quoi le hash du
    /// group context cesserait de les distinguer.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        push_string(&mut out, &self.admin)?;

        if self.moderators.len() > u16::MAX as usize {
            return Err(CryptoError::Malformed("trop de modérateurs"));
        }
        out.extend_from_slice(&(self.moderators.len() as u16).to_be_bytes());
        for moderator in &self.moderators {
            push_string(&mut out, moderator)?;
        }
        Ok(out)
    }

    /// Lecture stricte : tout octet en trop est une erreur.
    ///
    /// Tolérer une queue non lue laisserait deux encodages représenter le même roster, ce qui
    /// suffirait à faire diverger deux clients sur l'état du groupe.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let admin = take_string(bytes, &mut cursor)?;

        let count = u16::from_be_bytes(
            take(bytes, &mut cursor, 2)?.try_into().expect("2 octets demandés, 2 obtenus"),
        );

        let mut moderators = Vec::with_capacity(count as usize);
        for _ in 0..count {
            moderators.push(take_string(bytes, &mut cursor)?);
        }

        if cursor != bytes.len() {
            return Err(CryptoError::Malformed("octets excédentaires après le roster"));
        }

        Self::new(admin, moderators)
    }
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(CryptoError::Malformed("handle trop long"));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, n: usize) -> Result<&'a [u8]> {
    let fin = cursor.checked_add(n).ok_or(CryptoError::Malformed("roster tronqué"))?;
    let part = bytes.get(*cursor..fin).ok_or(CryptoError::Malformed("roster tronqué"))?;
    *cursor = fin;
    Ok(part)
}

fn take_string(bytes: &[u8], cursor: &mut usize) -> Result<String> {
    let len = u16::from_be_bytes(
        take(bytes, cursor, 2)?.try_into().expect("2 octets demandés, 2 obtenus"),
    );
    let raw = take(bytes, cursor, len as usize)?;
    std::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|_| CryptoError::Malformed("handle non UTF-8 dans le roster"))
}

/// Ce qu'un commit entrant contient, réduit à ce dont la politique a besoin.
///
/// Ce type existe pour que la politique soit testable sans monter un groupe MLS : c'est la
/// seule façon de couvrir les cas limites, qui sont nombreux et dont certains ne se
/// reproduisent pas facilement avec de vraies epochs.
#[derive(Debug, Clone)]
pub struct CommitSummary<'a> {
    /// Handle du committer, lu dans son credential — donc authentifié par MLS.
    pub committer: &'a str,
    /// Un élément par retrait proposé.
    pub removals: Vec<Removal<'a>>,
    /// Le commit ajoute-t-il des membres ?
    pub adds: usize,
    /// Le commit modifie-t-il les extensions du group context (donc le roster) ?
    pub changes_roster: bool,
    /// Handles encore représentés dans le groupe **après** application du commit.
    ///
    /// Nécessaire parce qu'un compte a plusieurs appareils : retirer un appareil d'Alice ne
    /// retire pas Alice. Raisonner sur les cibles des retraits ferait croire à tort qu'un
    /// admin quitte le groupe dès qu'il y perd un téléphone, et le commit serait refusé.
    pub remaining: Vec<&'a str>,
}

/// Un retrait proposé, vu par la politique.
#[derive(Debug, Clone)]
pub struct Removal<'a> {
    /// Handle du compte propriétaire de l'appareil retiré.
    pub target: &'a str,
    /// Clé de signature MLS de l'appareil retiré, qui l'identifie sans ambiguïté.
    pub target_key: &'a [u8],
    /// Le retrait a-t-il été proposé par l'appareil lui-même ? Un départ volontaire.
    pub self_requested: bool,
}

/// Ce que l'appelant sait de l'extérieur, et que le protocole ne peut pas lui apprendre.
///
/// La liste des révocations vient du serveur et **doit avoir été vérifiée** par l'appelant
/// (`attest::verify_revocation`) avant d'arriver ici. Ce module ne fait pas de réseau et ne
/// vérifie pas de signature : c'est ce qui garde `crypto-core` sans I/O, et ce qui rend la
/// politique testable.
#[derive(Debug, Default, Clone)]
pub struct Context {
    /// Clés de signature MLS dont le certificat de révocation a été vérifié.
    pub revoked: Vec<Vec<u8>>,
}

impl Context {
    fn est_revoque(&self, key: &[u8]) -> bool {
        self.revoked.iter().any(|k| k == key)
    }
}

/// Décide si un commit doit être appliqué.
///
/// Fonction pure : mêmes entrées, même verdict, sur tous les clients. C'est la condition pour
/// qu'un refus ne provoque pas de fork — voir l'en-tête du module.
///
/// # La hiérarchie
///
/// | Opération | Autorisée pour |
/// |---|---|
/// | tout, dans un groupe sans roster | tout le monde |
/// | ajouter un membre | admin, modérateur |
/// | retirer un membre ordinaire | admin, modérateur |
/// | retirer un modérateur | admin |
/// | modifier le roster (nommer, révoquer, transmettre) | admin |
/// | retirer l'admin | personne |
/// | commiter le départ volontaire d'un membre | tout le monde |
/// | retirer un appareil dont la révocation est vérifiée | tout le monde |
///
/// # Pourquoi un modérateur ne touche pas aux autres modérateurs
///
/// Sinon deux modérateurs peuvent se retirer mutuellement, et le résultat dépend de qui commite
/// le premier — une course, pas une règle. Le pouvoir sur les rôles reste indivis chez l'admin,
/// ce qui est précisément ce qu'apporte une racine unique.
///
/// # Pourquoi l'admin ne peut pas être retiré
///
/// Un groupe sans admin est gelé : plus personne ne peut nommer, révoquer, ni transmettre,
/// l'extension étant sous son seul contrôle. Le départ d'un admin passe donc par une
/// **transmission préalable** — il désigne son successeur tant qu'il en a encore le pouvoir.
///
/// # Les deux exceptions, qui ne sont pas du confort
///
/// **Le départ volontaire.** Un membre ne peut pas se retirer lui-même dans un commit (RFC
/// 9420) : il propose, un autre commite. Réserver ce commit aux porteurs de rôle rendrait la
/// sortie impossible quand aucun n'est en ligne — un groupe dont on ne peut pas sortir.
///
/// **L'appareil révoqué.** Sans elle, le téléphone volé d'un membre ordinaire reste dans le
/// groupe, à lire, jusqu'au retour en ligne d'un modérateur. C'est précisément le délai que la
/// révocation existe pour supprimer. Le certificat étant vérifiable par tous, l'exception
/// n'ouvre rien : seul le compte propriétaire peut la déclencher.
pub fn authorize(
    roster: Option<&Roster>,
    commit: &CommitSummary<'_>,
    context: &Context,
) -> Result<()> {
    // Groupe plat : aucune règle à appliquer. C'est le cas des 1-to-1 et des groupes créés
    // avant l'introduction du roster.
    let Some(roster) = roster else { return Ok(()) };

    let auteur_admin = roster.is_admin(commit.committer);
    let auteur_modere = roster.can_moderate(commit.committer);

    if commit.changes_roster && !auteur_admin {
        return Err(CryptoError::PolicyViolation("seul l'admin modifie les rôles"));
    }

    if commit.adds > 0 && !auteur_modere {
        return Err(CryptoError::PolicyViolation("ajouter un membre demande un rôle"));
    }

    for removal in &commit.removals {
        // Les deux exceptions, applicables à n'importe qui.
        if removal.self_requested || context.est_revoque(removal.target_key) {
            continue;
        }

        if !auteur_modere {
            return Err(CryptoError::PolicyViolation("retirer un membre demande un rôle"));
        }
        if roster.is_moderator(removal.target) && !auteur_admin {
            return Err(CryptoError::PolicyViolation(
                "seul l'admin retire un modérateur",
            ));
        }
    }

    // S'applique à tous, y compris à l'admin lui-même : le groupe ne doit jamais se retrouver
    // sans autorité, quelle que soit l'intention. Le départ légitime passe par une
    // transmission préalable, qui installe le successeur avant que le retrait n'ait lieu.
    if !commit.remaining.contains(&roster.admin()) {
        return Err(CryptoError::PolicyViolation(
            "le groupe perdrait son admin : transmettez-le d'abord",
        ));
    }

    Ok(())
}
