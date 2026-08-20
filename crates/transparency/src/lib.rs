//! Journal auditable des clés de compte.
//!
//! # Le trou que cette crate ferme
//!
//! Les attestations (crate `attest`) empêchent le serveur d'**ajouter** un appareil à un
//! compte. Elles ne l'empêchent pas de mentir sur la clé du compte **au premier contact** :
//! quand Alice demande le compte de Bob pour la première fois, elle n'a rien à quoi comparer.
//! Le serveur peut servir sa propre clé, relayer en clair entre deux sessions parfaitement
//! chiffrées, et rien ne le détecte — sauf une comparaison d'empreintes de vive voix, que
//! presque personne ne fait.
//!
//! C'est le *trust on first use*, et c'est le dernier vrai trou cryptographique du projet.
//!
//! # Ce qu'un journal apporte, et ce qu'il n'apporte pas
//!
//! Chaque clé de compte est ajoutée à un arbre de Merkle **append-only**. Le serveur publie une
//! tête signée (STH) et, à la demande, une preuve que telle clé figure bien dans l'arbre. Le
//! client vérifie deux choses :
//!
//! - **l'inclusion** : la clé qu'on me sert est bien celle du journal ;
//! - **la cohérence** : le journal d'aujourd'hui prolonge celui d'hier, sans réécriture.
//!
//! Cela réduit le mensonge à une seule forme, mais ne l'élimine pas : un serveur peut tenir
//! **deux journaux** et servir l'un à Alice, l'autre à Bob. Chacun voit un journal cohérent.
//! Seule la comparaison des têtes entre clients — le *gossip* — attrape cette bifurcation, et
//! il se fait hors de cette crate, dans les messages chiffrés que le serveur ne peut pas
//! falsifier.
//!
//! # Pourquoi RFC 6962 et pas un arbre maison
//!
//! Les préfixes de domaine `0x00` (feuille) et `0x01` (nœud interne) empêchent une **attaque
//! par seconde préimage** : sans eux, le hash d'un nœud interne pourrait être présenté comme
//! celui d'une feuille, et un attaquant fabriquerait une preuve d'inclusion pour une entrée
//! qu'il choisit. C'est la partie qu'on ne devine pas et qu'il ne faut pas réinventer.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Préfixe des feuilles. Voir la note du module : sans séparation feuille/nœud, un hash
/// interne peut être rejoué comme feuille.
const LEAF_PREFIX: u8 = 0x00;

/// Préfixe des nœuds internes.
const NODE_PREFIX: u8 = 0x01;

/// Séparation de domaine des têtes signées, distincte de celles de la crate `attest`.
const STH_DOMAIN: &[u8] = b"wac-sth-v1";

pub type Hash = [u8; 32];

#[derive(Debug, PartialEq, Eq)]
pub enum LogError {
    /// L'indice demandé dépasse la taille de l'arbre.
    OutOfRange,
    /// La preuve ne reconstruit pas la racine annoncée.
    BadProof,
    /// Les deux tailles ne peuvent pas être reliées : `from` doit être non nul et ≤ `to`.
    BadRange,
    /// La signature de la tête ne vérifie pas.
    BadSignature,
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange => write!(f, "indice hors de l'arbre"),
            Self::BadProof => write!(f, "preuve invalide"),
            Self::BadRange => write!(f, "intervalle de cohérence invalide"),
            Self::BadSignature => write!(f, "tête de journal non signée par le journal"),
        }
    }
}

impl std::error::Error for LogError {}

/// Hash d'une feuille : `SHA256(0x00 ‖ contenu)`.
pub fn leaf_hash(contents: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(contents);
    hasher.finalize().into()
}

/// Hash d'un nœud interne : `SHA256(0x01 ‖ gauche ‖ droite)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Contenu canonique d'une entrée du journal.
///
/// Longueur-préfixé comme dans `attest`, et pour la même raison : sans préfixe,
/// `("ab", clé)` et `("a", "b"‖clé)` produiraient les mêmes octets, donc la même feuille.
pub fn entry(handle: &str, identity_key: &[u8]) -> Vec<u8> {
    let handle = handle.as_bytes();
    let mut out = Vec::with_capacity(4 + handle.len() + identity_key.len());
    out.extend_from_slice(&(handle.len() as u16).to_be_bytes());
    out.extend_from_slice(handle);
    out.extend_from_slice(&(identity_key.len() as u16).to_be_bytes());
    out.extend_from_slice(identity_key);
    out
}

/// Racine d'un arbre de Merkle sur `leaves`, selon RFC 6962.
///
/// L'arbre n'est pas complété jusqu'à une puissance de deux : un sous-arbre isolé remonte tel
/// quel. Compléter par des feuilles vides ferait qu'un arbre de 3 feuilles et un arbre de 4
/// dont la dernière est vide auraient la même racine.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let split = split_point(n);
            node_hash(&root(&leaves[..split]), &root(&leaves[split..]))
        }
    }
}

/// Point de découpe : la plus grande puissance de deux **strictement** inférieure à `n`.
///
/// C'est ce qui rend l'arbre *append-only* : ajouter une feuille ne redécoupe jamais la partie
/// gauche, donc les sous-arbres déjà calculés restent valides. Un découpage au milieu
/// (`n / 2`) réorganiserait l'arbre à chaque ajout et rendrait toute preuve de cohérence
/// impossible.
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Preuve qu'une feuille figure dans l'arbre : le chemin d'audit, de bas en haut.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Result<Vec<Hash>, LogError> {
    if index >= leaves.len() {
        return Err(LogError::OutOfRange);
    }
    if leaves.len() == 1 {
        return Ok(Vec::new());
    }

    let split = split_point(leaves.len());
    let mut proof = if index < split {
        let mut p = inclusion_proof(&leaves[..split], index)?;
        p.push(root(&leaves[split..]));
        p
    } else {
        let mut p = inclusion_proof(&leaves[split..], index - split)?;
        p.push(root(&leaves[..split]));
        p
    };
    proof.shrink_to_fit();
    Ok(proof)
}

/// Vérifie qu'une feuille figure bien dans l'arbre de racine `root`.
///
/// Fonction libre et sans état : le client la rappelle sur ce que le serveur lui sert, sans
/// jamais se fier au verdict de ce dernier.
///
/// # L'ordre, qui n'est pas un détail
///
/// [`inclusion_proof`] produit le chemin **de bas en haut** : le premier élément est le frère
/// le plus profond. La vérification doit donc reconstituer le chemin dans le même sens.
/// Décider de la direction à chaque niveau *en descendant* — ce qui semble naturel — associe
/// le frère le plus profond à la décision du sommet, et combine les hashs dans le mauvais
/// ordre. L'erreur ne se voit que sur les arbres de taille non puissance de deux, où les deux
/// parcours cessent de coïncider.
pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    size: usize,
    proof: &[Hash],
    expected_root: &Hash,
) -> Result<(), LogError> {
    if index >= size {
        return Err(LogError::OutOfRange);
    }

    // Descente : à chaque niveau, notre feuille est-elle dans la moitié droite ?
    let mut directions = Vec::new();
    let mut index = index;
    let mut size = size;
    while size > 1 {
        let split = split_point(size);
        if index < split {
            directions.push(false);
            size = split;
        } else {
            directions.push(true);
            index -= split;
            size -= split;
        }
    }

    if directions.len() != proof.len() {
        return Err(LogError::BadProof);
    }

    // Remontée : le frère le plus profond va avec la décision la plus profonde.
    let mut hash = *leaf;
    for (sibling, from_right) in proof.iter().zip(directions.iter().rev()) {
        hash = if *from_right { node_hash(sibling, &hash) } else { node_hash(&hash, sibling) };
    }

    if hash != *expected_root {
        return Err(LogError::BadProof);
    }
    Ok(())
}

/// Preuve que l'arbre de taille `to` prolonge celui de taille `from` **sans réécriture**.
///
/// C'est la propriété qui distingue un journal auditable d'une simple base : le serveur ne peut
/// pas revenir en arrière et remplacer une clé déjà publiée sans que tous ceux qui ont vu
/// l'ancienne tête le constatent.
pub fn consistency_proof(leaves: &[Hash], from: usize) -> Result<Vec<Hash>, LogError> {
    let to = leaves.len();
    if from == 0 || from > to {
        return Err(LogError::BadRange);
    }
    if from == to {
        return Ok(Vec::new());
    }
    Ok(subtree_proof(leaves, from, true))
}

/// Cœur de la preuve de cohérence.
///
/// `complete` indique que le sous-arbre couvrant les `from` premières feuilles est exactement
/// un nœud déjà connu du vérificateur — auquel cas il n'a pas besoin qu'on le lui redonne.
fn subtree_proof(leaves: &[Hash], from: usize, complete: bool) -> Vec<Hash> {
    let n = leaves.len();
    if from == n {
        // Le vérificateur connaît déjà ce nœud s'il était complet ; sinon il faut le lui
        // fournir pour qu'il recalcule sa propre ancienne racine.
        return if complete { Vec::new() } else { vec![root(leaves)] };
    }

    let split = split_point(n);
    if from <= split {
        let mut proof = subtree_proof(&leaves[..split], from, complete);
        proof.push(root(&leaves[split..]));
        proof
    } else {
        let mut proof = subtree_proof(&leaves[split..], from - split, false);
        proof.push(root(&leaves[..split]));
        proof
    }
}

/// Vérifie qu'un arbre en prolonge un autre.
///
/// Reconstruit **les deux** racines à partir de la même preuve : accepter sans recalculer
/// l'ancienne reviendrait à croire le serveur sur ce qu'il publiait hier.
///
/// L'algorithme est celui de la RFC 6962, transcrit tel quel. Il travaille sur les indices des
/// dernières feuilles (`from - 1`, `to - 1`) et lit leurs bits pour retrouver la découpe des
/// sous-arbres — une gymnastique qu'il vaut mieux ne pas réinventer.
pub fn verify_consistency(
    from: usize,
    old_root: &Hash,
    to: usize,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<(), LogError> {
    if from == 0 || from > to {
        return Err(LogError::BadRange);
    }
    if from == to {
        return if proof.is_empty() && old_root == new_root {
            Ok(())
        } else {
            Err(LogError::BadProof)
        };
    }

    let mut fnode = from - 1;
    let mut snode = to - 1;

    // Remonte tant que l'ancien arbre finit sur une feuille droite : ces niveaux sont communs
    // aux deux arbres et n'apparaissent pas dans la preuve.
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }

    // `fnode == 0` signifie que l'ancien arbre est un sous-arbre complet : le vérificateur en
    // connaît déjà la racine, la preuve ne la contient donc pas. Sinon elle l'ouvre.
    let (seed, rest) = if fnode == 0 {
        (*old_root, proof)
    } else {
        let (first, rest) = proof.split_first().ok_or(LogError::BadProof)?;
        (*first, rest)
    };

    let mut old = seed;
    let mut new = seed;

    for sibling in rest {
        if snode == 0 {
            return Err(LogError::BadProof);
        }

        if fnode & 1 == 1 || fnode == snode {
            old = node_hash(sibling, &old);
            new = node_hash(sibling, &new);
            while fnode != 0 && fnode & 1 == 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            new = node_hash(&new, sibling);
        }

        fnode >>= 1;
        snode >>= 1;
    }

    if snode != 0 || old != *old_root || new != *new_root {
        return Err(LogError::BadProof);
    }
    Ok(())
}

/// Tête de journal signée : ce que le serveur publie, et ce que les clients s'échangent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeHead {
    pub size: u64,
    pub root: Hash,
    /// Secondes Unix. Dans le message signé : sans lui, une vieille tête pourrait être
    /// rejouée indéfiniment pour masquer les ajouts qui ont suivi.
    pub timestamp: u64,
}

impl TreeHead {
    /// Message canonique signé. Domaine distinct de ceux d'`attest` : une signature de tête ne
    /// doit valoir dans aucun autre contexte.
    pub fn message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STH_DOMAIN.len() + 8 + 32 + 8);
        out.extend_from_slice(STH_DOMAIN);
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out
    }

    pub fn sign(&self, key: &SigningKey) -> [u8; 64] {
        key.sign(&self.message()).to_bytes()
    }

    /// Vérifie la signature du journal.
    ///
    /// **Ce que cela prouve est étroit** : que la tête vient bien du journal. Pas qu'elle soit
    /// la seule qu'il ait émise. Un journal qui bifurque signe deux têtes également valides ;
    /// seul le gossip entre clients l'attrape.
    pub fn verify(&self, log_key: &[u8], signature: &[u8]) -> Result<(), LogError> {
        let log_key: [u8; 32] = log_key.try_into().map_err(|_| LogError::BadSignature)?;
        let verifying = VerifyingKey::from_bytes(&log_key).map_err(|_| LogError::BadSignature)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| LogError::BadSignature)?;

        verifying
            .verify(&self.message(), &Signature::from_bytes(&signature))
            .map_err(|_| LogError::BadSignature)
    }
}
