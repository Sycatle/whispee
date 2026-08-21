//! Auditable log of account keys.
//!
//! # The gap this crate closes
//!
//! Attestations (the `attest` crate) stop the server from **adding** a device to an account. They
//! do not stop it from lying about the account key **on first contact**: when Alice asks for
//! Bob's account for the first time, she has nothing to compare against. The server can serve its
//! own key, relay in the clear between two perfectly encrypted sessions, and nothing detects it —
//! except comparing fingerprints out loud, which almost nobody does.
//!
//! That is *trust on first use*, and it is the last real cryptographic gap in the project.
//!
//! # What a log brings, and what it does not
//!
//! Every account key is appended to an **append-only** Merkle tree. The server publishes a signed
//! tree head (STH) and, on request, a proof that a given key really is in the tree. The client
//! checks two things:
//!
//! - **inclusion**: the key I am served really is the one in the log;
//! - **consistency**: today's log extends yesterday's, with no rewriting.
//!
//! This reduces the lie to a single form, but does not eliminate it: a server can keep **two
//! logs** and serve one to Alice and the other to Bob. Each sees a consistent log. Only comparing
//! heads between clients — *gossip* — catches that fork, and it happens outside this crate, in
//! the encrypted messages the server cannot forge.
//!
//! # Why RFC 6962 and not a homemade tree
//!
//! The domain prefixes `0x00` (leaf) and `0x01` (internal node) prevent a **second-preimage
//! attack**: without them the hash of an internal node could be presented as that of a leaf, and
//! an attacker would forge an inclusion proof for an entry of their choosing. That is the part
//! nobody guesses and nobody should reinvent.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Leaf prefix. See the module note: without leaf/node separation, an internal hash can be
/// replayed as a leaf.
const LEAF_PREFIX: u8 = 0x00;

/// Internal node prefix.
const NODE_PREFIX: u8 = 0x01;

/// Domain separation for signed tree heads, distinct from those of the `attest` crate.
const STH_DOMAIN: &[u8] = b"wac-sth-v1";

pub type Hash = [u8; 32];

#[derive(Debug, PartialEq, Eq)]
pub enum LogError {
    /// The requested index is beyond the size of the tree.
    OutOfRange,
    /// The proof does not rebuild the announced root.
    BadProof,
    /// The two sizes cannot be related: `from` must be non-zero and ≤ `to`.
    BadRange,
    /// The head signature does not verify.
    BadSignature,
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange => write!(f, "index outside the tree"),
            Self::BadProof => write!(f, "invalid proof"),
            Self::BadRange => write!(f, "invalid consistency range"),
            Self::BadSignature => write!(f, "tree head not signed by the log"),
        }
    }
}

impl std::error::Error for LogError {}

/// Leaf hash: `SHA256(0x00 ‖ contents)`.
pub fn leaf_hash(contents: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(contents);
    hasher.finalize().into()
}

/// Internal node hash: `SHA256(0x01 ‖ left ‖ right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Canonical contents of a log entry.
///
/// Length-prefixed as in `attest`, and for the same reason: without prefixes, `("ab", key)` and
/// `("a", "b"‖key)` would produce the same bytes, hence the same leaf.
pub fn entry(handle: &str, identity_key: &[u8]) -> Vec<u8> {
    let handle = handle.as_bytes();
    let mut out = Vec::with_capacity(4 + handle.len() + identity_key.len());
    out.extend_from_slice(&(handle.len() as u16).to_be_bytes());
    out.extend_from_slice(handle);
    out.extend_from_slice(&(identity_key.len() as u16).to_be_bytes());
    out.extend_from_slice(identity_key);
    out
}

/// Root of a Merkle tree over `leaves`, per RFC 6962.
///
/// The tree is not padded up to a power of two: an isolated subtree is carried up as is. Padding
/// with empty leaves would make a 3-leaf tree and a 4-leaf tree whose last leaf is empty share
/// the same root.
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

/// Split point: the largest power of two **strictly** below `n`.
///
/// This is what makes the tree *append-only*: appending a leaf never re-splits the left part, so
/// the subtrees already computed stay valid. Splitting in the middle (`n / 2`) would reorganise
/// the tree on every append and make any consistency proof impossible.
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Proof that a leaf is in the tree: the audit path, bottom-up.
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

/// Checks that a leaf really is in the tree with root `root`.
///
/// Free and stateless: the client redoes it on whatever the server serves, never trusting the
/// latter's verdict.
///
/// # The order, which is not a detail
///
/// [`inclusion_proof`] produces the path **bottom-up**: the first element is the deepest sibling.
/// Verification must therefore rebuild the path in the same direction. Deciding the direction at
/// each level *on the way down* — which feels natural — pairs the deepest sibling with the
/// decision taken at the top, and combines the hashes in the wrong order. The mistake only shows
/// on trees whose size is not a power of two, where the two traversals stop coinciding.
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

    // Descent: at each level, is our leaf in the right half?
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

    // Climb back up: the deepest sibling goes with the deepest decision.
    let mut hash = *leaf;
    for (sibling, from_right) in proof.iter().zip(directions.iter().rev()) {
        hash = if *from_right { node_hash(sibling, &hash) } else { node_hash(&hash, sibling) };
    }

    if hash != *expected_root {
        return Err(LogError::BadProof);
    }
    Ok(())
}

/// Proof that the tree of size `to` extends the one of size `from` **without rewriting**.
///
/// This is the property that separates an auditable log from a plain database: the server cannot
/// go back and replace an already published key without everyone who saw the old head noticing.
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

/// Core of the consistency proof.
///
/// `complete` means the subtree covering the first `from` leaves is exactly a node the verifier
/// already knows — in which case it does not need to be given back to them.
fn subtree_proof(leaves: &[Hash], from: usize, complete: bool) -> Vec<Hash> {
    let n = leaves.len();
    if from == n {
        // The verifier already knows this node if it was complete; otherwise it must be supplied
        // so they can recompute their own old root.
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

/// Checks that one tree extends another.
///
/// Rebuilds **both** roots from the same proof: accepting without recomputing the old one would
/// amount to believing the server about what it published yesterday.
///
/// The algorithm is RFC 6962's, transcribed as is. It works on the indices of the last leaves
/// (`from - 1`, `to - 1`) and reads their bits to recover the subtree splits — gymnastics best
/// not reinvented.
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

    // Climb while the old tree ends on a right leaf: those levels are common to both trees and do
    // not appear in the proof.
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }

    // `fnode == 0` means the old tree is a complete subtree: the verifier already knows its root,
    // so the proof does not contain it. Otherwise the proof opens it.
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

/// Signed tree head: what the server publishes, and what clients exchange with each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeHead {
    pub size: u64,
    pub root: Hash,
    /// Unix seconds. Inside the signed message: without it, an old head could be replayed forever
    /// to hide the appends that followed.
    pub timestamp: u64,
}

impl TreeHead {
    /// Canonical signed message. Domain distinct from `attest`'s: a head signature must hold in
    /// no other context.
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

    /// Verifies the log's signature.
    ///
    /// **What this proves is narrow**: that the head does come from the log. Not that it is the
    /// only one it issued. A forking log signs two equally valid heads; only gossip between
    /// clients catches it.
    pub fn verify(&self, log_key: &[u8], signature: &[u8]) -> Result<(), LogError> {
        let log_key: [u8; 32] = log_key.try_into().map_err(|_| LogError::BadSignature)?;
        let verifying = VerifyingKey::from_bytes(&log_key).map_err(|_| LogError::BadSignature)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| LogError::BadSignature)?;

        verifying
            .verify(&self.message(), &Signature::from_bytes(&signature))
            .map_err(|_| LogError::BadSignature)
    }
}
