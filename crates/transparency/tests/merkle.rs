//! The log is only worth its proofs: a proof wrongly accepted hands the server exactly the power
//! we are trying to take away from it. These tests sweep the small sizes exhaustively, where the
//! splitting mistakes hide.

use transparency::*;

fn leaves(n: usize) -> Vec<Hash> {
    (0..n).map(|i| leaf_hash(&entry(&format!("account{i}"), &[i as u8; 32]))).collect()
}

/// A root over a single leaf is the leaf itself: without that, a one-leaf tree and a tree of two
/// identical leaves would be confused.
#[test]
fn a_leaf_is_its_own_root() {
    let f = leaves(1);
    assert_eq!(root(&f), f[0]);
}

/// **Exhaustive.** Every leaf of every tree up to 33 must produce a proof that rebuilds the root.
#[test]
fn every_inclusion_verifies() {
    for n in 1..=33 {
        let f = leaves(n);
        let r = root(&f);
        for i in 0..n {
            let proof = inclusion_proof(&f, i).unwrap();
            assert_eq!(
                verify_inclusion(&f[i], i, n, &proof, &r),
                Ok(()),
                "tree of {n} leaves, index {i}",
            );
        }
    }
}

/// **Exhaustive.** Every tree extends every smaller tree.
#[test]
fn every_consistency_verifies() {
    for to in 1..=33 {
        let f = leaves(to);
        let new_root = root(&f);
        for from in 1..=to {
            let old_root = root(&f[..from]);
            let proof = consistency_proof(&f, from).unwrap();
            assert_eq!(
                verify_consistency(from, &old_root, to, &new_root, &proof),
                Ok(()),
                "consistency from {from} to {to}",
            );
        }
    }
}

/// **The test that counts.** A log that rewrites an already published entry must not be able to
/// produce a consistency proof — that is the whole difference between an auditable log and a
/// database.
#[test]
fn a_rewritten_log_does_not_pass_consistency() {
    let old = leaves(5);
    let old_root = root(&old);

    // The server replaces the third entry, then appends leaves on top.
    let mut rewritten = old.clone();
    rewritten[2] = leaf_hash(&entry("account2", &[0xFFu8; 32]));
    rewritten.extend(leaves(8).into_iter().skip(5));

    let new_root = root(&rewritten);
    let proof = consistency_proof(&rewritten, 5).unwrap();

    assert_eq!(
        verify_consistency(5, &old_root, rewritten.len(), &new_root, &proof),
        Err(LogError::BadProof),
        "a rewrite produced a valid consistency proof: the log proves nothing",
    );
}

/// An inclusion proof for a leaf that is not there must not pass. This is key substitution on
/// first contact, exactly.
#[test]
fn a_foreign_leaf_does_not_pass() {
    let f = leaves(7);
    let r = root(&f);
    let proof = inclusion_proof(&f, 3).unwrap();

    let intruder = leaf_hash(&entry("account3", &[0xAAu8; 32]));
    assert_eq!(
        verify_inclusion(&intruder, 3, 7, &proof, &r),
        Err(LogError::BadProof),
    );
}

/// Moving a valid proof to another index must not make it valid elsewhere.
#[test]
fn a_proof_only_holds_for_its_own_index() {
    let f = leaves(7);
    let r = root(&f);
    let proof = inclusion_proof(&f, 3).unwrap();

    for other in 0..7 {
        if other == 3 {
            continue;
        }
        assert!(
            verify_inclusion(&f[3], other, 7, &proof, &r).is_err(),
            "the proof for index 3 was accepted at index {other}",
        );
    }
}

/// An over-long proof is rejected rather than ignored: the surplus would be chosen by the
/// attacker.
#[test]
fn an_over_long_proof_is_refused() {
    let f = leaves(4);
    let r = root(&f);
    let mut proof = inclusion_proof(&f, 1).unwrap();
    proof.push([0u8; 32]);

    assert_eq!(verify_inclusion(&f[1], 1, 4, &proof, &r), Err(LogError::BadProof));
}

#[test]
fn a_truncated_proof_is_refused() {
    let f = leaves(8);
    let r = root(&f);
    let mut proof = inclusion_proof(&f, 5).unwrap();
    proof.pop();

    assert_eq!(verify_inclusion(&f[5], 5, 8, &proof, &r), Err(LogError::BadProof));
}

/// **RFC 6962's leaf/node separation.** Without it, the hash of an internal node could be
/// presented as that of a leaf, and an attacker would forge an inclusion proof for an entry of
/// their choosing.
#[test]
fn an_internal_node_cannot_pass_itself_off_as_a_leaf() {
    let f = leaves(2);
    let internal = node_hash(&f[0], &f[1]);

    // The internal node exists in the tree, but as a node — not as a leaf. The contents that
    // would produce that leaf are not computable, and that is precisely the goal.
    assert_ne!(leaf_hash(&[]), internal);
    assert_ne!(root(&f), leaf_hash(&node_bytes(&f[0], &f[1])));
}

fn node_bytes(left: &Hash, right: &Hash) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(left);
    out.extend_from_slice(right);
    out
}

/// Length prefixing, same reason as in `attest`: without it, two distinct entries would produce
/// the same leaf.
#[test]
fn two_different_splits_do_not_collide() {
    assert_ne!(entry("ab", b"c"), entry("a", b"bc"));
}

#[test]
fn an_invalid_range_is_refused() {
    let f = leaves(4);
    assert_eq!(consistency_proof(&f, 0), Err(LogError::BadRange));
    assert_eq!(consistency_proof(&f, 5), Err(LogError::BadRange));
    assert_eq!(inclusion_proof(&f, 4), Err(LogError::OutOfRange));
}

// ------------------------------------------------------------------ signed heads

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

#[test]
fn a_head_signed_by_the_log_is_accepted() {
    let key = SigningKey::generate(&mut OsRng);
    let head = TreeHead { size: 12, root: [7u8; 32], timestamp: 1_700_000_000 };
    let sig = head.sign(&key);

    assert_eq!(head.verify(key.verifying_key().as_bytes(), &sig), Ok(()));
}

/// Every field is covered: altering the size or the root must invalidate the signature.
#[test]
fn every_field_of_the_head_is_covered() {
    let key = SigningKey::generate(&mut OsRng);
    let head = TreeHead { size: 12, root: [7u8; 32], timestamp: 1_700_000_000 };
    let sig = head.sign(&key);
    let pk = key.verifying_key();
    let pk = pk.as_bytes();

    for altered in [
        TreeHead { size: 13, ..head },
        TreeHead { root: [8u8; 32], ..head },
        TreeHead { timestamp: 1_600_000_000, ..head },
    ] {
        assert_eq!(altered.verify(pk, &sig), Err(LogError::BadSignature));
    }
}

/// A third party cannot forge a head: otherwise anyone would publish a fake log.
#[test]
fn a_third_party_cannot_sign_a_head() {
    let log = SigningKey::generate(&mut OsRng);
    let intruder = SigningKey::generate(&mut OsRng);
    let head = TreeHead { size: 12, root: [7u8; 32], timestamp: 1_700_000_000 };

    assert_eq!(
        head.verify(log.verifying_key().as_bytes(), &head.sign(&intruder)),
        Err(LogError::BadSignature),
    );
}
