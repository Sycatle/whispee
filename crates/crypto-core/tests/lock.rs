//! The lock is what separates state encrypted at rest from state readable by anyone who gets
//! hold of the disk. These tests freeze its behaviour.

use crypto_core::lock::{SALT_LEN, derive_unlock_key};

const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];

#[test]
fn the_derivation_is_deterministic() {
    let a = derive_unlock_key("a sufficiently long password", &SALT).unwrap();
    let b = derive_unlock_key("a sufficiently long password", &SALT).unwrap();
    assert_eq!(a, b);
}

#[test]
fn two_passwords_yield_different_keys() {
    let a = derive_unlock_key("a sufficiently long password", &SALT).unwrap();
    let b = derive_unlock_key("a sufficiently long passphrase", &SALT).unwrap();
    assert_ne!(a, b);
}

/// The salt rules out precomputed tables: the same password on two devices must not produce the
/// same key, otherwise breaking one amounts to breaking all the others.
#[test]
fn the_salt_separates_devices() {
    let a = derive_unlock_key("a sufficiently long password", &SALT).unwrap();
    let b = derive_unlock_key("a sufficiently long password", &[9u8; SALT_LEN]).unwrap();
    assert_ne!(a, b);
}

#[test]
fn a_salt_of_the_wrong_size_is_rejected() {
    assert!(derive_unlock_key("does not matter", &[0u8; 8]).is_err());
}

/// Non-regression on the parameters.
///
/// This is not a conformance vector — it is a guard rail. If this test breaks, the derivation
/// cost changed and **every existing encrypted state becomes unreadable**: its key will no
/// longer be the same. Lowering these parameters silently weakens every device already
/// deployed; raising them breaks unlocking. Both deserve an explicit decision, not an
/// absent-minded update of this test.
#[test]
fn the_parameters_are_frozen() {
    // The password stays as it is: it is the input of a frozen vector, not prose.
    let key = derive_unlock_key("mot de passe de reference", &SALT).unwrap();
    assert_eq!(hex::encode(key), "593cf6a8b414b58943847e366561d9a4004a8da42869d0c549a9bb4ffe1a9dcc");
}
