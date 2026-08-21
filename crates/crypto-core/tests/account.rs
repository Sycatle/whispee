//! The account is the root of trust for the whole multi-device story. These tests freeze its
//! derivation and check that it cannot sign on anyone else's behalf.

use crypto_core::Account;

/// Public, well-known test phrase. **Never use it anywhere but here.**
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn the_same_phrase_yields_the_same_account() {
    let a = Account::from_phrase(PHRASE).unwrap();
    let b = Account::from_phrase(PHRASE).unwrap();

    assert_eq!(a.identity_key(), b.identity_key());
    assert_eq!(a.fingerprint(), b.fingerprint());
}

/// Non-regression on the derivation format.
///
/// This is **not** a conformance vector: there is no standard for deriving a messaging identity
/// key from a BIP-39 seed. It is a guard rail: if this test breaks, the derivation changed and
/// every existing account has become unrecoverable from its phrase. That is a format change to
/// own explicitly, never a test to update absent-mindedly.
#[test]
fn the_derivation_is_frozen() {
    let account = Account::from_phrase(PHRASE).unwrap();
    let key = hex::encode(account.identity_key());

    assert_eq!(key, "001cb5f77239887d8bffef1f23ecb9ff237c730419b0104fc19affe61be83acc");
}

/// The vault key must be independent of the identity key: compromising one must teach nothing
/// about the other. That is what the separate HKDF `info` strings guarantee.
#[test]
fn the_vault_key_is_distinct_from_the_identity_key() {
    let account = Account::from_phrase(PHRASE).unwrap();
    assert_ne!(account.vault_key(), account.identity_key());
}

#[test]
fn two_generated_accounts_are_different() {
    let (a, phrase_a) = Account::generate().unwrap();
    let (b, phrase_b) = Account::generate().unwrap();

    assert_ne!(a.identity_key(), b.identity_key());
    assert_ne!(phrase_a, phrase_b);
    assert_eq!(phrase_a.split_whitespace().count(), crypto_core::account::PHRASE_WORDS);
}

#[test]
fn the_generated_phrase_rebuilds_the_same_account() {
    let (account, phrase) = Account::generate().unwrap();
    let restored = Account::from_phrase(&phrase).unwrap();

    assert_eq!(account.identity_key(), restored.identity_key());
}

/// The BIP-39 checksum catches a mistyped word. Without it the user would get a different
/// account, perfectly valid and perfectly empty — the worst possible error message.
#[test]
fn a_mistyped_word_is_rejected() {
    let typo = PHRASE.replace("about", "abandon");
    assert!(Account::from_phrase(&typo).is_err());
}

#[test]
fn a_phrase_that_is_too_short_is_rejected() {
    assert!(Account::from_phrase("abandon abandon abandon").is_err());
}

/// Stray whitespace comes from a copy-paste, not from an attack. Tolerating it avoids an
/// incomprehensible failure on an otherwise correct phrase.
#[test]
fn stray_whitespace_is_tolerated() {
    let account = Account::from_phrase(&format!("  {PHRASE}\n")).unwrap();
    assert_eq!(account.identity_key(), Account::from_phrase(PHRASE).unwrap().identity_key());
}

#[test]
fn the_account_attests_its_own_devices() {
    let account = Account::from_phrase(PHRASE).unwrap();
    let auth_key = [1u8; 32];
    let mls_key = [2u8; 32];

    let signature = account.attest("alice", "phone", &auth_key, &mls_key).unwrap();
    let claim = attest::DeviceClaim {
        account: "alice",
        device_id: "phone",
        auth_key: &auth_key,
        mls_key: &mls_key,
    };

    assert!(attest::verify(&account.identity_key(), &claim, &signature).is_ok());
}

/// An account cannot attest for another handle: the attestation it produces only verifies under
/// its own handle.
#[test]
fn an_account_cannot_attest_for_another_handle() {
    let account = Account::from_phrase(PHRASE).unwrap();
    let signature = account.attest("alice", "phone", &[1u8; 32], &[2u8; 32]).unwrap();

    let impersonated = attest::DeviceClaim {
        account: "bob",
        device_id: "phone",
        auth_key: &[1u8; 32],
        mls_key: &[2u8; 32],
    };

    assert!(attest::verify(&account.identity_key(), &impersonated, &signature).is_err());
}

/// Pairing transfers the seed, not the phrase: the paired device must get exactly the same
/// power, including the power to attest in turn.
#[test]
fn the_transferred_seed_rebuilds_an_equivalent_account() {
    let source = Account::from_phrase(PHRASE).unwrap();
    let paired = Account::from_seed(source.export_seed());

    assert_eq!(source.identity_key(), paired.identity_key());
    assert_eq!(source.vault_key(), paired.vault_key());

    let signature = paired.attest("alice", "tablet", &[3u8; 32], &[4u8; 32]).unwrap();
    let claim = attest::DeviceClaim {
        account: "alice",
        device_id: "tablet",
        auth_key: &[3u8; 32],
        mls_key: &[4u8; 32],
    };
    assert!(attest::verify(&source.identity_key(), &claim, &signature).is_ok());
}

/// `Debug` must never leak the private key into a log.
#[test]
fn debug_does_not_disclose_the_secret() {
    let account = Account::from_phrase(PHRASE).unwrap();
    let rendered = format!("{account:?}");

    assert!(rendered.contains(&account.fingerprint()));
    assert!(!rendered.contains(&hex::encode(account.export_seed())));
}

/// The revocation certificate produced by the account must be verifiable by a third party that
/// only holds the public key — that is its whole point: letting another group member commit the
/// removal without trusting the server.
#[test]
fn a_revocation_certificate_is_verifiable_by_a_third_party() {
    let (account, _) = Account::generate().unwrap();
    let certificate = account.revoke("alice", "alice:phone", 1_700_000_000).unwrap();

    let claim =
        attest::RevocationClaim { account: "alice", device_id: "alice:phone", revoked_at: 1_700_000_000 };

    assert!(attest::verify_revocation(&account.identity_key(), &claim, &certificate).is_ok());
}

/// An account only revokes its own devices. Without that property, revoking would amount to
/// being able to evict anyone from the network.
#[test]
fn an_account_cannot_revoke_for_another_handle() {
    let (alice, _) = Account::generate().unwrap();
    let (bob, _) = Account::generate().unwrap();

    let certificate = alice.revoke("bob", "bob:phone", 1_700_000_000).unwrap();
    let claim =
        attest::RevocationClaim { account: "bob", device_id: "bob:phone", revoked_at: 1_700_000_000 };

    // Signed by Alice, hence invalid under Bob's key: the server and the other clients alike
    // verify against the key of the account *named* in the certificate.
    assert!(attest::verify_revocation(&bob.identity_key(), &claim, &certificate).is_err());
}
