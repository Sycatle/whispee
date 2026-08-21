//! The canonical format is the one place in the project where a serialisation mistake becomes an
//! authentication flaw. These tests pin it down.

use attest::{AttestError, DeviceClaim, message, verify};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;

fn claim<'a>(handle: &'a str, device_id: &'a str) -> DeviceClaim<'a> {
    DeviceClaim { account: handle, device_id, auth_key: &[7u8; 32], mls_key: &[9u8; 32] }
}

fn account() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

#[test]
fn an_attestation_produced_by_the_account_is_accepted() {
    let key = account();
    let claim = claim("alice", "laptop");
    let signature = key.sign(&message(&claim).unwrap());

    assert!(verify(key.verifying_key().as_bytes(), &claim, &signature.to_bytes()).is_ok());
}

#[test]
fn another_account_cannot_attest_in_our_place() {
    let legitimate = account();
    let impostor = account();
    let claim = claim("alice", "laptop");

    let signature = impostor.sign(&message(&claim).unwrap());

    assert_eq!(
        verify(legitimate.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// The heart of the matter: an attestation obtained for one device must not hold for another.
/// That is what prevents recycling the attestation of a revoked legitimate device.
#[test]
fn an_attestation_only_holds_for_its_own_device() {
    let key = account();
    let signature = key.sign(&message(&claim("alice", "laptop")).unwrap());

    assert_eq!(
        verify(key.verifying_key().as_bytes(), &claim("alice", "tablet"), &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// An attestation for Alice's account must not hold in Bob's account, even if the device is the
/// same. Without that, Bob attaches one of Alice's devices to his own account.
#[test]
fn an_attestation_only_holds_for_its_own_account() {
    let key = account();
    let signature = key.sign(&message(&claim("alice", "laptop")).unwrap());

    assert_eq!(
        verify(key.verifying_key().as_bytes(), &claim("bob", "laptop"), &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// The whole point of the length prefixes.
///
/// Concatenated without prefixes, `("ab", "c")` and `("a", "bc")` give the same bytes: an
/// attestation obtained for one would be valid for the other. An attacker choosing their handle
/// and device identifier can manufacture such a collision at will.
#[test]
fn two_different_splits_do_not_collide() {
    assert_ne!(
        message(&claim("ab", "c")).unwrap(),
        message(&claim("a", "bc")).unwrap(),
    );
}

/// Both keys are attested together. Treating them separately would allow combining the
/// authentication key of a legitimate device with the MLS key of a hostile one.
#[test]
fn substituting_the_mls_key_invalidates_the_attestation() {
    let key = account();
    let original = claim("alice", "laptop");
    let signature = key.sign(&message(&original).unwrap());

    let substituted = DeviceClaim { mls_key: &[0xff; 32], ..original };

    assert_eq!(
        verify(key.verifying_key().as_bytes(), &substituted, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

#[test]
fn a_truncated_signature_is_rejected_without_panicking() {
    let key = account();
    let claim = claim("alice", "laptop");
    let signature = key.sign(&message(&claim).unwrap());

    assert_eq!(
        verify(key.verifying_key().as_bytes(), &claim, &signature.to_bytes()[..63]),
        Err(AttestError::BadSignature),
    );
}

#[test]
fn a_wrongly_sized_identity_key_is_rejected_without_panicking() {
    let claim = claim("alice", "laptop");
    assert_eq!(verify(&[0u8; 31], &claim, &[0u8; 64]), Err(AttestError::BadIdentityKey));
}

/// The fingerprint does not move when the account gains a device: that is what avoids asking for
/// an out-of-band check again after every legitimate event.
#[test]
fn the_fingerprint_depends_only_on_the_account_key() {
    let key = account();
    let a = attest::fingerprint(key.verifying_key().as_bytes());
    let b = attest::fingerprint(key.verifying_key().as_bytes());

    assert_eq!(a, b);
    assert_ne!(a, attest::fingerprint(account().verifying_key().as_bytes()));
}

// ---------------------------------------------------------------------------------------
// Revocation certificates
// ---------------------------------------------------------------------------------------

use attest::{RevocationClaim, revocation_message, verify_revocation};

fn revocation<'a>(handle: &'a str, device_id: &'a str, revoked_at: u64) -> RevocationClaim<'a> {
    RevocationClaim { account: handle, device_id, revoked_at }
}

#[test]
fn a_revocation_certificate_produced_by_the_account_is_accepted() {
    let key = account();
    let claim = revocation("alice", "alice:laptop", 1_700_000_000);
    let signature = key.sign(&revocation_message(&claim).unwrap());

    assert_eq!(
        verify_revocation(key.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Ok(()),
    );
}

/// Otherwise any account could get anyone's devices evicted.
#[test]
fn another_account_cannot_revoke_in_our_place() {
    let victim = account();
    let attacker = account();
    let claim = revocation("alice", "alice:laptop", 1_700_000_000);
    let signature = attacker.sign(&revocation_message(&claim).unwrap());

    assert_eq!(
        verify_revocation(victim.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// A certificate only holds for the device it names: otherwise revoking one's own old phone
/// would allow evicting any of one's other devices.
#[test]
fn a_certificate_only_holds_for_its_own_device() {
    let key = account();
    let issued = revocation("alice", "alice:laptop", 1_700_000_000);
    let signature = key.sign(&revocation_message(&issued).unwrap());

    let other = revocation("alice", "alice:desktop", 1_700_000_000);
    assert_eq!(
        verify_revocation(key.verifying_key().as_bytes(), &other, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// The timestamp is covered by the signature. A server able to change it would backdate a genuine
/// revocation to pretend a device was already excluded when it legitimately received a message.
#[test]
fn the_timestamp_is_covered_by_the_signature() {
    let key = account();
    let issued = revocation("alice", "alice:laptop", 1_700_000_000);
    let signature = key.sign(&revocation_message(&issued).unwrap());

    let backdated = revocation("alice", "alice:laptop", 1_600_000_000);
    assert_eq!(
        verify_revocation(key.verifying_key().as_bytes(), &backdated, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// **The test that justifies domain separation.**
///
/// Without a distinct label, a device attestation — which everyone holds, since the server serves
/// it publicly — could be presented as a revocation certificate for the same device. Anyone could
/// then get any device on the network evicted.
#[test]
fn an_attestation_cannot_be_replayed_as_a_revocation() {
    let key = account();
    let device = claim("alice", "alice:laptop");
    let attestation = key.sign(&message(&device).unwrap());

    // Every possible timestamp value fails; we test one, the structure of the message explains
    // the rest: the domain bytes differ from the very first one.
    let as_revocation = revocation("alice", "alice:laptop", 1_700_000_000);
    assert_eq!(
        verify_revocation(
            key.verifying_key().as_bytes(),
            &as_revocation,
            &attestation.to_bytes(),
        ),
        Err(AttestError::BadSignature),
    );

    // And the converse: a revocation certificate is not an attestation.
    let certificate = key.sign(&revocation_message(&as_revocation).unwrap());
    assert_eq!(
        verify(key.verifying_key().as_bytes(), &device, &certificate.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// Same reason as for the attestation: `("ab", "c")` and `("a", "bc")` must differ.
#[test]
fn two_different_splits_do_not_collide_in_revocation() {
    assert_ne!(
        revocation_message(&revocation("ab", "c", 1)).unwrap(),
        revocation_message(&revocation("a", "bc", 1)).unwrap(),
    );
}

// ---------------------------------------------------------------------------------------
// Account rotation
// ---------------------------------------------------------------------------------------

use attest::{RotationClaim, rotation_message, verify_rotation};

fn rotation<'a>(handle: &'a str, new_key: &'a [u8], at: u64) -> RotationClaim<'a> {
    RotationClaim { account: handle, new_identity_key: new_key, rotated_at: at }
}

/// A rotation is verified against the **old** key: it is the one designating the new one.
#[test]
fn a_rotation_is_verified_against_the_old_key() {
    let old = account();
    let new_one = account();
    let new_pub = new_one.verifying_key().to_bytes();

    let claim = rotation("alice", &new_pub, 1_700_000_000);
    let signature = old.sign(&rotation_message(&claim).unwrap());

    assert_eq!(
        verify_rotation(old.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Ok(()),
    );

    // Verifying against the new key would only prove possession of it, that is, nothing.
    assert_eq!(
        verify_rotation(&new_pub, &claim, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// Without proven continuity, anyone would take over someone else's handle.
#[test]
fn a_third_party_cannot_rotate_an_account() {
    let victim = account();
    let attacker = account();
    let target = account().verifying_key().to_bytes();

    let claim = rotation("alice", &target, 1_700_000_000);
    let signature = attacker.sign(&rotation_message(&claim).unwrap());

    assert_eq!(
        verify_rotation(victim.verifying_key().as_bytes(), &claim, &signature.to_bytes()),
        Err(AttestError::BadSignature),
    );
}

/// The incoming key is covered by the signature: substituting it would allow diverting a
/// legitimate rotation towards a key chosen by the attacker.
#[test]
fn substituting_the_incoming_key_invalidates_the_rotation() {
    let old = account();
    let intended = account().verifying_key().to_bytes();
    let substituted = account().verifying_key().to_bytes();

    let claim = rotation("alice", &intended, 1_700_000_000);
    let signature = old.sign(&rotation_message(&claim).unwrap());

    assert_eq!(
        verify_rotation(
            old.verifying_key().as_bytes(),
            &rotation("alice", &substituted, 1_700_000_000),
            &signature.to_bytes(),
        ),
        Err(AttestError::BadSignature),
    );
}

/// **The three domains are pairwise watertight.** A revocation signature that also held as a
/// rotation would let anyone who saw a revocation go by take over the account.
#[test]
fn the_three_domains_do_not_overlap() {
    let key = account();
    let target = [3u8; 32];

    let device = claim("alice", "alice:laptop");
    let revoc = revocation("alice", "alice:laptop", 1_700_000_000);
    let rot = rotation("alice", &target, 1_700_000_000);

    let sig_attest = key.sign(&message(&device).unwrap()).to_bytes();
    let sig_revoc = key.sign(&revocation_message(&revoc).unwrap()).to_bytes();
    let sig_rot = key.sign(&rotation_message(&rot).unwrap()).to_bytes();

    let pk = key.verifying_key();
    let pk = pk.as_bytes();

    // Each signature only holds in its own domain.
    assert!(verify(pk, &device, &sig_attest).is_ok());
    assert!(verify(pk, &device, &sig_revoc).is_err());
    assert!(verify(pk, &device, &sig_rot).is_err());

    assert!(verify_revocation(pk, &revoc, &sig_revoc).is_ok());
    assert!(verify_revocation(pk, &revoc, &sig_attest).is_err());
    assert!(verify_revocation(pk, &revoc, &sig_rot).is_err());

    assert!(verify_rotation(pk, &rot, &sig_rot).is_ok());
    assert!(verify_rotation(pk, &rot, &sig_attest).is_err());
    assert!(verify_rotation(pk, &rot, &sig_revoc).is_err());
}

use attest::{post_message, signal_message};

/// The MAC of an ephemeral signal is not replayable as an envelope post.
///
/// Signals deliberately have no replay protection — a stale typing indicator has no effect. That
/// exemption must not extend to envelopes, which are kept.
#[test]
fn a_signal_is_not_a_post() {
    let group_id = b"group";
    let nonce = [7u8; 16];
    let digest = [9u8; 32];

    let post = post_message(group_id, &nonce, &digest).unwrap();
    let signal = signal_message(group_id, &nonce, &digest).unwrap();

    assert_ne!(post, signal, "same key, same fields: only the domain separates them");
}

use attest::gateway_message;

/// **The test that justifies the gateway domain.**
///
/// A gateway session is authenticated by the device's authentication key — the same one that
/// signs HTTP requests. Without its own domain, capturing the signature of any `GET` would be
/// enough to open a session on behalf of its author, and the challenge issued by the server would
/// be pointless.
#[test]
fn a_session_opening_holds_in_no_other_domain() {
    let nonce = [3u8; 32];
    let opening = gateway_message("device-a", &nonce).unwrap();

    // The same fields, presented in the other domains.
    assert_ne!(opening, post_message(b"device-a", &nonce, &[]).unwrap());
    assert_ne!(opening, signal_message(b"device-a", &nonce, &[]).unwrap());
}

/// A challenge only holds for the device it was served to.
///
/// Without the identifier in the signed message, a nonce served to Alice could be returned along
/// with a signature of Bob's captured elsewhere.
#[test]
fn a_challenge_only_holds_for_its_own_device() {
    let nonce = [3u8; 32];

    assert_ne!(
        gateway_message("device-a", &nonce).unwrap(),
        gateway_message("device-b", &nonce).unwrap(),
    );
}

/// Two different splits must not produce the same bytes — otherwise a signature obtained for one
/// would hold for the other.
#[test]
fn two_different_splits_do_not_collide_in_gateway() {
    assert_ne!(gateway_message("ab", b"cd").unwrap(), gateway_message("abc", b"d").unwrap());
}

// ---------------------------------------------------------------------------
// Account ids
// ---------------------------------------------------------------------------

#[test]
fn an_id_is_thirty_two_lowercase_hex_characters() {
    let id = attest::account_id(&[3u8; 32]);
    assert_eq!(id.len(), attest::ID_HEX_LEN);
    assert!(attest::is_account_id(&id));
    assert_eq!(id, id.to_lowercase());
}

#[test]
fn an_id_follows_the_key_it_was_derived_from() {
    assert_ne!(attest::account_id(&[3u8; 32]), attest::account_id(&[4u8; 32]));
    // Stable across calls: it keys database rows and lives in credentials.
    assert_eq!(attest::account_id(&[3u8; 32]), attest::account_id(&[3u8; 32]));
}

#[test]
fn a_handle_shaped_string_is_not_an_id() {
    // The confusion the v2 domain bump exists for. `bob` is a legal handle and not an id; a
    // thirty-two character hex string is both, which is why the shape check alone was never
    // going to be the defence.
    assert!(!attest::is_account_id("bob"));
    assert!(!attest::is_account_id(""));
    // Uppercase is refused rather than folded: one representation, so two rows cannot disagree.
    assert!(!attest::is_account_id(&"AB".repeat(16)));
    // A hex string of the right length is accepted, and that is the point of the domain bump.
    assert!(attest::is_account_id(&"ab".repeat(16)));
}

#[test]
fn the_short_form_is_half_the_id_grouped_in_fours() {
    let id = attest::account_id(&[3u8; 32]);
    let short = attest::short_id(&id);

    assert_eq!(short.replace(' ', ""), id[..attest::ID_SHORT_HEX_LEN]);
    assert_eq!(short.split(' ').count(), attest::ID_SHORT_HEX_LEN / 4);
    // 64 bits inline. The number is a decision, not an accident — see the constant.
    assert_eq!(attest::ID_SHORT_HEX_LEN * 4, 64);
}

#[test]
fn shortening_something_that_is_not_an_id_changes_nothing() {
    // A caller must not be able to launder a malformed value into a plausible-looking one.
    assert_eq!(attest::short_id("bob"), "bob");
}

#[test]
fn the_claims_carry_the_second_version_of_their_domain() {
    // Field zero used to be a handle and is now an account id, and the two are not
    // distinguishable by shape — a thirty-two character handle is legal and reads as an id. The
    // label is therefore the only thing standing between an old signature and a new meaning, so
    // it is pinned here rather than left to a reviewer to notice.
    let device = attest::message(&claim("bob", "bob:desktop")).unwrap();
    assert!(device.starts_with(b"wac-attest-v2"));

    let revocation =
        attest::revocation_message(&attest::RevocationClaim {
            account: "bob",
            device_id: "bob:desktop",
            revoked_at: 1,
        })
        .unwrap();
    assert!(revocation.starts_with(b"wac-revoke-v2"));

    let rotation = attest::rotation_message(&attest::RotationClaim {
        account: "bob",
        new_identity_key: &[1u8; 32],
        rotated_at: 1,
    })
    .unwrap();
    assert!(rotation.starts_with(b"wac-rotate-v2"));
}
