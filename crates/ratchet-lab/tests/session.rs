//! End-to-end tests of a session: establishment, conversation, desynchronisation.

mod common;

use common::TestRng;
use ratchet_lab::{IdentityKeyPair, PreKeyStore, RatchetError, Session, safety_number};

/// Sets up a ready-to-use Alice → Bob session.
fn pair(with_one_time: bool) -> (TestRng, Session, Session, PreKeyStore) {
    let mut rng = TestRng::seed("session");
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let bob_store = PreKeyStore::generate(&mut rng, with_one_time);

    let (alice, initial) =
        Session::initiate(&mut rng, &alice_identity, &bob_store.bundle()).expect("valid bundle");
    let bob = Session::accept(&bob_store, &initial).expect("X3DH replayed");

    (rng, alice, bob, bob_store)
}

#[test]
fn first_message_in_both_directions() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let msg = alice.encrypt("hi Bob".as_bytes()).unwrap();
    assert_eq!(bob.decrypt(&mut rng, &msg).unwrap(), "hi Bob".as_bytes());

    // Bob can only reply after receiving: it is his first reception that gives him a sending
    // chain.
    let reply = bob.encrypt("hi Alice".as_bytes()).unwrap();
    assert_eq!(alice.decrypt(&mut rng, &reply).unwrap(), "hi Alice".as_bytes());
}

#[test]
fn bob_cannot_write_before_receiving() {
    let (_, _, mut bob, _) = pair(true);
    assert_eq!(bob.encrypt("too early".as_bytes()).unwrap_err(), RatchetError::NoSession);
}

#[test]
fn session_without_one_time_prekey() {
    // A real case: Bob's stock of one-time prekeys is exhausted. The session must still be
    // established, with slightly degraded forward secrecy on the first message.
    let (mut rng, mut alice, mut bob, _) = pair(false);
    let msg = alice.encrypt("stock exhausted".as_bytes()).unwrap();
    assert_eq!(bob.decrypt(&mut rng, &msg).unwrap(), "stock exhausted".as_bytes());
}

#[test]
fn an_alternating_conversation_turns_the_dh_ratchet() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let mut previous = alice.encrypt("round 0".as_bytes()).unwrap().header.dh;
    bob.decrypt(&mut rng, &alice.encrypt("bootstrap".as_bytes()).unwrap()).ok();

    for round in 0..10u32 {
        let from_alice = alice.encrypt(format!("A{round}").as_bytes()).unwrap();
        assert_eq!(bob.decrypt(&mut rng, &from_alice).unwrap(), format!("A{round}").as_bytes());

        let from_bob = bob.encrypt(format!("B{round}").as_bytes()).unwrap();
        // Every change of direction must produce a new ratchet key: that is exactly what
        // gives post-compromise security.
        assert_ne!(from_bob.header.dh.as_bytes(), previous.as_bytes());
        previous = from_bob.header.dh;

        assert_eq!(alice.decrypt(&mut rng, &from_bob).unwrap(), format!("B{round}").as_bytes());
    }
}

#[test]
fn out_of_order_messages() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let m0 = alice.encrypt("zero".as_bytes()).unwrap();
    let m1 = alice.encrypt("one".as_bytes()).unwrap();
    let m2 = alice.encrypt("two".as_bytes()).unwrap();

    // The network delivers them backwards.
    assert_eq!(bob.decrypt(&mut rng, &m2).unwrap(), "two".as_bytes());
    assert_eq!(bob.skipped_count(), 2, "the keys of m0 and m1 must be set aside");

    assert_eq!(bob.decrypt(&mut rng, &m0).unwrap(), "zero".as_bytes());
    assert_eq!(bob.decrypt(&mut rng, &m1).unwrap(), "one".as_bytes());
    assert_eq!(bob.skipped_count(), 0, "every pending key must be consumed");
}

#[test]
fn a_permanently_lost_message_does_not_block_what_follows() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let _lost = alice.encrypt("never delivered".as_bytes()).unwrap();
    let next_one = alice.encrypt("this one arrives".as_bytes()).unwrap();

    assert_eq!(bob.decrypt(&mut rng, &next_one).unwrap(), "this one arrives".as_bytes());
    // The lost message's key stays pending indefinitely. That is the Double Ratchet's
    // trade-off: robustness to the network is paid for in live keys kept in memory.
    assert_eq!(bob.skipped_count(), 1);
}

#[test]
fn a_replay_is_refused() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let msg = alice.encrypt("only once".as_bytes()).unwrap();
    assert_eq!(bob.decrypt(&mut rng, &msg).unwrap(), "only once".as_bytes());

    // The key was consumed and then destroyed: the same ciphertext must never pass again.
    assert_eq!(
        bob.decrypt(&mut rng, &msg).unwrap_err(),
        RatchetError::MessageKeyGone
    );
}

#[test]
fn an_excessive_skip_is_refused() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let mut msg = alice.encrypt("payload".as_bytes()).unwrap();
    // A malicious peer announces an absurd index to force the allocation of billions of keys.
    // The MAX_SKIP cap must cut it off.
    msg.header.n = 500_000;

    assert!(matches!(
        bob.decrypt(&mut rng, &msg).unwrap_err(),
        RatchetError::TooManySkipped(_, _)
    ));
}

#[test]
fn an_altered_header_is_rejected() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let m0 = alice.encrypt("zero".as_bytes()).unwrap();
    let mut m1 = alice.encrypt("one".as_bytes()).unwrap();
    bob.decrypt(&mut rng, &m0).unwrap();

    // The header is in the clear but authenticated by the AEAD: modifying it must break
    // decryption, not produce a different text.
    m1.header.pn = m1.header.pn.wrapping_add(1);
    assert_eq!(
        bob.decrypt(&mut rng, &m1).unwrap_err(),
        RatchetError::DecryptionFailed
    );
}

#[test]
fn an_altered_ciphertext_is_rejected() {
    let (mut rng, mut alice, mut bob, _) = pair(true);

    let mut msg = alice.encrypt("intact".as_bytes()).unwrap();
    msg.ciphertext[0] ^= 0x01;
    assert_eq!(
        bob.decrypt(&mut rng, &msg).unwrap_err(),
        RatchetError::DecryptionFailed
    );
}

#[test]
fn a_badly_signed_bundle_is_refused() {
    let mut rng = TestRng::seed("mitm");
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let bob_store = PreKeyStore::generate(&mut rng, true);
    let attacker = PreKeyStore::generate(&mut rng, true);

    // The server swaps Bob's signed prekey for an attacker's, keeping Bob's identity. The
    // signature no longer matches.
    let mut bundle = bob_store.bundle();
    bundle.signed_prekey = attacker.signed_prekey.public();

    assert_eq!(
        Session::initiate(&mut rng, &alice_identity, &bundle).unwrap_err(),
        RatchetError::BadPreKeySignature
    );
}

#[test]
fn the_safety_number_is_identical_on_both_sides() {
    let mut rng = TestRng::seed("fingerprint");
    let alice = IdentityKeyPair::generate(&mut rng).public();
    let bob = IdentityKeyPair::generate(&mut rng).public();

    // Both screens must show the same string, otherwise the out-of-band comparison is
    // impossible.
    assert_eq!(safety_number(&alice, &bob), safety_number(&bob, &alice));
    assert_eq!(safety_number(&alice, &bob).chars().filter(|c| c.is_ascii_digit()).count(), 60);
}

#[test]
fn the_safety_number_changes_if_the_identity_changes() {
    let mut rng = TestRng::seed("fingerprint-mitm");
    let alice = IdentityKeyPair::generate(&mut rng).public();
    let bob = IdentityKeyPair::generate(&mut rng).public();
    let attacker = IdentityKeyPair::generate(&mut rng).public();

    // This is the property that makes verification useful: if the server substitutes an
    // identity, the displayed fingerprint differs and the out-of-band comparison reveals it.
    assert_ne!(safety_number(&alice, &bob), safety_number(&alice, &attacker));
}
