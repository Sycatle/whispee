//! Full life cycle of a 1-to-1 conversation: publication, invitation, exchange, persistence.

use crypto_core::{Conversation, Identity, Incoming, fingerprint};

/// Stands up a two-member conversation the way the real flow would: Bob publishes a KeyPackage,
/// Alice creates the group and invites him, Bob joins through the Welcome.
fn two_member_conversation() -> (Identity, Identity, Conversation, Conversation) {
    let alice = Identity::create("alice@device-1").unwrap();
    let bob = Identity::create("bob@device-1").unwrap();

    let bob_key_package = bob.publish_key_package().unwrap();

    let mut alice_group = Conversation::create(&alice).unwrap();
    let invitation = alice_group.invite(&alice, &bob_key_package).unwrap();
    let tree = alice_group.apply_pending(&alice).unwrap();

    let bob_group =
        Conversation::join(&bob, &invitation.welcome, &tree).unwrap();

    (alice, bob, alice_group, bob_group)
}

#[test]
fn full_1_to_1_cycle() {
    let (alice, bob, mut alice_group, mut bob_group) = two_member_conversation();

    assert_eq!(alice_group.member_count(), 2);
    assert_eq!(bob_group.member_count(), 2);
    // Both must sit at the same epoch, otherwise nothing decrypts.
    assert_eq!(alice_group.epoch(), bob_group.epoch());
    assert_eq!(alice_group.id(), bob_group.id());

    let ciphertext = alice_group.encrypt(&alice, b"hi Bob").unwrap();
    match bob_group.process(&bob, &ciphertext, &Default::default()).unwrap() {
        Incoming::Application { sender, plaintext } => {
            assert_eq!(plaintext, b"hi Bob");
            assert_eq!(sender.as_deref(), Some("alice@device-1"));
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    let reply = bob_group.encrypt(&bob, b"hi Alice").unwrap();
    match alice_group.process(&alice, &reply, &Default::default()).unwrap() {
        Incoming::Application { sender, plaintext } => {
            assert_eq!(plaintext, b"hi Alice");
            assert_eq!(sender.as_deref(), Some("bob@device-1"));
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[test]
fn the_transport_sees_nothing() {
    // This is *the* test that matters: the blob that travels must carry no trace of the
    // plaintext. Everything else in the protocol is only worth something if this one passes.
    let (alice, _bob, mut alice_group, _bob_group) = two_member_conversation();

    let secret = b"the vault code is 4815162342";
    let ciphertext = alice_group.encrypt(&alice, secret).unwrap();

    assert!(
        !ciphertext.windows(secret.len()).any(|w| w == secret),
        "the plaintext appears in the transported message"
    );
    assert!(
        !ciphertext.windows(5).any(|w| w == b"alice"),
        "the sender identity appears in the clear in the message"
    );
}

/// OpenMLS 0.8.1 runs a `debug_assert!(false)` before returning the decryption error
/// (`framing/private_message_in.rs:136`). In a debug build a tampered message therefore
/// **panics** the process instead of being rejected — a trivial remote denial of service for
/// anyone able to flip a byte in transit.
///
/// In release, `debug_assert!` disappears and the error propagates correctly. The test is thus
/// only checked in release. **Operational consequence: never deploy a debug build of this
/// code**, and treat that constraint as a CI invariant.
#[test]
#[cfg_attr(debug_assertions, ignore = "OpenMLS panics through debug_assert!; run with --release")]
fn tampered_ciphertext_is_rejected() {
    let (alice, bob, mut alice_group, mut bob_group) = two_member_conversation();

    let mut ciphertext = alice_group.encrypt(&alice, "intact".as_bytes()).unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(bob_group.process(&bob, &ciphertext, &Default::default()).is_err());
}

#[test]
fn replay_is_rejected() {
    let (alice, bob, mut alice_group, mut bob_group) = two_member_conversation();

    let ciphertext = alice_group.encrypt(&alice, b"once only").unwrap();
    assert!(bob_group.process(&bob, &ciphertext, &Default::default()).is_ok());

    // The message key has been consumed: the same ciphertext must not go through again.
    assert!(bob_group.process(&bob, &ciphertext, &Default::default()).is_err());
}

#[test]
fn cross_fingerprints_are_consistent() {
    let (alice, bob, alice_group, bob_group) = two_member_conversation();

    let alice_view = alice_group.peer_fingerprints(&alice);
    let bob_view = bob_group.peer_fingerprints(&bob);

    assert_eq!(alice_view.len(), 1);
    assert_eq!(bob_view.len(), 1);
    assert_eq!(alice_view[0].0, "bob@device-1");
    assert_eq!(bob_view[0].0, "alice@device-1");

    // Each must see the other's real fingerprint: that is what makes the out-of-band comparison
    // able to detect a substitution by the server.
    assert_eq!(alice_view[0].1, fingerprint(bob.signature_key()));
    assert_eq!(bob_view[0].1, fingerprint(alice.signature_key()));
    assert_ne!(alice_view[0].1, bob_view[0].1);
}

/// Not reusing KeyPackages is the **server's** responsibility, not the library's: OpenMLS is
/// happy to reuse the same KeyPackage for two groups.
///
/// A KeyPackage init key is nevertheless single-use. Serving it twice makes two distinct groups
/// share the same entry secret, which destroys the forward secrecy of the add. The server must
/// therefore take each KeyPackage out of the stock as soon as it is served, and report when a
/// device's stock runs out.
///
/// This test locks that requirement in: if it starts failing, some OpenMLS version has begun
/// refusing reuse — good news, but the server-side constraint stays necessary for earlier
/// versions.
#[test]
fn key_package_reuse_must_be_prevented_by_the_server() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let key_package = bob.publish_key_package().unwrap();

    let mut first = Conversation::create(&alice).unwrap();
    first.invite(&alice, &key_package).unwrap();

    let mut second = Conversation::create(&alice).unwrap();
    assert!(
        second.invite(&alice, &key_package).is_ok(),
        "OpenMLS now refuses reuse: update the note above"
    );
}

#[test]
fn an_unreadable_key_package_is_rejected() {
    let alice = Identity::create("alice").unwrap();
    let mut group = Conversation::create(&alice).unwrap();

    assert!(group.invite(&alice, b"this is not a key package").is_err());
}

#[test]
fn the_state_is_persisted_and_reloaded() {
    let (alice, bob, mut alice_group, mut bob_group) = two_member_conversation();

    let ciphertext = alice_group.encrypt(&alice, "before restart".as_bytes()).unwrap();
    bob_group.process(&bob, &ciphertext, &Default::default()).unwrap();

    // The exported state is in the clear: the platform must encrypt it at rest.
    let state = bob.export_state().unwrap();
    assert!(!state.is_empty());

    // And it does hold session material, not an empty shell.
    assert!(state.len() > 100, "suspiciously small state: {} bytes", state.len());

    let group_id = bob_group.id();
    let reloaded = Conversation::load(&bob, &group_id).unwrap();
    assert_eq!(reloaded.epoch(), bob_group.epoch());
    assert_eq!(reloaded.member_count(), 2);
}

#[test]
fn a_missing_group_is_rejected() {
    let alice = Identity::create("alice").unwrap();
    assert!(Conversation::load(&alice, b"nonexistent-group").is_err());
}

#[test]
fn the_identity_and_the_conversation_survive_a_restart() {
    let (alice, bob, mut alice_group, mut bob_group) = two_member_conversation();

    let first = alice_group.encrypt(&alice, "before".as_bytes()).unwrap();
    bob_group.process(&bob, &first, &Default::default()).unwrap();

    // Simulates closing the application: the whole state goes through the exported blob.
    let state = bob.export_state().unwrap();
    let group_id = bob_group.id();
    drop(bob);
    drop(bob_group);

    let bob = Identity::restore(&state).unwrap();
    assert_eq!(bob.name(), "bob@device-1");

    let mut bob_group = Conversation::load(&bob, &group_id).unwrap();
    assert_eq!(bob_group.member_count(), 2);

    // The session must stay usable in both directions after the restore.
    let second = alice_group.encrypt(&alice, "after".as_bytes()).unwrap();
    match bob_group.process(&bob, &second, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, "after".as_bytes()),
        other => panic!("expected an application message, got {other:?}"),
    }

    let response = bob_group.encrypt(&bob, "I am back".as_bytes()).unwrap();
    match alice_group.process(&alice, &response, &Default::default()).unwrap() {
        Incoming::Application { plaintext, sender } => {
            assert_eq!(plaintext, "I am back".as_bytes());
            assert_eq!(sender.as_deref(), Some("bob@device-1"));
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[test]
fn a_truncated_state_is_rejected() {
    let (_, bob, _, _) = two_member_conversation();
    let state = bob.export_state().unwrap();

    // A corrupted or truncated state must produce an error, never a panic: those bytes come
    // from disk and may have been tampered with.
    for size in [0, 4, 8, state.len() / 2, state.len() - 1] {
        assert!(
            Identity::restore(&state[..size]).is_err(),
            "state truncated to {size} bytes accepted"
        );
    }
}

/// Adding a third member to an existing group requires delivering the **commit** to the members
/// already present, not only the Welcome to the newcomer.
///
/// The case went unnoticed as long as an account had a single device: the group was brand new at
/// invitation time, and the commit had nobody to inform. As soon as an account has two,
/// forgetting it freezes the peer at the old epoch — nobody decrypts anything any more, in
/// silence.
#[test]
fn adding_a_member_requires_delivering_the_commit_to_those_present() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let tablet = Identity::create("alice-tablet").unwrap();

    let mut group = Conversation::create(&alice).unwrap();
    let invitation = group.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = group.apply_pending(&alice).unwrap();

    let mut bob_side =
        Conversation::join(&bob, &invitation.welcome, &tree).unwrap();

    // Alice adds her tablet. The group moves to the next epoch.
    let second = group.invite(&alice, &tablet.publish_key_package().unwrap()).unwrap();
    let tree = group.apply_pending(&alice).unwrap();
    let mut tablet_side =
        Conversation::join(&tablet, &second.welcome, &tree).unwrap();

    // Without this line, Bob stays one epoch behind and everything that follows is unreadable.
    bob_side.process(&bob, &second.commit, &Default::default()).unwrap();

    let ciphertext = bob_side.encrypt(&bob, b"readable by both devices").unwrap();

    for (name, session, identity) in
        [("alice", &mut group, &alice), ("tablet", &mut tablet_side, &tablet)]
    {
        match session.process(identity, &ciphertext, &Default::default()).unwrap() {
            Incoming::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"readable by both devices", "at {name}");
            }
            other => panic!("at {name}: expected an application message, got {other:?}"),
        }
    }
}

/// A complete real-world scenario: a live conversation to which a second device is added.
///
/// Reproduces the exact message order observed on the client side, including the traffic
/// **before** the add — that traffic is what advances the ratchet, and it was missing from the
/// previous test.
#[test]
fn a_device_added_to_a_live_conversation_receives_what_follows() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let tablet = Identity::create("alice").unwrap();

    let mut alice_side = Conversation::create(&alice).unwrap();
    let inv = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &inv.welcome, &tree).unwrap();

    // Traffic before the add: that is what advances the ratchet.
    let m1 = alice_side.encrypt(&alice, b"before the add").unwrap();
    assert!(matches!(bob_side.process(&bob, &m1, &Default::default()).unwrap(), Incoming::Application { .. }));

    // Alice adds her tablet.
    let add = alice_side.invite(&alice, &tablet.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut tablet_side =
        Conversation::join(&tablet, &add.welcome, &tree).unwrap();
    bob_side.process(&bob, &add.commit, &Default::default()).unwrap();

    // Alice reads back her OWN commit: that is what the client does, since it picks up
    // everything the server serves it without telling apart what it posted itself. The
    // operation must fail cleanly — and above all must not damage the group state.
    assert!(alice_side.process(&alice, &add.commit, &Default::default()).is_err());

    // Bob answers. Both of Alice's devices must read it.
    let m2 = bob_side.encrypt(&bob, b"after the add").unwrap();

    match alice_side.process(&alice, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"after the add"),
        other => panic!("at alice: {other:?}"),
    }
    match tablet_side.process(&tablet, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"after the add"),
        other => panic!("at the tablet: {other:?}"),
    }
}

/// A failed decryption attempt **still consumes** the generation.
///
/// This is the trap that cost the most on the client side: the read cursor and the MLS state
/// must advance together. If the cursor is lost — a network error after the fetch loop, and the
/// persistence that never happens — an envelope the ratchet has already moved past gets read
/// again, MLS rejects it for good, and the message vanishes with nothing to report it.
///
/// This test freezes the OpenMLS behaviour that reasoning rests on.
#[test]
fn reading_an_already_processed_message_again_is_permanently_rejected() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut alice_side = Conversation::create(&alice).unwrap();
    let inv = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &inv.welcome, &tree).unwrap();

    let ciphertext = bob_side.encrypt(&bob, b"once only").unwrap();

    match alice_side.process(&alice, &ciphertext, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"once only"),
        other => panic!("expected an application message, got {other:?}"),
    }

    // The second read fails: the key was destroyed to preserve forward secrecy. A client that
    // re-reads its envelopes after losing its cursor therefore loses the message.
    assert!(alice_side.process(&alice, &ciphertext, &Default::default()).is_err());
}

/// The client persists its state after **every** operation and reloads it at startup. This test
/// reproduces that cycle around a device add, which the others do not.
#[test]
fn adding_a_device_survives_persistence() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut alice_side = Conversation::create(&alice).unwrap();
    let inv = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &inv.welcome, &tree).unwrap();

    let m1 = alice_side.encrypt(&alice, b"before").unwrap();
    bob_side.process(&bob, &m1, &Default::default()).unwrap();

    // Alice adds her tablet, then her state is saved and reloaded — exactly what the client does
    // between two fetches.
    let tablet = Identity::create("alice").unwrap();
    let add = alice_side.invite(&alice, &tablet.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();

    let group = alice_side.id();
    let alice = {
        let state = alice.export_state().unwrap();
        Identity::restore(&state).unwrap()
    };
    let mut alice_side = Conversation::load(&alice, &group).unwrap();

    let mut tablet_side =
        Conversation::join(&tablet, &add.welcome, &tree).unwrap();
    bob_side.process(&bob, &add.commit, &Default::default()).unwrap();

    let m2 = bob_side.encrypt(&bob, b"after").unwrap();

    match alice_side.process(&alice, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"after"),
        other => panic!("at alice after reload: {other:?}"),
    }
    match tablet_side.process(&tablet, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"after"),
        other => panic!("at the tablet: {other:?}"),
    }
}

/// Sending a message does not excuse you from reading what came before it.
///
/// The delivery service assigns a sequence number to every envelope. The client was tempted to
/// advance its read cursor up to the number of its own message — after all, it need not read
/// itself back. That is wrong: the number says **nothing** about the envelopes posted meanwhile
/// by the others. Jumping there steps over their commits, and the group freezes at a stale epoch
/// with no error to report it.
///
/// Here Bob writes without having applied Alice's commit: his message is unreadable for
/// everyone, including the device that already existed.
#[test]
fn writing_without_having_applied_the_commit_makes_the_message_unreadable() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let tablet = Identity::create("alice").unwrap();

    let mut alice_side = Conversation::create(&alice).unwrap();
    let inv = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &inv.welcome, &tree).unwrap();

    // Alice adds her tablet. The commit goes out, but Bob does not read it.
    let add = alice_side.invite(&alice, &tablet.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut tablet_side =
        Conversation::join(&tablet, &add.welcome, &tree).unwrap();

    let m = bob_side.encrypt(&bob, b"written one epoch too early").unwrap();

    assert!(alice_side.process(&alice, &m, &Default::default()).is_err(), "alice should not be able to read it");
    assert!(tablet_side.process(&tablet, &m, &Default::default()).is_err(), "nor should the tablet");

    // Once the commit is applied, what follows goes through again — but the lost message is lost
    // for good.
    bob_side.process(&bob, &add.commit, &Default::default()).unwrap();
    let m2 = bob_side.encrypt(&bob, b"after applying the commit").unwrap();

    match alice_side.process(&alice, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => {
            assert_eq!(plaintext, b"after applying the commit");
        }
        other => panic!("at alice: {other:?}"),
    }
}

/// Publish before applying: if publication fails, the group must stay usable.
///
/// Applying the commit before publishing it is unrecoverable. The sender changes epoch while the
/// others stay at the old one, and the commit that would have reconciled them exists nowhere any
/// more — the group dies in silence, with no error to say why. That is exactly what happened on
/// the client side before this separation.
#[test]
fn an_invitation_that_was_not_applied_leaves_the_group_intact() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let tablet = Identity::create("alice").unwrap();

    let mut alice_side = Conversation::create(&alice).unwrap();
    let inv = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &inv.welcome, &tree).unwrap();

    let epoch_before = alice_side.epoch();

    // Alice prepares the add of her tablet, then publication fails: we do not apply.
    let _abandoned = alice_side.invite(&alice, &tablet.publish_key_package().unwrap()).unwrap();

    assert_eq!(alice_side.epoch(), epoch_before, "the epoch moved without publication");

    // The conversation keeps working as if nothing had happened.
    let m = bob_side.encrypt(&bob, b"still readable").unwrap();
    match alice_side.process(&alice, &m, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"still readable"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// Member removal and post-compromise security
// ---------------------------------------------------------------------------------------

/// **The test that matters in this phase.**
///
/// This is the property MLS was chosen for in this project, and the one it had never
/// demonstrated.
///
/// The removed member is not deprived of her keys: her group state is intact, she holds
/// everything she held a second earlier, and nothing in the test takes it away. What changes is
/// that the removal commit re-keyed the tree — TreeKEM, in O(log N) — and that the next epoch
/// secret no longer derives from anything she knows.
///
/// Without this test, device revocation is decorative: filtering server side does not stop a
/// stolen device from decrypting what it intercepts by other means.
#[test]
fn a_removed_member_no_longer_decrypts_what_follows() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    // Three-member group.
    let mut alice_side = Conversation::create(&alice).unwrap();
    let to_bob = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &to_bob.welcome, &tree).unwrap();

    let to_carol = alice_side.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut carol_side = Conversation::join(&carol, &to_carol.welcome, &tree).unwrap();
    bob_side.process(&bob, &to_carol.commit, &Default::default()).unwrap();

    // Before the removal, Carol reads like everyone else. Without this assertion the test would
    // also pass if Carol had never been able to read anything.
    let before = alice_side.encrypt(&alice, b"before the removal").unwrap();
    bob_side.process(&bob, &before, &Default::default()).unwrap();
    match carol_side.process(&carol, &before, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"before the removal"),
        other => panic!("expected an application message, got {other:?}"),
    }

    // Alice removes Carol. Usual discipline: prepare, publish, apply.
    let removal = alice_side.remove(&alice, carol.signature_key()).unwrap();
    bob_side.process(&bob, &removal.commit, &Default::default()).unwrap();
    alice_side.apply_pending(&alice).unwrap();

    // Carol receives the commit that excludes her — she learns of her exclusion instead of
    // observing a silence. Applying it gives her nothing back.
    let _ = carol_side.process(&carol, &removal.commit, &Default::default());

    let after = alice_side.encrypt(&alice, "after the removal".as_bytes()).unwrap();

    // Bob, still a member, still reads.
    match bob_side.process(&bob, &after, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, "after the removal".as_bytes()),
        other => panic!("expected an application message at Bob's, got {other:?}"),
    }

    // Carol, with her whole group state, can no longer do anything with it.
    assert!(
        carol_side.process(&carol, &after, &Default::default()).is_err(),
        "a removed member still decrypts: post-compromise security does not exist, \
         and device revocation protects nothing",
    );
}

/// A removal follows the same discipline as an invitation: prepare, publish, apply. Applying
/// before publishing leaves the others at the old epoch with a commit that exists nowhere — the
/// group dies in silence.
#[test]
fn a_removal_that_was_not_applied_leaves_the_group_intact() {
    let (alice, _bob, mut alice_side, _bob_side) = two_member_conversation();
    let epoch = alice_side.epoch();
    let members = alice_side.member_count();

    let bob_key = alice_side.peer_signature_keys(&alice).into_iter().next().unwrap();
    let _removal = alice_side.remove(&alice, &bob_key).unwrap();

    assert_eq!(alice_side.epoch(), epoch, "the epoch advanced before publication");
    assert_eq!(alice_side.member_count(), members, "the member was removed before publication");
}

/// Two members can remove the same device at the same time. The second commit arrives after the
/// first has been applied: the target is gone. The caller must tell that benign case apart from
/// a real error, otherwise it loops retrying an operation already carried out.
#[test]
fn removing_an_absent_member_is_reported_distinctly() {
    let (alice, _bob, mut alice_side, _bob_side) = two_member_conversation();
    let stranger = Identity::create("stranger").unwrap();

    assert!(matches!(
        alice_side.remove(&alice, stranger.signature_key()),
        Err(crypto_core::CryptoError::UnknownMember),
    ));
}

/// Leaving a group goes through a proposal that **another** member commits: RFC 9420 forbids
/// removing yourself in a commit you generate.
#[test]
fn leaving_a_group_requires_someone_elses_commit() {
    let (alice, bob, mut alice_side, mut bob_side) = two_member_conversation();

    let request = bob_side.leave(&bob).unwrap();

    // As long as nobody commits, Bob is still there — and still reads.
    assert_eq!(alice_side.member_count(), 2);

    assert!(matches!(alice_side.process(&alice, &request, &Default::default()).unwrap(), Incoming::Proposal));

    let departure = alice_side.commit_pending(&alice).unwrap();
    let _ = bob_side.process(&bob, &departure.commit, &Default::default());
    alice_side.apply_pending(&alice).unwrap();

    assert_eq!(alice_side.member_count(), 1, "Bob is still in the tree after leaving");

    let after = alice_side.encrypt(&alice, b"alone").unwrap();
    assert!(bob_side.process(&bob, &after, &Default::default()).is_err(), "Bob still reads after leaving");
}

/// A received proposal must be kept until the commit that picks it up. Dropping it made every
/// leave request silently ineffective: the leaver stayed in the group and no error reported it.
#[test]
fn a_received_proposal_is_kept_until_the_commit() {
    let (alice, bob, mut alice_side, mut bob_side) = two_member_conversation();

    let request = bob_side.leave(&bob).unwrap();
    alice_side.process(&alice, &request, &Default::default()).unwrap();

    // Had the proposal been dropped, there would be nothing to commit here.
    let departure = alice_side.commit_pending(&alice).unwrap();
    let _ = bob_side.process(&bob, &departure.commit, &Default::default());
    alice_side.apply_pending(&alice).unwrap();

    assert_eq!(alice_side.member_count(), 1);
}

// ---------------------------------------------------------------------------------------
// Administered groups
// ---------------------------------------------------------------------------------------

/// The roster travels in the group context, hence in the authenticated state: a joining member
/// reads it as it is, without anyone having to hand it over separately.
#[test]
fn the_roster_is_carried_by_the_group_context() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut alice_side =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let invitation = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();

    let bob_side = Conversation::join(&bob, &invitation.welcome, &tree).unwrap();

    let roster = bob_side.roster().unwrap().expect("the roster did not follow the Welcome");
    assert_eq!(roster.admin(), "alice");
    assert!(roster.moderators().is_empty());
    assert!(!roster.can_moderate("bob"));

    // A flat conversation has none — and wants none.
    let (_, _, flat, _) = two_member_conversation();
    assert!(flat.roster().unwrap().is_none());
}

/// **The test that matters for A.4.**
///
/// Bob is not an admin. His commit is cryptographically impeccable — MLS accepts it, and that is
/// precisely the problem: refusing it is the application's job. Alice must reject it **without
/// moving an inch**, otherwise the refusal itself breaks the group.
#[test]
fn an_unauthorized_commit_is_rejected_without_altering_the_state() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    let mut alice_side =
        Conversation::create_administered(&alice, "alice".into()).unwrap();

    let to_bob = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &to_bob.welcome, &tree).unwrap();

    let to_carol = alice_side.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let _carol_side = Conversation::join(&carol, &to_carol.welcome, &tree).unwrap();
    bob_side.process(&bob, &to_carol.commit, &Default::default()).unwrap();

    let epoch = alice_side.epoch();
    let members = alice_side.member_count();

    // Bob, a plain member, tries to evict Carol.
    let attempt = bob_side.remove(&bob, carol.signature_key()).unwrap();

    let refusal = alice_side.process(&alice, &attempt.commit, &Default::default());
    assert!(
        matches!(refusal, Err(crypto_core::CryptoError::PolicyViolation(_))),
        "unauthorized commit accepted: the policy is useless — got {refusal:?}",
    );

    // A refusal that still advanced the ratchet would be worse than no policy at all: the group
    // would diverge on every hostile attempt.
    assert_eq!(alice_side.epoch(), epoch, "the refusal advanced the epoch");
    assert_eq!(alice_side.member_count(), members, "the refusal changed the membership");

    // And the group still works normally afterwards.
    let after = alice_side.encrypt(&alice, b"still alive").unwrap();
    match bob_side.process(&bob, &after, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"still alive"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// The exception that makes revocation useful: Bob, not an admin, evicts Carol's stolen device
/// because he holds a verified revocation certificate. Without it the device would stay in the
/// group until an admin comes back online.
#[test]
fn a_non_admin_evicts_a_revoked_device() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    let mut alice_side =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let to_bob = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &to_bob.welcome, &tree).unwrap();

    let to_carol = alice_side.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut carol_side = Conversation::join(&carol, &to_carol.welcome, &tree).unwrap();
    bob_side.process(&bob, &to_carol.commit, &Default::default()).unwrap();

    // The context the caller built after having VERIFIED the certificate served by the server.
    // `crypto-core` does no networking: filling this in is the client's job.
    let context = crypto_core::roles::Context {
        revoked: vec![carol.signature_key().to_vec()],
    };

    let removal = bob_side.remove(&bob, carol.signature_key()).unwrap();
    alice_side.process(&alice, &removal.commit, &context).unwrap();
    bob_side.apply_pending(&bob).unwrap();

    assert_eq!(alice_side.member_count(), 2);

    let after = alice_side.encrypt(&alice, b"without carol").unwrap();
    assert!(carol_side.process(&carol, &after, &context).is_err());
}

/// An empty context is not neutral: it makes exactly the stolen-phone case fail. That is the
/// most likely implementation trap on the client side, hence this test.
#[test]
fn without_a_verified_certificate_the_same_removal_is_rejected() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    let mut alice_side =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let to_bob = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &to_bob.welcome, &tree).unwrap();

    let to_carol = alice_side.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let _ = Conversation::join(&carol, &to_carol.welcome, &tree).unwrap();
    bob_side.process(&bob, &to_carol.commit, &Default::default()).unwrap();

    let removal = bob_side.remove(&bob, carol.signature_key()).unwrap();

    assert!(matches!(
        alice_side.process(&alice, &removal.commit, &Default::default()),
        Err(crypto_core::CryptoError::PolicyViolation(_)),
    ));
}

/// An admin promotes someone, who then gains the right to remove.
#[test]
fn a_promotion_grants_moderation_rights() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    let mut alice_side =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let to_bob = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &to_bob.welcome, &tree).unwrap();

    let to_carol = alice_side.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut carol_side = Conversation::join(&carol, &to_carol.welcome, &tree).unwrap();
    bob_side.process(&bob, &to_carol.commit, &Default::default()).unwrap();

    // Alice promotes Bob.
    let promotion =
        alice_side.set_roles(&alice, "alice".into(), vec!["bob".into()]).unwrap();
    bob_side.process(&bob, &promotion.commit, &Default::default()).unwrap();
    carol_side.process(&carol, &promotion.commit, &Default::default()).unwrap();
    alice_side.apply_pending(&alice).unwrap();

    assert!(bob_side.roster().unwrap().unwrap().is_moderator("bob"));

    // The very removal an earlier test rejected now goes through.
    let removal = bob_side.remove(&bob, carol.signature_key()).unwrap();
    alice_side.process(&alice, &removal.commit, &Default::default()).unwrap();
    bob_side.apply_pending(&bob).unwrap();

    assert_eq!(alice_side.member_count(), 2);
}

/// A non-admin promoting himself would bypass the whole policy in a single commit.
#[test]
fn an_ordinary_member_cannot_promote_himself() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut alice_side =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let to_bob = alice_side.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let tree = alice_side.apply_pending(&alice).unwrap();
    let mut bob_side = Conversation::join(&bob, &to_bob.welcome, &tree).unwrap();

    let attempt =
        bob_side.set_roles(&bob, "bob".into(), Vec::new()).unwrap();

    assert!(matches!(
        alice_side.process(&alice, &attempt.commit, &Default::default()),
        Err(crypto_core::CryptoError::PolicyViolation(_)),
    ));
    assert_eq!(alice_side.roster().unwrap().unwrap().admin(), "alice");
}

/// The `0xF100` capability must be declared in the leaves, otherwise MLS refuses to add a member
/// to a group carrying the extension. The error would only show up at the add, far from its
/// cause.
#[test]
fn a_member_does_join_a_group_carrying_the_extension() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut alice_side =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let invitation = alice_side
        .invite(&alice, &bob.publish_key_package().unwrap())
        .expect("add refused: the KeyPackages are missing the 0xF100 capability");
    let tree = alice_side.apply_pending(&alice).unwrap();

    let mut bob_side = Conversation::join(&bob, &invitation.welcome, &tree).unwrap();
    let m = alice_side.encrypt(&alice, b"welcome").unwrap();
    assert!(matches!(
        bob_side.process(&bob, &m, &Default::default()).unwrap(),
        Incoming::Application { .. },
    ));
}

/// Both members derive the same ephemeral channel key without exchanging anything.
///
/// That is what makes the typing indicator cost the protocol nothing: no key to distribute, no
/// extra message.
#[test]
fn the_signal_key_is_shared_by_the_members() {
    let (alice, bob, alice_group, bob_group) = two_member_conversation();

    let alice_side = alice_group.signal_key(&alice).unwrap();
    let bob_side = bob_group.signal_key(&bob).unwrap();

    assert_eq!(alice_side.len(), 32);
    assert_eq!(alice_side, bob_side, "without agreement the signals would be unreadable");
}

/// **PCS applies to the ephemeral channel without a single extra line of code.**
///
/// The key derives from the epoch export secret: any commit changes it. A removed member
/// therefore loses the typing indicator at the very moment he loses the messages — which would
/// have had to be implemented by hand had the channel carried its own long-term key.
#[test]
fn the_signal_key_changes_every_epoch() {
    let (alice, _bob, mut alice_group, _bob_group) = two_member_conversation();

    let before = alice_group.signal_key(&alice).unwrap();
    let epoch_before = alice_group.epoch();

    // An add is enough to turn the tree: what counts is the commit, not its nature.
    let carol = Identity::create("carol@device-1").unwrap();
    alice_group.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    alice_group.apply_pending(&alice).unwrap();

    let after = alice_group.signal_key(&alice).unwrap();

    assert_ne!(epoch_before, alice_group.epoch());
    assert_ne!(before, after, "otherwise a removed member would keep reading the ephemeral channel");
}

/// Both members derive the same call key, for the reason the signal key works: nothing is
/// exchanged, so the media server has nothing to hand out and nothing to keep.
#[test]
fn the_call_key_is_shared_by_the_members() {
    let (alice, bob, alice_group, bob_group) = two_member_conversation();

    let alice_side = alice_group.call_key(&alice, b"call-1").unwrap();
    let bob_side = bob_group.call_key(&bob, b"call-1").unwrap();

    assert_eq!(alice_side.len(), 32);
    assert_eq!(alice_side, bob_side, "without agreement the audio would be noise");
}

/// **Two calls in one epoch must not share a key.**
///
/// Without the call id in the exporter's context, audio captured from one call would decrypt
/// inside the next — a recording outliving the call it belonged to.
#[test]
fn each_call_gets_its_own_key_within_one_epoch() {
    let (alice, _bob, alice_group, _bob_group) = two_member_conversation();

    let first = alice_group.call_key(&alice, b"call-1").unwrap();
    let second = alice_group.call_key(&alice, b"call-2").unwrap();

    assert_ne!(first, second, "otherwise one call's audio replays into another");
}

/// The call key is a *different* key from the ephemeral channel's, at the same epoch.
///
/// They come from the same secret, so only the label separates them. A copied label would make a
/// typing indicator and a media frame share a key — the kind of confusion that raises no error
/// anywhere.
#[test]
fn the_call_key_is_not_the_signal_key() {
    let (alice, _bob, alice_group, _bob_group) = two_member_conversation();

    assert_ne!(alice_group.call_key(&alice, &[]).unwrap(), alice_group.signal_key(&alice).unwrap());
}

/// A member removed mid-call loses the audio at the commit, exactly as they lose the messages.
///
/// Unlike the ephemeral channel this is not entirely free: the live call has to be handed the new
/// key. What this pins down is the half that is — the key really does move.
#[test]
fn the_call_key_changes_every_epoch() {
    let (alice, _bob, mut alice_group, _bob_group) = two_member_conversation();

    let before = alice_group.call_key(&alice, b"call-1").unwrap();

    let carol = Identity::create("carol@device-1").unwrap();
    alice_group.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    alice_group.apply_pending(&alice).unwrap();

    let after = alice_group.call_key(&alice, b"call-1").unwrap();

    assert_ne!(before, after, "otherwise a removed member would keep listening");
}
