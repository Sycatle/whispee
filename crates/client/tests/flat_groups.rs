//! What a flat conversation actually allows, as opposed to what it is said to allow.
//!
//! No server needed: this is a question about `crypto-core` alone.
//!
//! It exists because the opposite was asserted, written into a design, and acted on before
//! anyone ran it. The claim was that a one-to-one "can never take a third member" because the
//! policy has no authority to appeal to. `roles::authorize` in fact returns `Ok` for every
//! commit when there is no roster — a flat group is one where **everyone can do everything** —
//! so the third member is added without complaint.
//!
//! The refusal a user meets lives in `apps/web/src/lib/session.ts`, and it is a product
//! decision. That is a good decision for the reason this file pins next: the resulting group
//! has no administrator, so any member can remove any other.

use crypto_core::{Conversation, Identity, roles};

fn identity(name: &str) -> Identity {
    Identity::create(name).expect("identity")
}

#[test]
fn a_flat_conversation_does_take_a_third_member() {
    let alice = identity("alice");
    let bob = identity("bob");
    let carol = identity("carol");

    let mut flat = Conversation::create(&alice).expect("create");
    let invitation = flat
        .invite(&alice, &bob.publish_key_package().expect("key package"))
        .expect("invite bob");
    let tree = flat.apply_pending(&alice).expect("apply");
    let mut bob_group = Conversation::join(&bob, &invitation.welcome, &tree).expect("bob joins");

    assert!(flat.roster().expect("roster").is_none(), "a one-to-one is created flat");

    let invitation = flat
        .invite(&alice, &carol.publish_key_package().expect("key package"))
        .expect("the protocol does not refuse a third member in a flat group");
    let tree = flat.apply_pending(&alice).expect("apply");

    bob_group
        .process(&bob, &invitation.commit, &roles::Context::default())
        .expect("the existing member applies the commit");
    Conversation::join(&carol, &invitation.welcome, &tree).expect("carol joins");

    assert_eq!(flat.member_count(), 3);
}

/// And why the application refuses anyway.
///
/// A flat group of three has no administrator, so nothing distinguishes a member from an
/// admin: any member may remove any other. In a conversation between a freelancer and their
/// client that means the client can eject the freelancer, or a service, with no recourse —
/// which is the reason to create an administered conversation when one is meant to grow.
#[test]
fn a_flat_group_lets_any_member_remove_any_other() {
    let alice = identity("alice");
    let bob = identity("bob");
    let carol = identity("carol");

    let mut alice_group = Conversation::create(&alice).expect("create");
    let to_bob = alice_group
        .invite(&alice, &bob.publish_key_package().expect("key package"))
        .expect("invite bob");
    let tree = alice_group.apply_pending(&alice).expect("apply");
    let mut bob_group = Conversation::join(&bob, &to_bob.welcome, &tree).expect("bob joins");

    let to_carol = alice_group
        .invite(&alice, &carol.publish_key_package().expect("key package"))
        .expect("invite carol");
    let tree = alice_group.apply_pending(&alice).expect("apply");
    bob_group
        .process(&bob, &to_carol.commit, &roles::Context::default())
        .expect("bob applies");
    let carol_group = Conversation::join(&carol, &to_carol.welcome, &tree).expect("carol joins");

    // Carol, who created nothing and administers nothing, removes Alice.
    let alice_key = carol_group
        .peer_signature_keys(&carol)
        .into_iter()
        .find(|key| key.as_slice() == alice.signature_key())
        .expect("carol sees alice");

    let mut carol_group = carol_group;
    carol_group
        .remove(&carol, &alice_key)
        .expect("a flat group has no authority to appeal to, so this is allowed");
}

/// An administered conversation, which is what the application creates when told the
/// conversation is meant to grow, does have that authority — **and it is applied on receipt**.
///
/// This is the half that is easy to get backwards. `invite` builds a commit locally and does not
/// consult the roster, so an ordinary member can produce one; nothing stops them. The policy runs
/// in `process`, on every other member's machine, and that is where the commit is refused. The
/// roster is worth something because honest clients enforce it, not because a hostile one is
/// prevented from trying.
#[test]
fn an_administered_group_refuses_an_ordinary_member_s_commit_on_receipt() {
    let alice = identity("alice");
    let bob = identity("bob");
    let carol = identity("carol");

    let mut alice_group =
        Conversation::create_administered(&alice, "alice".to_owned()).expect("create");
    assert!(alice_group.roster().expect("roster").is_some());

    let to_bob = alice_group
        .invite(&alice, &bob.publish_key_package().expect("key package"))
        .expect("the admin may add");
    let tree = alice_group.apply_pending(&alice).expect("apply");
    let mut bob_group = Conversation::join(&bob, &to_bob.welcome, &tree).expect("bob joins");

    // Bob is an ordinary member. He can build the commit: the check is not here.
    let forged = bob_group
        .invite(&bob, &carol.publish_key_package().expect("key package"))
        .expect("building a commit consults no roster");
    let _ = bob_group.apply_pending(&bob);

    // The admin refuses it, which is what keeps the roster meaningful.
    let refused = alice_group.process(&alice, &forged.commit, &roles::Context::default());
    assert!(
        refused.is_err(),
        "an ordinary member's add must be refused by the members who receive it, or the roster \
         buys nothing at all"
    );
}
