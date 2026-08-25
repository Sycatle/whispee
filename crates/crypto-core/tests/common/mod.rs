//! Helpers shared by the integration tests.
//!
//! Every file here builds identities and groups the same way, and one builder is enough: two of
//! them drift, and the day they disagree the tests stop describing the same protocol.
#![allow(dead_code)]

use crypto_core::{Conversation, Identity};

/// An identity, named. Nothing else — the name is the handle the roster rules read.
pub fn identity(name: &str) -> Identity {
    Identity::create(name).unwrap()
}

/// One member: their identity and their view of the conversation.
///
/// The two travel together because every call needs both — `crypto-core` keeps the signer out of
/// the group on purpose, so the test has to carry it.
pub struct Member {
    pub identity: Identity,
    pub conversation: Conversation,
}

/// Stands up a two-member conversation the way the real flow would: Bob publishes a KeyPackage,
/// Alice creates the group and invites him, Bob joins through the Welcome.
pub fn two_member_conversation() -> (Identity, Identity, Conversation, Conversation) {
    let alice = identity("alice@device-1");
    let bob = identity("bob@device-1");

    let bob_key_package = bob.publish_key_package().unwrap();

    let mut alice_group = Conversation::create(&alice).unwrap();
    let invitation = alice_group.invite(&alice, &bob_key_package).unwrap();
    let tree = alice_group.apply_pending(&alice).unwrap();

    let bob_group = Conversation::join(&bob, &invitation.welcome, &tree).unwrap();

    (alice, bob, alice_group, bob_group)
}

/// Two members of one **administered** group: the first is its admin, the second an ordinary
/// member. Both can hand commits to the other, which is what a rule enforced on application
/// needs in order to be tested at all.
pub fn administered_pair(admin: &str, member: &str) -> (Member, Member) {
    let admin_identity = identity(admin);
    let member_identity = identity(member);

    let mut admin_side =
        Conversation::create_administered(&admin_identity, admin.to_owned()).unwrap();
    let invitation =
        admin_side.invite(&admin_identity, &member_identity.publish_key_package().unwrap()).unwrap();
    let tree = admin_side.apply_pending(&admin_identity).unwrap();
    let member_side =
        Conversation::join(&member_identity, &invitation.welcome, &tree).unwrap();

    (
        Member { identity: admin_identity, conversation: admin_side },
        Member { identity: member_identity, conversation: member_side },
    )
}
