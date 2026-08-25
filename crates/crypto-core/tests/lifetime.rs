//! The conversation lifetime, where it lives and what it must not take with it.

mod common;

use crypto_core::lifetime::{DEFAULT_SECONDS, Lifetime};

/// A new administered group starts at seven days, and still has its admin.
#[test]
fn a_new_group_starts_at_seven_days() {
    let alice = common::identity("alice");
    let group = crypto_core::Conversation::create_administered(&alice, "alice".into()).unwrap();

    assert_eq!(group.lifetime().unwrap().map(|l| l.get()), Some(DEFAULT_SECONDS));
    assert_eq!(group.roster().unwrap().map(|r| r.admin().to_owned()), Some("alice".into()));
}

/// Setting the lifetime keeps the roster.
///
/// The failure this pins is not hypothetical: `update_group_context_extensions` replaces every
/// extension, so a setter that rebuilds only its own drops the roster and turns an administered
/// group flat — everyone an admin, in a commit the others accept because nothing about it is
/// malformed.
#[test]
fn setting_the_lifetime_keeps_the_roster() {
    let alice = common::identity("alice");
    let mut group = crypto_core::Conversation::create_administered(&alice, "alice".into()).unwrap();

    group.set_lifetime(&alice, Lifetime::seconds(3600)).unwrap();
    group.apply_pending(&alice).unwrap();

    assert_eq!(group.lifetime().unwrap().map(|l| l.get()), Some(3600));
    assert_eq!(
        group.roster().unwrap().map(|r| r.admin().to_owned()),
        Some("alice".into()),
        "the roster was dropped by a commit that only meant to change the lifetime"
    );
}

/// And the reverse: changing the roster keeps the lifetime.
#[test]
fn setting_the_roster_keeps_the_lifetime() {
    let alice = common::identity("alice");
    let mut group = crypto_core::Conversation::create_administered(&alice, "alice".into()).unwrap();

    group.set_lifetime(&alice, Lifetime::seconds(3600)).unwrap();
    group.apply_pending(&alice).unwrap();
    group.set_roles(&alice, "alice".into(), vec!["bob".into()]).unwrap();
    group.apply_pending(&alice).unwrap();

    assert_eq!(group.lifetime().unwrap().map(|l| l.get()), Some(3600));
}

/// A flat conversation — a 1-to-1 — also gets the default, and gains no roster from it.
#[test]
fn a_flat_conversation_has_a_lifetime_and_no_roster() {
    let alice = common::identity("alice");
    let group = crypto_core::Conversation::create(&alice).unwrap();

    assert_eq!(group.lifetime().unwrap().map(|l| l.get()), Some(DEFAULT_SECONDS));
    assert!(group.roster().unwrap().is_none());
}

/// The rule is enforced on the commit, not merely in an interface.
///
/// Two members, one of them an ordinary member of an administered group: their commit changing
/// the lifetime is refused by the other side when it is applied, which is where enforcement has
/// to live. An interface that hides the control protects nobody from a client that does not.
#[test]
fn an_ordinary_members_lifetime_commit_is_refused_by_the_others() {
    let (mut admin, mut member) = common::administered_pair("alice", "bob");

    let change =
        member.conversation.set_lifetime(&member.identity, Lifetime::seconds(60)).unwrap();

    let refused =
        admin.conversation.process(&admin.identity, &change.commit, &Default::default());

    assert!(
        matches!(refused, Err(crypto_core::CryptoError::PolicyViolation(_))),
        "an ordinary member changed the room's memory and it was accepted — got {refused:?}"
    );
}

/// And a moderator's is accepted, on the same path.
#[test]
fn a_moderators_lifetime_commit_is_applied_by_the_others() {
    let (mut admin, mut member) = common::administered_pair("alice", "bob");

    let promotion =
        admin.conversation.set_roles(&admin.identity, "alice".into(), vec!["bob".into()]).unwrap();
    member.conversation.process(&member.identity, &promotion.commit, &Default::default()).unwrap();
    admin.conversation.apply_pending(&admin.identity).unwrap();

    let change =
        member.conversation.set_lifetime(&member.identity, Lifetime::seconds(60)).unwrap();
    admin.conversation.process(&admin.identity, &change.commit, &Default::default()).unwrap();

    assert_eq!(admin.conversation.lifetime().unwrap().map(|l| l.get()), Some(60));
    assert_eq!(
        admin.conversation.roster().unwrap().map(|r| r.admin().to_owned()),
        Some("alice".into())
    );
}
