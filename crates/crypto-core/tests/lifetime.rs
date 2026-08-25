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
