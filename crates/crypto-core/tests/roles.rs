//! The administration policy, tested as a pure function.
//!
//! It is isolated from the protocol precisely so it can be tested this way: covering these cases
//! by standing up real MLS groups would cost ten times as much and cover less. The matching
//! integration test lives in `conversation.rs` and checks that the commit → summary translation
//! is faithful; here we check the rule itself.
//!
//! What is at stake: two clients that do not apply the same rule do not produce an error, they
//! silently fork the group.

use crypto_core::CryptoError;
use crypto_core::roles::{CommitSummary, Context, Removal, Roster, authorize};

fn roster(admin: &str, moderators: &[&str]) -> Roster {
    Roster::new(admin.to_string(), moderators.iter().map(|m| m.to_string()).collect()).unwrap()
}

fn commit<'a>(committer: &'a str, remaining: Vec<&'a str>) -> CommitSummary<'a> {
    CommitSummary {
        committer,
        removals: Vec::new(),
        adds: 0,
        changes_roster: false,
        changes_lifetime: false,
        remaining,
    }
}

fn removal<'a>(target: &'a str, key: &'a [u8]) -> Removal<'a> {
    Removal { target, target_key: key, self_requested: false }
}

// ------------------------------------------------------------------ flat group

/// A group without a roster has no roles: that is the shape of a 1-to-1, and of the groups
/// created before the extension existed. Applying rules to them would make every existing
/// conversation unreadable.
#[test]
fn without_a_roster_everything_is_allowed() {
    let mut c = commit("anyone-at-all", vec!["alice"]);
    c.adds = 3;
    c.changes_roster = true;
    c.removals.push(removal("bob", &[1]));

    assert!(authorize(None, &c, &Context::default()).is_ok());
}

// ------------------------------------------------------------------ the admin

#[test]
fn the_admin_can_do_everything() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("alice", vec!["alice", "bob"]);
    c.adds = 1;
    c.changes_roster = true;
    c.removals.push(removal("carol", &[9]));

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

/// **The rule that gives the single root its meaning.** If a moderator could change the roles he
/// would promote himself to admin and there would be no authority left — only a race.
#[test]
fn a_moderator_does_not_touch_the_roles() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("bob", vec!["alice", "bob"]);
    c.changes_roster = true;

    assert!(matches!(
        authorize(Some(&r), &c, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

/// A group without an admin is frozen for good: nobody can appoint, revoke or hand over any
/// more. A legitimate departure goes through handing over first.
#[test]
fn the_admin_cannot_be_removed() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("alice", vec!["bob"]);
    c.removals.push(removal("alice", &[1]));

    assert!(matches!(
        authorize(Some(&r), &c, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

/// The rule holds for a voluntary departure too: the cause of the freeze matters little, the
/// result is the same.
#[test]
fn the_admin_cannot_leave_without_handing_over() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("bob", vec!["bob"]);
    c.removals.push(Removal { target: "alice", target_key: &[1], self_requested: true });

    assert!(matches!(
        authorize(Some(&r), &c, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

/// **The trap avoided.** An account has several devices: removing the admin's phone does not
/// remove the admin. Reasoning about targets would reject this legitimate commit, and the admin
/// could no longer revoke his own device.
#[test]
fn removing_a_device_of_the_admin_does_not_remove_him_from_the_group() {
    let r = roster("alice", &[]);
    let mut c = commit("alice", vec!["alice"]);
    c.removals.push(removal("alice", &[2]));

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

// ------------------------------------------------------------------ the moderators

#[test]
fn a_moderator_adds_and_removes_ordinary_members() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("bob", vec!["alice", "bob"]);
    c.adds = 1;
    c.removals.push(removal("carol", &[9]));

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

/// Otherwise two moderators remove each other and the outcome depends on who commits first: a
/// race, not a rule.
#[test]
fn a_moderator_does_not_remove_another_moderator() {
    let r = roster("alice", &["bob", "carol"]);
    let mut c = commit("bob", vec!["alice", "bob", "carol"]);
    c.removals.push(removal("carol", &[9]));

    assert!(matches!(
        authorize(Some(&r), &c, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

#[test]
fn the_admin_removes_a_moderator() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("alice", vec!["alice"]);
    c.removals.push(removal("bob", &[2]));

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

// ------------------------------------------------------------------ the ordinary members

#[test]
fn an_ordinary_member_can_neither_add_nor_remove() {
    let r = roster("alice", &["bob"]);

    let mut add = commit("carol", vec!["alice", "bob", "carol"]);
    add.adds = 1;
    assert!(matches!(
        authorize(Some(&r), &add, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));

    let mut remove = commit("carol", vec!["alice", "bob", "carol"]);
    remove.removals.push(removal("dave", &[9]));
    assert!(matches!(
        authorize(Some(&r), &remove, &Context::default()),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

// ------------------------------------------------------------------ the two exceptions

/// A member cannot remove himself in a commit (RFC 9420): he proposes, someone else commits.
/// Reserving that commit to role holders would make leaving impossible when none of them is
/// online — a group you cannot get out of.
#[test]
fn anyone_can_commit_a_voluntary_departure() {
    let r = roster("alice", &[]);
    let mut c = commit("dave", vec!["alice", "dave"]);
    c.removals.push(Removal { target: "carol", target_key: &[9], self_requested: true });

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

/// **The exception that matters.** Without it, an ordinary member's stolen phone stays in the
/// group, reading, until a moderator comes back online — which is exactly the delay revocation
/// exists to remove.
///
/// It opens nothing: the certificate can only be produced by the owning account.
#[test]
fn anyone_can_remove_a_revoked_device() {
    let r = roster("alice", &[]);
    let mut c = commit("dave", vec!["alice", "carol", "dave"]);
    c.removals.push(removal("carol", &[9]));

    let context = Context { revoked: vec![vec![9]] };
    assert!(authorize(Some(&r), &c, &context).is_ok());
}

/// The exception is keyed on the device key, not on the account: revoking one device does not
/// make the others expellable.
#[test]
fn revoking_one_device_does_not_expose_the_others() {
    let r = roster("alice", &[]);
    let mut c = commit("dave", vec!["alice", "carol", "dave"]);
    c.removals.push(removal("carol", &[8]));

    let context = Context { revoked: vec![vec![9]] };
    assert!(matches!(
        authorize(Some(&r), &c, &context),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

/// The exception does not bypass the admin protection: a revoked device of the admin is evicted,
/// but not the admin himself.
#[test]
fn revocation_does_not_allow_evicting_the_admin() {
    let r = roster("alice", &[]);
    let mut c = commit("dave", vec!["dave"]);
    c.removals.push(removal("alice", &[9]));

    let context = Context { revoked: vec![vec![9]] };
    assert!(matches!(
        authorize(Some(&r), &c, &context),
        Err(CryptoError::PolicyViolation(_)),
    ));
}

// ------------------------------------------------------------------ serialisation

#[test]
fn the_roster_survives_a_round_trip() {
    let r = roster("alice", &["bob-the-long-handle", "c"]);
    assert_eq!(Roster::decode(&r.encode().unwrap()).unwrap(), r);
}

#[test]
fn a_roster_without_moderators_survives_a_round_trip() {
    let r = roster("alice", &[]);
    assert_eq!(Roster::decode(&r.encode().unwrap()).unwrap(), r);
}

/// The admin is already above: repeating him there would make `is_moderator` ambiguous to read.
#[test]
fn the_admin_is_not_also_a_moderator() {
    let r = roster("alice", &["alice", "bob"]);
    assert_eq!(r.moderators(), ["bob"]);
    assert!(r.is_admin("alice"));
    assert!(!r.is_moderator("alice"));
}

/// Two encodings of the same roster would make the group context hash diverge, and the clients
/// with it.
#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = roster("alice", &["bob"]).encode().unwrap();
    bytes.push(0);
    assert!(Roster::decode(&bytes).is_err());
}

#[test]
fn a_truncated_roster_is_rejected_without_panicking() {
    let bytes = roster("alice", &["bob"]).encode().unwrap();
    for n in 0..bytes.len() {
        assert!(Roster::decode(&bytes[..n]).is_err(), "length {n} accepted");
    }
}

/// A group without an admin could never be administered again.
#[test]
fn a_roster_without_an_admin_is_rejected() {
    assert!(Roster::new(String::new(), Vec::new()).is_err());
    assert!(Roster::decode(&[0, 0, 0, 0]).is_err());
}

// ------------------------------------------------------------ the room's memory

/// A moderator may change the lifetime. It is the same rank that admits and removes members.
#[test]
fn a_moderator_may_change_the_lifetime() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("bob", vec!["alice", "bob"]);
    c.changes_lifetime = true;

    assert!(authorize(Some(&r), &c, &Context::default()).is_ok());
}

/// An ordinary member may not.
#[test]
fn an_ordinary_member_may_not_change_the_lifetime() {
    let r = roster("alice", &["bob"]);
    let mut c = commit("carol", vec!["alice", "bob", "carol"]);
    c.changes_lifetime = true;

    assert!(authorize(Some(&r), &c, &Context::default()).is_err());
}

/// A flat group has no rule to apply, and a 1-to-1 is a flat group.
#[test]
fn anyone_changes_the_lifetime_of_a_flat_group() {
    let mut c = commit("carol", vec!["alice", "carol"]);
    c.changes_lifetime = true;

    assert!(authorize(None, &c, &Context::default()).is_ok());
}
