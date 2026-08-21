//! Group administration roles.
//!
//! # MLS provides no authorization
//!
//! That is the point to grasp before reading on. RFC 9420 describes who can *prove* what, not
//! who is *allowed* to do what: any member can commit any add or remove, and the protocol will
//! accept it. "Only admins can remove" is an application rule, and nothing in MLS enforces it
//! for us.
//!
//! Direct consequence: **every client must apply the rule identically**. A client that accepts
//! a commit the others refuse does not cause an error, it causes a *fork* — two halves of the
//! group move on to different epochs, each convinced it is the group, and nothing passes
//! between them any more. No error message anywhere.
//!
//! That is why the policy here is a **pure** function, tested in isolation, rather than a set
//! of conditions scattered through the calling code.
//!
//! # Why the roster lives in the group context
//!
//! Putting it in an application message would leave it replayable and unauthenticated: a member
//! could rebroadcast an old roster in which they were admin. In the group context it is hashed
//! into every commit and is part of the state all members agree on by construction. Changing it
//! requires a commit, so it goes through the same policy as everything else.
//!
//! # Why handles, and not signature keys
//!
//! A handle covers all of an account's devices. Adding a phone therefore needs no roster
//! change, and an admin is admin from any of their devices. It is also what the MLS credential
//! already carries — no extra binding to establish.

use crate::error::{CryptoError, Result};

/// Group context extension type carrying the roster.
///
/// `0xF100` sits in RFC 9420's private-use range (`0xF000`–`0xFFFF`): no standardised extension
/// will ever collide with it.
pub const ROSTER_EXTENSION: u16 = 0xF100;

/// Who administers the group: **one** admin, and moderators under them.
///
/// # Why a single admin
///
/// Several admins of equal rank have no tie-breaker: two of them can demote each other, remove
/// each other, or contradict each other on the group's membership. Nothing in the protocol says
/// which one is right, and the group splits. A single root removes the question: there is
/// always exactly one authority.
///
/// Moderators maintain the group — adding and removing ordinary members — without being able to
/// touch roles. Only the admin hands out power, including their own.
///
/// # No roster is not an empty roster
///
/// It is a **flat group**, where everyone can do everything. That covers 1-to-1 conversations,
/// where roles would make no sense, and groups created before this extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    admin: String,
    moderators: Vec<String>,
}

impl Roster {
    /// Creates a roster. The admin cannot appear among the moderators: they are already above,
    /// and repeating them there would make `is_moderator` ambiguous to read.
    pub fn new(admin: String, moderators: Vec<String>) -> Result<Self> {
        if admin.is_empty() {
            return Err(CryptoError::PolicyViolation("an administered group requires an admin"));
        }
        let moderators: Vec<String> = moderators.into_iter().filter(|m| *m != admin).collect();
        Ok(Self { admin, moderators })
    }

    pub fn admin(&self) -> &str {
        &self.admin
    }

    pub fn moderators(&self) -> &[String] {
        &self.moderators
    }

    pub fn is_admin(&self, handle: &str) -> bool {
        self.admin == handle
    }

    pub fn is_moderator(&self, handle: &str) -> bool {
        self.moderators.iter().any(|m| m == handle)
    }

    /// May add and remove ordinary members.
    pub fn can_moderate(&self, handle: &str) -> bool {
        self.is_admin(handle) || self.is_moderator(handle)
    }

    /// Holds a role, whichever it is. A role holder can only be removed by the admin.
    pub fn has_role(&self, handle: &str) -> bool {
        self.can_moderate(handle)
    }

    /// Canonical serialisation:
    ///   `u16 len ‖ admin ‖ u16 count ‖ count × (u16 len ‖ moderator)`
    ///
    /// Same length-prefixing discipline as the `attest` crate, and for the same reason: two
    /// distinct rosters must never produce the same bytes, or the group context hash would stop
    /// telling them apart.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        push_string(&mut out, &self.admin)?;

        if self.moderators.len() > u16::MAX as usize {
            return Err(CryptoError::Malformed("too many moderators"));
        }
        out.extend_from_slice(&(self.moderators.len() as u16).to_be_bytes());
        for moderator in &self.moderators {
            push_string(&mut out, moderator)?;
        }
        Ok(out)
    }

    /// Strict reading: any leftover byte is an error.
    ///
    /// Tolerating an unread tail would let two encodings represent the same roster, which is
    /// enough to make two clients diverge on the group state.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let admin = take_string(bytes, &mut cursor)?;

        let count = u16::from_be_bytes(
            take(bytes, &mut cursor, 2)?.try_into().expect("2 bytes asked for, 2 obtained"),
        );

        let mut moderators = Vec::with_capacity(count as usize);
        for _ in 0..count {
            moderators.push(take_string(bytes, &mut cursor)?);
        }

        if cursor != bytes.len() {
            return Err(CryptoError::Malformed("trailing bytes after the roster"));
        }

        Self::new(admin, moderators)
    }
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(CryptoError::Malformed("handle too long"));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = cursor.checked_add(n).ok_or(CryptoError::Malformed("truncated roster"))?;
    let part = bytes.get(*cursor..end).ok_or(CryptoError::Malformed("truncated roster"))?;
    *cursor = end;
    Ok(part)
}

fn take_string(bytes: &[u8], cursor: &mut usize) -> Result<String> {
    let len = u16::from_be_bytes(
        take(bytes, cursor, 2)?.try_into().expect("2 bytes asked for, 2 obtained"),
    );
    let raw = take(bytes, cursor, len as usize)?;
    std::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|_| CryptoError::Malformed("non-UTF-8 handle in the roster"))
}

/// What an incoming commit contains, reduced to what the policy needs.
///
/// This type exists so the policy is testable without standing up an MLS group: that is the
/// only way to cover the edge cases, which are many and some of which do not reproduce easily
/// with real epochs.
#[derive(Debug, Clone)]
pub struct CommitSummary<'a> {
    /// The committer's handle, read from its credential — hence authenticated by MLS.
    pub committer: &'a str,
    /// One entry per proposed removal.
    pub removals: Vec<Removal<'a>>,
    /// Does the commit add members?
    pub adds: usize,
    /// Does the commit change the group context extensions (hence the roster)?
    pub changes_roster: bool,
    /// Handles still represented in the group **after** the commit is applied.
    ///
    /// Needed because an account has several devices: removing one of Alice's devices does not
    /// remove Alice. Reasoning on removal targets would wrongly suggest an admin leaves the
    /// group as soon as they lose a phone from it, and the commit would be refused.
    pub remaining: Vec<&'a str>,
}

/// A proposed removal, as the policy sees it.
#[derive(Debug, Clone)]
pub struct Removal<'a> {
    /// Handle of the account owning the removed device.
    pub target: &'a str,
    /// MLS signature key of the removed device, which identifies it unambiguously.
    pub target_key: &'a [u8],
    /// Was the removal proposed by the device itself? A voluntary departure.
    pub self_requested: bool,
}

/// What the caller knows from outside, and the protocol cannot teach it.
///
/// The revocation list comes from the server and **must have been verified** by the caller
/// (`attest::verify_revocation`) before reaching here. This module does no networking and
/// verifies no signature: that is what keeps `crypto-core` I/O-free, and what makes the policy
/// testable.
#[derive(Debug, Default, Clone)]
pub struct Context {
    /// MLS signature keys whose revocation certificate has been verified.
    pub revoked: Vec<Vec<u8>>,
}

impl Context {
    fn is_revoked(&self, key: &[u8]) -> bool {
        self.revoked.iter().any(|k| k == key)
    }
}

/// Decides whether a commit must be applied.
///
/// A pure function: same inputs, same verdict, on every client. That is the condition for a
/// refusal not to cause a fork — see the module header.
///
/// # The hierarchy
///
/// | Operation | Allowed for |
/// |---|---|
/// | anything, in a group without a roster | everyone |
/// | add a member | admin, moderator |
/// | remove an ordinary member | admin, moderator |
/// | remove a moderator | admin |
/// | change the roster (appoint, revoke, hand over) | admin |
/// | remove the admin | nobody |
/// | commit a member's voluntary departure | everyone |
/// | remove a device whose revocation is verified | everyone |
///
/// # Why a moderator does not touch other moderators
///
/// Otherwise two moderators can remove each other, and the outcome depends on who commits
/// first — a race, not a rule. Power over roles stays undivided with the admin, which is
/// precisely what a single root buys.
///
/// # Why the admin cannot be removed
///
/// A group without an admin is frozen: nobody can appoint, revoke or hand over any more, the
/// extension being under the admin's sole control. An admin's departure therefore goes through
/// a **prior hand-over** — they name their successor while they still have the power to.
///
/// # The two exceptions, which are not conveniences
///
/// **Voluntary departure.** A member cannot remove themselves in a commit (RFC 9420): they
/// propose, someone else commits. Reserving that commit to role holders would make leaving
/// impossible when none is online — a group you cannot get out of.
///
/// **The revoked device.** Without it, an ordinary member's stolen phone stays in the group,
/// reading, until a moderator comes back online. That delay is exactly what revocation exists
/// to remove. Since the certificate is verifiable by all, the exception opens nothing: only the
/// owning account can trigger it.
pub fn authorize(
    roster: Option<&Roster>,
    commit: &CommitSummary<'_>,
    context: &Context,
) -> Result<()> {
    // Flat group: no rule to apply. That covers 1-to-1s and groups created before the roster
    // was introduced.
    let Some(roster) = roster else { return Ok(()) };

    let committer_is_admin = roster.is_admin(commit.committer);
    let committer_can_moderate = roster.can_moderate(commit.committer);

    if commit.changes_roster && !committer_is_admin {
        return Err(CryptoError::PolicyViolation("only the admin changes roles"));
    }

    if commit.adds > 0 && !committer_can_moderate {
        return Err(CryptoError::PolicyViolation("adding a member requires a role"));
    }

    for removal in &commit.removals {
        // The two exceptions, available to anyone.
        if removal.self_requested || context.is_revoked(removal.target_key) {
            continue;
        }

        if !committer_can_moderate {
            return Err(CryptoError::PolicyViolation("removing a member requires a role"));
        }
        if roster.is_moderator(removal.target) && !committer_is_admin {
            return Err(CryptoError::PolicyViolation(
                "only the admin removes a moderator",
            ));
        }
    }

    // Applies to everyone, the admin included: the group must never end up without an
    // authority, whatever the intent. A legitimate departure goes through a prior hand-over,
    // which installs the successor before the removal happens.
    if !commit.remaining.contains(&roster.admin()) {
        return Err(CryptoError::PolicyViolation(
            "the group would lose its admin: hand it over first",
        ));
    }

    Ok(())
}
