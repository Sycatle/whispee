//! When a message stops existing, and why that is computed once rather than read from a clock.
//!
//! # The lie the sender can tell
//!
//! `sent_at` travels inside the MLS message and is **declared, not proven**. A member can put a
//! future timestamp in their own message and buy it a longer life. So the deadline is
//! `min(sent_at, first seen here) + lifetime`: shortening one's own message stays possible, which
//! was never forbidden, and extending it does not.
//!
//! # Why the deadline is stamped and stored
//!
//! A message keeps the deadline it was given when it arrived, even if the conversation's lifetime
//! changes afterwards. That is what "turning it on is not retroactive" means in code, and it also
//! means a device that was offline during a change does not recompute a different answer from the
//! same history.
//!
//! **Anything archiving a conversation elsewhere has to store this per message and never
//! recompute it from the current lifetime.** Recomputing is how an archive quietly outlives the
//! promise the room was given.

/// The deadline for a message, in milliseconds, or `None` when nothing expires it.
///
/// `sent_at` is what the sender declared; `seen_at` is when this client first saw it. Both are
/// milliseconds since the epoch, and `lifetime_seconds` is the conversation's, `0` meaning off.
///
/// Nothing without a stamp has a deadline, because there is nothing to count from. In practice
/// that is control traffic — gossip, receipts, posting keys, profiles, handles, signals — which
/// [`crate::content::Content::is_control`] keeps unstamped, plus anything written before
/// stamping existed.
///
/// It is deliberately **not** the notices. A membership or expiry notice is stamped, appears in
/// the thread, and therefore expires with the messages around it. A room that forgets what was
/// said should not keep a permanent record of who joined it.
#[must_use]
pub fn expiry_of(sent_at: Option<u64>, seen_at: u64, lifetime_seconds: u32) -> Option<u64> {
    if lifetime_seconds == 0 {
        return None;
    }

    let sent_at = sent_at?;
    Some(sent_at.min(seen_at) + u64::from(lifetime_seconds) * 1000)
}

/// Has this deadline passed?
#[must_use]
pub const fn is_expired(expires_at: Option<u64>, now: u64) -> bool {
    match expires_at {
        Some(deadline) => deadline <= now,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEEK: u32 = 7 * 24 * 60 * 60;
    const WEEK_MS: u64 = 7 * 24 * 60 * 60 * 1000;

    #[test]
    fn an_ordinary_message_expires_a_lifetime_after_it_was_sent() {
        assert_eq!(expiry_of(Some(1_000), 1_500, WEEK), Some(1_000 + WEEK_MS));
    }

    /// The property this module exists for. A hostile sender declaring a date far in the future
    /// must not thereby keep their message alive longer than the room agreed.
    #[test]
    fn a_sender_cannot_extend_the_life_of_their_own_message() {
        let far_future = 9_000_000;
        let seen = 1_000;
        assert_eq!(
            expiry_of(Some(far_future), seen, WEEK),
            Some(seen + WEEK_MS),
            "the receipt time caps a declared one"
        );
    }

    /// The other direction is allowed, and always was: nothing forbids shortening your own
    /// message's life.
    #[test]
    fn a_sender_may_shorten_it() {
        assert_eq!(expiry_of(Some(500), 1_000, WEEK), Some(500 + WEEK_MS));
    }

    #[test]
    fn control_traffic_has_no_deadline() {
        assert_eq!(expiry_of(None, 1_000, WEEK), None);
    }

    #[test]
    fn a_conversation_without_a_lifetime_expires_nothing() {
        assert_eq!(expiry_of(Some(1_000), 1_000, 0), None);
        assert_eq!(expiry_of(None, 1_000, 0), None);
    }

    #[test]
    fn expiry_is_inclusive_of_its_own_deadline() {
        assert!(is_expired(Some(100), 100), "a message is gone at its deadline, not after it");
        assert!(is_expired(Some(100), 101));
        assert!(!is_expired(Some(100), 99));
        assert!(!is_expired(None, u64::MAX), "no deadline means it never goes");
    }
}
