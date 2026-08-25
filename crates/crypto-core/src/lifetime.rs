//! How long a conversation keeps what is said in it.
//!
//! # Why this is in the group context and not in a preference
//!
//! A lifetime one side sets and the other cannot see is a note to oneself. Carried in the group
//! context it is authenticated by MLS, hashed into every commit, and read identically by every
//! member — which is what makes "this disappears in seven days" a sentence about the room rather
//! than about one screen.
//!
//! # What it does not do
//!
//! Nothing here is enforced on anybody's machine. A modified client keeps what it likes and
//! screenshots exist. What the feature buys is that the message does not end up in an archive
//! sitting on a server for the rest of time, and `Conversation` is where that half is arranged.

use crate::error::{CryptoError, Result};

/// Group context extension type carrying the lifetime.
///
/// `0xF101` sits in RFC 9420's private-use range, next to `roles::ROSTER_EXTENSION`. Adjacent on
/// purpose: the two are the same kind of thing — a policy of the room, in the authenticated state.
pub const LIFETIME_EXTENSION: u16 = 0xF101;

/// Seven days, in seconds: what every conversation this client creates starts with.
pub const DEFAULT_SECONDS: u32 = 7 * 24 * 60 * 60;

/// How long a message lives in this conversation. `0` is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetime(u32);

impl Lifetime {
    pub fn seconds(seconds: u32) -> Self {
        Self(seconds)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    /// `0` and an absent extension mean the same thing to a reader, and are different states to a
    /// writer: absent is a group that never had the feature, `0` is one where somebody turned it
    /// off. Both keep everything; only the second one posted a notice saying so.
    pub fn is_off(&self) -> bool {
        self.0 == 0
    }

    pub fn encode(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let four: [u8; 4] = bytes
            .try_into()
            .map_err(|_| CryptoError::PolicyViolation("lifetime extension of invalid length"))?;

        Ok(Self(u32::from_be_bytes(four)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lifetime_survives_the_round_trip() {
        let seven_days = Lifetime::seconds(DEFAULT_SECONDS);
        assert_eq!(Lifetime::decode(&seven_days.encode()).unwrap(), seven_days);
    }

    #[test]
    fn zero_is_off_and_is_not_an_absent_extension() {
        assert!(Lifetime::seconds(0).is_off());
        assert!(!Lifetime::seconds(1).is_off());
    }

    /// Four bytes, big-endian, and nothing else — because this crosses the wire between clients
    /// that must all read it identically, and a length nobody checks is how a garbled extension
    /// becomes a lifetime somebody did not choose.
    #[test]
    fn a_body_of_the_wrong_length_is_refused() {
        assert!(Lifetime::decode(&[0, 0, 0]).is_err());
        assert!(Lifetime::decode(&[0, 0, 0, 0, 0]).is_err());
        assert!(Lifetime::decode(&[]).is_err());
    }

    #[test]
    fn the_default_is_seven_days() {
        assert_eq!(DEFAULT_SECONDS, 7 * 24 * 60 * 60);
    }
}
