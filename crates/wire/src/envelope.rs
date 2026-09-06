//! The application envelope carried inside the server's opaque blobs.
//!
//! The server does not speak MLS: it routes bytes. But a conversation's mailbox mixes two things
//! handled differently — ordinary MLS messages, and the Welcome that lets a newcomer join. A
//! type byte tells them apart.
//!
//! The Welcome therefore travels in the clear as far as the server is concerned, and that is of
//! no consequence: its secrets are encrypted to the init key of the invitee's KeyPackage, and the
//! ratchet tree is public by construction.
//!
//! A joining client has no dedicated delivery to wait for. It lists its groups, reads each
//! unknown mailbox from the beginning, and tries every Welcome it finds until one is addressed to
//! it — the others fail to decrypt, which is not an anomaly but the normal shape of the search.

use crate::{Result, WireError};

const TYPE_MLS: u8 = 0;
const TYPE_WELCOME: u8 = 1;

/// What an envelope turned out to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope<'a> {
    /// An ordinary MLS message, to hand to the group.
    Mls(&'a [u8]),
    /// A Welcome and the ratchet tree that goes with it.
    Welcome {
        /// The MLS Welcome message.
        welcome: &'a [u8],
        /// The public ratchet tree, needed to join.
        ratchet_tree: &'a [u8],
    },
}

/// Wraps an MLS message.
#[must_use]
pub fn encode_mls(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(TYPE_MLS);
    out.extend_from_slice(payload);
    out
}

/// Wraps a Welcome and its ratchet tree: `u8 1 ‖ u32 BE welcome length ‖ welcome ‖ tree`.
#[must_use]
pub fn encode_welcome(welcome: &[u8], ratchet_tree: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + welcome.len() + ratchet_tree.len());
    out.push(TYPE_WELCOME);
    // `as u32` is sound for any welcome a peer could send: the server's body limit is far below
    // 4 GiB, so a longer one never reaches this code.
    out.extend_from_slice(&(welcome.len() as u32).to_be_bytes());
    out.extend_from_slice(welcome);
    out.extend_from_slice(ratchet_tree);
    out
}

/// Reads an envelope.
///
/// Every length is checked against what is actually present: these bytes arrive straight off the
/// network, before MLS has authenticated anything, so an inconsistent length must produce an
/// error and never an out-of-bounds read or a silently truncated slice.
pub fn decode(blob: &[u8]) -> Result<Envelope<'_>> {
    let (&kind, body) = blob.split_first().ok_or(WireError::Empty("envelope"))?;

    match kind {
        TYPE_MLS => Ok(Envelope::Mls(body)),
        TYPE_WELCOME => {
            if body.len() < 4 {
                return Err(WireError::Truncated {
                    format: "welcome envelope",
                    claimed: 4,
                    available: body.len(),
                });
            }
            let (length, rest) = body.split_at(4);
            let length = u32::from_be_bytes(length.try_into().expect("split_at(4) yields 4 bytes"))
                as usize;

            if length > rest.len() {
                return Err(WireError::Truncated {
                    format: "welcome envelope",
                    claimed: length,
                    available: rest.len(),
                });
            }
            let (welcome, ratchet_tree) = rest.split_at(length);
            Ok(Envelope::Welcome { welcome, ratchet_tree })
        }
        byte => Err(WireError::UnknownType { format: "envelope", byte }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn an_mls_message_round_trips() {
        let blob = encode_mls(b"ciphertext");
        assert_eq!(blob[0], 0, "the type byte is pinned: clients agree on it or nothing works");
        assert_eq!(decode(&blob).unwrap(), Envelope::Mls(b"ciphertext"));
    }

    #[test]
    fn a_welcome_round_trips() {
        let blob = encode_welcome(b"welcome-bytes", b"tree-bytes");
        assert_eq!(blob[0], 1);
        assert_eq!(
            decode(&blob).unwrap(),
            Envelope::Welcome { welcome: b"welcome-bytes", ratchet_tree: b"tree-bytes" }
        );
    }

    /// The layout is pinned byte for byte: a client that writes the length little-endian would
    /// otherwise pass every round-trip test of its own and interoperate with nobody.
    #[test]
    fn the_welcome_layout_is_exact() {
        assert_eq!(encode_welcome(b"ab", b"cd"), vec![1, 0, 0, 0, 2, b'a', b'b', b'c', b'd']);
    }

    #[test]
    fn an_empty_welcome_and_tree_are_legal() {
        let blob = encode_welcome(b"", b"");
        assert_eq!(decode(&blob).unwrap(), Envelope::Welcome { welcome: b"", ratchet_tree: b"" });
    }

    #[test]
    fn an_empty_envelope_is_refused() {
        assert_eq!(decode(&[]).unwrap_err(), WireError::Empty("envelope"));
    }

    #[test]
    fn an_unknown_type_is_refused() {
        assert_eq!(
            decode(&[9, 1, 2]).unwrap_err(),
            WireError::UnknownType { format: "envelope", byte: 9 }
        );
    }

    #[test]
    fn a_welcome_without_a_full_length_prefix_is_refused() {
        assert!(matches!(decode(&[1, 0, 0]).unwrap_err(), WireError::Truncated { .. }));
    }

    /// The read that would be out of bounds if the length were trusted.
    #[test]
    fn a_welcome_claiming_more_than_it_carries_is_refused() {
        let error = decode(&[1, 0, 0, 0xff, 0xff, 1, 2, 3]).unwrap_err();
        assert_eq!(
            error,
            WireError::Truncated { format: "welcome envelope", claimed: 65535, available: 3 }
        );
    }
}
