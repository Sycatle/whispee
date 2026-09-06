//! Message padding, so that size stops informing the server.
//!
//! The content is encrypted; its **length** is not. It crosses MLS almost unchanged and the
//! server reads it on every envelope — enough to tell "yes" from "I'll call you back in ten
//! minutes", to spot a pasted password, to recognise a boilerplate message. Followed over a
//! conversation, the sequence of lengths is a signature.
//!
//! Buckets start at 256 bytes — above the overwhelming majority of written messages, which
//! therefore all become the same size — then double. Doubling bounds the waste to under 100 %
//! and leaves the server only the order of magnitude.
//!
//! What it does not hide: who writes, to whom, and when. Masking that would take decoy traffic,
//! a cost paid even when nobody is talking.

use crate::{Result, WireError};

/// First bucket. Chosen above nearly all written messages.
const FIRST_BUCKET: usize = 256;

/// End-of-content marker, then zeroes — ISO/IEC 7816-4.
///
/// Plain zero filling would be ambiguous: content legitimately ending in a zero would become
/// indistinguishable from its padding. The marker removes the ambiguity for one byte.
const MARKER: u8 = 0x80;

/// The bucket reaching at least `length`, never above `ceiling`.
fn bucket(length: usize, ceiling: usize) -> usize {
    let mut size = FIRST_BUCKET;
    while size < length && size < ceiling {
        // Saturating rather than wrapping: a ceiling above `usize::MAX / 2` would otherwise
        // wrap to zero and hand back a bucket smaller than the body.
        size = size.saturating_mul(2);
    }
    size.min(ceiling)
}

/// Pads up to the next bucket, with no ceiling.
///
/// The marker is **always** added, even when the length falls exactly on a bucket: without it,
/// removal could not tell whether the last byte belongs to the content.
#[must_use]
pub fn pad(body: &[u8]) -> Vec<u8> {
    pad_under(body, usize::MAX).expect("no body can exceed a ceiling of usize::MAX")
}

/// Pads up to the next bucket, capped at `ceiling`.
///
/// For a caller whose transport refuses anything above a size. It errors rather than returning
/// something shorter than asked: a caller handing over more than `ceiling - 1` bytes has a bug
/// in its own limit, and silently padding to less than the ceiling would produce a size that
/// identifies the payload — the opposite of the point.
pub fn pad_under(body: &[u8], ceiling: usize) -> Result<Vec<u8>> {
    if body.len() + 1 > ceiling {
        return Err(WireError::AboveCeiling { length: body.len(), ceiling });
    }

    let size = bucket(body.len() + 1, ceiling);
    let mut out = vec![0u8; size];
    out[..body.len()].copy_from_slice(body);
    out[body.len()] = MARKER;
    Ok(out)
}

/// Removes the padding.
///
/// Errors on malformed padding rather than guessing: these bytes were authenticated by MLS, so
/// they do come from a member — but a member can send anything at all, and a loose reading here
/// would become a difference of interpretation between clients.
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let end = padded
        .iter()
        .rposition(|&byte| byte != 0x00)
        .ok_or(WireError::MalformedPadding)?;

    if padded[end] != MARKER {
        return Err(WireError::MalformedPadding);
    }

    Ok(&padded[..end])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The bucket sizes are pinned as literals, never as `FIRST_BUCKET`. Asserting against the
    /// constant would make the test follow any change to it, so it would agree with a scheme
    /// that starts at 128 — and 128 is below plenty of ordinary messages, which is the one
    /// thing the first bucket is chosen to be above.
    #[test]
    fn a_short_message_becomes_the_first_bucket_of_256() {
        assert_eq!(pad(b"yes").len(), 256);
        assert_eq!(pad(b"I'll call you back in ten minutes").len(), 256);
        // 200 bytes is an ordinary message and must still land in the first bucket.
        assert_eq!(pad(&[0u8; 200]).len(), 256);
    }

    /// The property the whole scheme exists for: two messages a human would tell apart by
    /// length must not be tellable apart on the wire.
    #[test]
    fn two_different_short_messages_are_indistinguishable_by_length() {
        assert_eq!(pad(b"ok").len(), pad(b"here is a very much longer sentence").len());
    }

    #[test]
    fn buckets_double() {
        assert_eq!(pad(&vec![0u8; 255]).len(), 256);
        assert_eq!(pad(&vec![0u8; 256]).len(), 512);
        assert_eq!(pad(&vec![0u8; 512]).len(), 1024);
        assert_eq!(pad(&vec![0u8; 1000]).len(), 1024);
    }

    /// A body landing exactly on a bucket still gets a marker, so it spills into the next one.
    /// Without the marker, removal could not tell content from padding.
    #[test]
    fn a_body_on_a_bucket_boundary_spills_into_the_next() {
        let body = vec![7u8; 256];
        let padded = pad(&body);
        assert_eq!(padded.len(), 512);
        assert_eq!(unpad(&padded).unwrap(), &body[..]);
    }

    #[test]
    fn padding_round_trips() {
        for length in [0usize, 1, 3, 255, 256, 257, 1023, 4096] {
            let body: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            assert_eq!(unpad(&pad(&body)).unwrap(), &body[..], "length {length}");
        }
    }

    /// The ambiguity the marker exists to remove.
    #[test]
    fn content_ending_in_zeroes_survives() {
        let body = vec![0u8; 40];
        assert_eq!(unpad(&pad(&body)).unwrap(), &body[..]);
    }

    #[test]
    fn a_ceiling_collapses_everything_above_the_last_doubling() {
        assert_eq!(pad_under(&vec![0u8; 300], 400).unwrap().len(), 400);
        assert_eq!(pad_under(&vec![0u8; 399], 400).unwrap().len(), 400);
    }

    #[test]
    fn a_body_that_does_not_fit_under_its_ceiling_is_refused() {
        let error = pad_under(&vec![0u8; 400], 400).unwrap_err();
        assert!(matches!(error, WireError::AboveCeiling { length: 400, ceiling: 400 }));
    }

    #[test]
    fn malformed_padding_is_refused() {
        assert_eq!(unpad(&[]).unwrap_err(), WireError::MalformedPadding);
        assert_eq!(unpad(&[0, 0, 0]).unwrap_err(), WireError::MalformedPadding);
        // No marker: the last non-zero byte is content, which is exactly the ambiguity the
        // scheme refuses to guess its way out of.
        assert_eq!(unpad(&[1, 2, 3, 0, 0]).unwrap_err(), WireError::MalformedPadding);
    }
}
