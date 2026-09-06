//! Attachments: encrypted here, opaque to the server, and padded like everything else.
//!
//! The blob the server stores is AES-256-GCM ciphertext. Its key, its nonce, the file's name and
//! its declared type travel **inside the MLS message**, in an [`AttachmentRef`] — they are facts
//! about the content, and the server has no reason to know them.
//!
//! # Padded before encryption, and it has to be that way round
//!
//! Padding the ciphertext would leave the true length readable at the point where the recipient
//! strips it, and would tell the server nothing less.
//!
//! # The tag is the integrity check
//!
//! If the server substitutes or alters a blob, decryption fails rather than returning forged
//! bytes. No separate digest is needed.
//!
//! # The declared type is a hint
//!
//! `mime` is whatever the sender wrote. A caller that renders it must never do so inline on its
//! own origin: an SVG or an HTML file displayed that way runs script with the user's keys within
//! reach.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use wire::content::AttachmentRef;
use wire::padding;

use crate::api::{Api, group_path};
use crate::error::{ClientError, Result};

/// What the server refuses a request body above.
const SERVER_CEILING: usize = 25 * 1024 * 1024;

/// The GCM tag the ciphertext carries on top of the padded plaintext.
const GCM_TAG: usize = 16;

/// The largest bucket padding may reach, leaving room for the tag under the ceiling.
const TOP_BUCKET: usize = SERVER_CEILING - GCM_TAG;

/// The largest file that can be sent.
///
/// One below the top bucket: a file of exactly `TOP_BUCKET` bytes would have to pad past the
/// ceiling, since the marker always costs a byte.
pub const MAX_ATTACHMENT_BYTES: usize = TOP_BUCKET - 1;

#[derive(Debug, Deserialize)]
struct Uploaded {
    id: String,
}

/// Encrypts a file, uploads it, and returns the descriptor to put in the message.
///
/// The descriptor is **not** sent anywhere by this function: the caller puts it in a
/// [`wire::content::Content::Attachment`] and sends that through the group, which is the only
/// path on which the key is protected.
pub async fn upload(api: &Api, group_id: &[u8], name: &str, mime: &str, plaintext: &[u8]) -> Result<AttachmentRef> {
    if plaintext.len() > MAX_ATTACHMENT_BYTES {
        return Err(ClientError::Malformed {
            path: "attachment".to_owned(),
            reason: format!(
                "{} bytes is above the {MAX_ATTACHMENT_BYTES} byte ceiling",
                plaintext.len()
            ),
        });
    }

    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);

    let padded = padding::pad_under(plaintext, TOP_BUCKET)?;
    let ciphertext = Aes256Gcm::new(&key.into())
        .encrypt(Nonce::from_slice(&iv), Payload { msg: &padded, aad: &[] })
        .map_err(|_| ClientError::Malformed {
            path: "attachment".to_owned(),
            reason: "encryption failed".to_owned(),
        })?;

    let uploaded: Uploaded = api
        .transport()
        .post_bytes(&group_path(group_id, "/attachments"), ciphertext)
        .await?;

    Ok(AttachmentRef {
        id: uploaded.id,
        key: B64.encode(key),
        iv: B64.encode(iv),
        name: name.to_owned(),
        mime: mime.to_owned(),
        size: plaintext.len() as u64,
        padded: Some(true),
    })
}

/// Fetches an attachment and returns its plaintext.
///
/// A descriptor without `padded` was written before padding existed; its blob is taken as-is.
/// Malformed padding is an error rather than a guess: the bytes carry a valid GCM tag, so they
/// are the ones the sender encrypted, and a tail that does not parse means the two clients
/// disagree about the format. Returning a plausible prefix would hide that behind a corrupt file.
pub async fn download(api: &Api, group_id: &[u8], reference: &AttachmentRef) -> Result<Vec<u8>> {
    let path = group_path(group_id, &format!("/attachments/{}", reference.id));
    let ciphertext = api.transport().get_bytes(&path).await?;

    let key: [u8; 32] = decode_exact(&reference.key, "attachment key")?;
    let iv: [u8; 12] = decode_exact(&reference.iv, "attachment nonce")?;

    let plaintext = Aes256Gcm::new(&key.into())
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ciphertext, aad: &[] })
        .map_err(|_| ClientError::Malformed {
            path: "attachment".to_owned(),
            reason: "decryption failed: the blob is not the one the sender encrypted".to_owned(),
        })?;

    if reference.padded.unwrap_or(false) {
        Ok(padding::unpad(&plaintext)?.to_vec())
    } else {
        Ok(plaintext)
    }
}

fn decode_exact<const N: usize>(encoded: &str, what: &'static str) -> Result<[u8; N]> {
    let bytes = B64.decode(encoded).map_err(|_| ClientError::Malformed {
        path: what.to_owned(),
        reason: "not base64".to_owned(),
    })?;

    bytes.try_into().map_err(|_| ClientError::Malformed {
        path: what.to_owned(),
        reason: format!("expected {N} bytes"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The ceiling exists so that a file plus its padding plus the tag still fits in what the
    /// server accepts. If that stops holding, uploads start failing at the far end with a 413.
    #[test]
    fn the_largest_allowed_file_still_fits_under_the_server_ceiling() {
        let padded = padding::pad_under(&vec![0u8; MAX_ATTACHMENT_BYTES], TOP_BUCKET).unwrap();
        assert!(
            padded.len() + GCM_TAG <= SERVER_CEILING,
            "a maximal file pads to {} bytes, which with the tag exceeds {SERVER_CEILING}",
            padded.len()
        );
    }

    #[test]
    fn one_byte_more_does_not_fit() {
        assert!(padding::pad_under(&vec![0u8; MAX_ATTACHMENT_BYTES + 1], TOP_BUCKET).is_err());
    }

    #[test]
    fn a_key_of_the_wrong_size_is_refused_rather_than_padded() {
        assert!(decode_exact::<32>(&B64.encode([0u8; 16]), "key").is_err());
        assert!(decode_exact::<32>("not base64!", "key").is_err());
        assert!(decode_exact::<32>(&B64.encode([0u8; 32]), "key").is_ok());
    }
}
