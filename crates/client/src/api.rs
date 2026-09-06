//! The delivery server's `/v1` surface, typed.
//!
//! Only what a headless client needs. The vault, recovery, pairing, presence, push and calls are
//! deliberately absent: a bot has no user to recover an account for, no second device to pair,
//! and no screen to show presence on. Adding them later is additive.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;

use crate::error::{ClientError, Result};
use crate::transport::Transport;

/// How many key packages a device keeps published.
///
/// At **zero, nobody can open a conversation with this device any more**, and nothing tells the
/// user: the failure lands on whoever is trying to reach them. A long-running client must watch
/// this and top it up, which is what [`Api::replenish_key_packages`] is for.
pub const KEY_PACKAGE_TARGET: usize = 10;

/// The stock level at which a client tops up rather than waiting to run dry.
pub const KEY_PACKAGE_LOW_WATER: i64 = 3;

/// One envelope out of a group's mailbox.
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope {
    /// Sequence number, assigned by the server. This, not any timestamp, is thread order.
    pub seq: i64,
    /// The opaque blob, base64.
    pub payload: String,
}

impl Envelope {
    /// The blob's bytes.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        B64.decode(&self.payload).map_err(|error| ClientError::Malformed {
            path: "envelope payload".to_owned(),
            reason: error.to_string(),
        })
    }
}

/// A page of a group's mailbox.
#[derive(Debug, Clone, Deserialize)]
pub struct EnvelopePage {
    /// The oldest sequence the server still holds for this group.
    ///
    /// Compared against a client's cursor, this is how a purge is detected before it is mistaken
    /// for a quiet conversation.
    pub oldest: i64,
    /// The envelopes after the requested cursor.
    pub envelopes: Vec<Envelope>,
}

#[derive(Debug, Deserialize)]
struct Stock {
    remaining: i64,
}

#[derive(Debug, Deserialize)]
struct Claimed {
    package: String,
    remaining: i64,
}

#[derive(Debug, Deserialize)]
struct Posted {
    seq: i64,
}

/// A key package taken from another device's stock, and what is left of it.
#[derive(Debug, Clone)]
pub struct ClaimedKeyPackage {
    /// The serialized KeyPackage, ready for `Conversation::invite`.
    pub package: Vec<u8>,
    /// What the target has left. Low is worth surfacing: at zero it becomes unreachable.
    pub remaining: i64,
}

/// Typed access to the routes a client needs.
pub struct Api {
    transport: Transport,
}

impl Api {
    /// Wraps a signed transport.
    #[must_use]
    pub const fn new(transport: Transport) -> Self {
        Self { transport }
    }

    /// The transport underneath, for the gateway and for callers doing something unusual.
    #[must_use]
    pub const fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Registers an account. Unsigned: there is no device yet to sign with.
    ///
    /// The account id is **derived** from the identity key, never assigned by the server, so
    /// the caller already knows it before this returns.
    pub async fn create_account(base_url: &str, handle: &str, identity_key: &[u8]) -> Result<()> {
        let response = reqwest::Client::new()
            .post(format!("{base_url}/v1/accounts"))
            .json(&serde_json::json!({
                "handle": handle,
                "identity_key": B64.encode(identity_key),
            }))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ClientError::Status {
                method: "POST",
                path: "/v1/accounts".to_owned(),
                status: response.status().as_u16(),
            })
        }
    }

    /// Registers a device under an account.
    ///
    /// Unsigned, but the attestation is verified: the server cannot add a device to an account
    /// on its own, which is the property that makes the device list trustworthy.
    pub async fn register_device(
        base_url: &str,
        device_id: &str,
        account_id: &str,
        auth_key: &[u8],
        mls_key: &[u8],
        attestation: &[u8],
    ) -> Result<()> {
        let response = reqwest::Client::new()
            .post(format!("{base_url}/v1/devices"))
            .json(&serde_json::json!({
                "id": device_id,
                "account": account_id,
                "auth_key": B64.encode(auth_key),
                "mls_key": B64.encode(mls_key),
                "attestation": B64.encode(attestation),
            }))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ClientError::Status {
                method: "POST",
                path: "/v1/devices".to_owned(),
                status: response.status().as_u16(),
            })
        }
    }

    /// How many key packages this device still has published.
    pub async fn key_package_stock(&self) -> Result<i64> {
        let stock: Stock = self.transport.get("/v1/key-packages/stock").await?;
        Ok(stock.remaining)
    }

    /// Publishes key packages.
    pub async fn publish_key_packages(&self, packages: &[Vec<u8>]) -> Result<()> {
        let encoded: Vec<String> = packages.iter().map(|package| B64.encode(package)).collect();
        let _: serde_json::Value = self
            .transport
            .post("/v1/key-packages", &serde_json::json!({ "packages": encoded }))
            .await?;
        Ok(())
    }

    /// Tops the stock back up to [`KEY_PACKAGE_TARGET`] if it has fallen to the low-water mark.
    ///
    /// Returns how many were published, so a caller can log the top-up rather than discover the
    /// stock was empty from a user who could not reach it.
    pub async fn replenish_key_packages(
        &self,
        identity: &crypto_core::Identity,
    ) -> Result<usize> {
        let remaining = self.key_package_stock().await?;
        if remaining > KEY_PACKAGE_LOW_WATER {
            return Ok(0);
        }

        let missing = KEY_PACKAGE_TARGET.saturating_sub(usize::try_from(remaining.max(0)).unwrap_or(0));
        let mut packages = Vec::with_capacity(missing);
        for _ in 0..missing {
            packages.push(identity.publish_key_package()?);
        }
        self.publish_key_packages(&packages).await?;
        Ok(missing)
    }

    /// Consumes one of another device's key packages, so it can be invited.
    ///
    /// Single-use and removed atomically: two concurrent callers cannot get the same one.
    pub async fn claim_key_package(&self, device_id: &str) -> Result<ClaimedKeyPackage> {
        let path = format!("/v1/key-packages/{device_id}/claim");
        let claimed: Claimed = self.transport.post(&path, &serde_json::json!({})).await?;

        Ok(ClaimedKeyPackage {
            package: B64.decode(&claimed.package).map_err(|error| ClientError::Malformed {
                path,
                reason: error.to_string(),
            })?,
            remaining: claimed.remaining,
        })
    }

    /// The groups the server says this device belongs to, hex-encoded.
    ///
    /// This is transport-level membership, not cryptographic membership: a device listed here
    /// but absent from the MLS tree fetches blobs it cannot decrypt. The tree is the truth.
    pub async fn groups(&self) -> Result<Vec<String>> {
        self.transport.get("/v1/groups").await
    }

    /// Declares who may read a group's mailbox.
    pub async fn add_members(&self, group_id: &[u8], device_ids: &[String]) -> Result<()> {
        let _: serde_json::Value = self
            .transport
            .post(
                &group_path(group_id, "/members"),
                &serde_json::json!({ "device_ids": device_ids }),
            )
            .await?;
        Ok(())
    }

    /// Posts an envelope and returns the sequence number the server assigned it.
    pub async fn post_envelope(&self, group_id: &[u8], payload: &[u8]) -> Result<i64> {
        let posted: Posted = self
            .transport
            .post(
                &group_path(group_id, "/envelopes"),
                &serde_json::json!({ "payload": B64.encode(payload) }),
            )
            .await?;
        Ok(posted.seq)
    }

    /// Reads a group's mailbox after a cursor.
    ///
    /// **Detects a purge before it becomes a mystery.** If the server's oldest surviving sequence
    /// is beyond the cursor, envelopes this device never read are gone; losing one breaks the MLS
    /// application ratchet for everything after it, so this returns [`ClientError::Gap`] rather
    /// than a short page that would look like a quiet conversation.
    pub async fn envelopes_after(&self, group_id: &[u8], cursor: i64) -> Result<Vec<Envelope>> {
        let path = group_path(group_id, &format!("/envelopes?after={cursor}"));
        let page: EnvelopePage = self.transport.get(&path).await?;

        if page.oldest > cursor + 1 && cursor > 0 {
            return Err(ClientError::Gap {
                group: hex::encode(group_id),
                oldest: page.oldest,
            });
        }

        Ok(page.envelopes)
    }
}

/// The path of a group's sub-resource. The id is hex on the wire.
#[must_use]
pub fn group_path(group_id: &[u8], suffix: &str) -> String {
    format!("/v1/groups/{}{}", hex::encode(group_id), suffix)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_group_path_is_hex() {
        assert_eq!(group_path(&[0xde, 0xad], "/envelopes"), "/v1/groups/dead/envelopes");
        assert_eq!(group_path(&[], ""), "/v1/groups/");
    }

    #[test]
    fn an_envelope_decodes_its_payload() {
        let envelope = Envelope { seq: 1, payload: "aGk=".to_owned() };
        assert_eq!(envelope.bytes().unwrap(), b"hi");
    }

    #[test]
    fn a_payload_that_is_not_base64_is_reported_and_not_guessed() {
        let envelope = Envelope { seq: 1, payload: "not base64!".to_owned() };
        assert!(matches!(envelope.bytes(), Err(ClientError::Malformed { .. })));
    }
}
