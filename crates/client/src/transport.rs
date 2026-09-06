//! Signed HTTP, the only way to talk to a Whispee server as a device.
//!
//! There is no session and no token: the server stores public keys and nothing else. Every
//! request carries `x-device-id`, `x-timestamp`, `x-signature` and `x-nonce`, and the signature
//! covers the method, the path, the timestamp, the nonce and a digest of the body — see
//! [`attest::http_signing_payload`].
//!
//! Two consequences a caller must plan for:
//!
//! - **The clock matters.** The server allows sixty seconds of skew. A host whose clock drifts
//!   stops being able to talk at all, with a 401 that says nothing about why, so a long-running
//!   client belongs on a machine that runs NTP.
//! - **The path is signed as sent.** A query string is part of the path, so it has to be built
//!   once and used for both, which is why [`Transport::get`] takes the full path rather than
//!   letting a caller append parameters afterwards.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::{OsRng, RngCore};

use crate::error::{ClientError, Result};

/// A device's authentication key and the server it speaks to.
///
/// This key is **distinct from the MLS signature key**. Reusing one key for two protocols is a
/// classic mistake, and the two are attested together precisely so that one device's attestation
/// cannot be recombined with another's MLS key.
pub struct Transport {
    base_url: String,
    device_id: String,
    signing_key: SigningKey,
    http: reqwest::Client,
}

impl Transport {
    /// Binds a device identity to a server.
    #[must_use]
    pub fn new(base_url: impl Into<String>, device_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            base_url: base_url.into(),
            device_id: device_id.into(),
            signing_key,
            http: reqwest::Client::new(),
        }
    }

    /// The device this transport signs as.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The server it points at.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The authentication key, for the callers that have to sign something else — a gateway
    /// challenge, for instance.
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// A signed GET, decoded as JSON.
    pub async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send("GET", path, Vec::new()).await
    }

    /// A signed POST, decoded as JSON.
    pub async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let body = serde_json::to_vec(body).map_err(|error| ClientError::Malformed {
            path: path.to_owned(),
            reason: format!("request body is not serialisable: {error}"),
        })?;
        self.send("POST", path, body).await
    }

    /// A signed POST whose body is raw bytes rather than JSON.
    ///
    /// Attachments go up this way: they are already ciphertext, and base64 in a JSON envelope
    /// would cost a third more bandwidth on the largest write the server accepts.
    pub async fn post_bytes<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<T> {
        self.send("POST", path, body).await
    }

    /// A signed GET returning raw bytes.
    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let response = self.raw("GET", path, Vec::new()).await?;
        let status = response.status();

        if !status.is_success() {
            return Err(ClientError::Status {
                method: "GET",
                path: path.to_owned(),
                status: status.as_u16(),
            });
        }

        Ok(response.bytes().await?.to_vec())
    }

    /// A signed request whose status is returned rather than raised.
    ///
    /// For the callers that expect a refusal and need to tell which one — a bot checking that a
    /// stranger's mailbox is closed to it, say.
    pub async fn status(&self, method: &'static str, path: &str) -> Result<u16> {
        Ok(self.raw(method, path, Vec::new()).await?.status().as_u16())
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<T> {
        let response = self.raw(method, path, body).await?;
        let status = response.status();

        if !status.is_success() {
            return Err(ClientError::Status {
                method,
                path: path.to_owned(),
                status: status.as_u16(),
            });
        }

        response.json().await.map_err(|error| ClientError::Malformed {
            path: path.to_owned(),
            reason: error.to_string(),
        })
    }

    async fn raw(
        &self,
        method: &'static str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let timestamp = unix_seconds();
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        let payload = attest::http_signing_payload(method, path, timestamp, &nonce, &body);
        let signature = self.signing_key.sign(&payload);

        let request = self
            .http
            .request(
                reqwest::Method::from_bytes(method.as_bytes())
                    .expect("methods are compile-time constants in this crate"),
                format!("{}{path}", self.base_url),
            )
            .header("x-device-id", &self.device_id)
            .header("x-timestamp", timestamp.to_string())
            .header("x-signature", B64.encode(signature.to_bytes()))
            .header("x-nonce", B64.encode(nonce))
            .header("content-type", "application/json")
            .body(body);

        Ok(request.send().await?)
    }
}

/// Seconds since the epoch.
///
/// A clock before 1970 is not a case worth a branch: the request would be rejected by the server
/// anyway, sixty seconds of skew being the whole allowance.
pub(crate) fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Milliseconds since the epoch, for the timestamps that go inside messages.
#[must_use]
pub fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The one property this module has that can be checked without a server: the bytes it signs
    /// are the ones `attest` defines. A transport that built its own payload would fail every
    /// request with a 401 and no explanation.
    #[test]
    fn the_signed_payload_is_the_canonical_one() {
        let payload = attest::http_signing_payload("GET", "/v1/groups", 1_700_000_000, &[7u8; 16], b"");
        let expected = {
            use sha2::{Digest, Sha256};
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"GET\n/v1/groups\n1700000000\n");
            bytes.extend_from_slice(&[7u8; 16]);
            bytes.push(b'\n');
            bytes.extend_from_slice(&Sha256::digest(b""));
            bytes
        };
        assert_eq!(payload, expected);
    }

    /// Two requests that are identical in every other respect must not produce the same
    /// signature: Ed25519 is deterministic, so the nonce is what separates them, and a nonce
    /// that repeated would make a captured request replayable.
    #[test]
    fn the_nonce_makes_identical_requests_differ() {
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        OsRng.fill_bytes(&mut first);
        OsRng.fill_bytes(&mut second);
        assert_ne!(first, second);

        let a = attest::http_signing_payload("GET", "/v1/groups", 1, &first, b"");
        let b = attest::http_signing_payload("GET", "/v1/groups", 1, &second, b"");
        assert_ne!(a, b);
    }

    #[test]
    fn the_body_is_covered_by_the_signature() {
        let a = attest::http_signing_payload("POST", "/v1/x", 1, &[0u8; 16], b"one");
        let b = attest::http_signing_payload("POST", "/v1/x", 1, &[0u8; 16], b"two");
        assert_ne!(a, b, "a tampered body must not verify against the original signature");
    }
}
