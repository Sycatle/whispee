//! Request authentication by Ed25519 signature.
//!
//! Every device registers an authentication public key, **distinct from its MLS signature key**.
//! Reusing one key for two protocols is a classic mistake: if the message formats overlap, a
//! signature produced in one becomes a valid signature in the other.
//!
//! So there is no password and no session token to steal server side: the database holds only
//! public keys.
//!
//! # Anti-replay
//!
//! Every request carries a nonce, covered by the signature and remembered on first presentation:
//! replaying it is refused.
//!
//! The nonce is **indispensable**, and cannot be replaced by the signature itself: Ed25519 is
//! deterministic, so two identical requests in the same second carry the same signature — one of
//! them possibly a replay while the other is legitimate. Claiming two KeyPackages back to back is
//! enough to produce the case.
//!
//! The memory need not outlive [`MAX_CLOCK_SKEW`]: beyond that, the timestamp refuses the request
//! anyway. See `migrations/0010_replay_protection.sql` for what that allows.
//!
//! **Limitation of the `UNLOGGED` table**, unstated in the migration and no longer addable there
//! — sqlx checks the fingerprint of every applied migration, so its text is frozen. PostgreSQL
//! empties an `UNLOGGED` table after a crash. The remembered nonces are then lost, and a captured
//! request becomes replayable again until the end of its tolerance window. The window is short
//! and the event rare, but the property is not "no replay possible": it is "no replay as long as
//! the database has not collapsed".
//!
//! # What this extractor no longer does
//!
//! Mark the device as awake. Presence used to be read here from every signed request, which put a
//! potential SQL write on the latency path of the whole server — for a coloured dot. It is now
//! fed by the [`crate::gateway`] heartbeat, a truer signal: an open session says a client is
//! there, where a request may come from a forgotten tab.
//!
//! Consequence to own: a client that never opens a session never appears online, even if it
//! queries the server. That is coherent — without a session it is not reachable in real time
//! anyway — but it is a behaviour change, not a transparent optimisation.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::error::{ApiError, ApiResult};

/// Clock skew tolerated between client and server.
pub const MAX_CLOCK_SKEW: u64 = 60;

pub const HEADER_DEVICE: &str = "x-device-id";
pub const HEADER_TIMESTAMP: &str = "x-timestamp";
pub const HEADER_SIGNATURE: &str = "x-signature";
pub const HEADER_NONCE: &str = "x-nonce";

/// Length of the anti-replay nonce.
///
/// Sixteen random bytes: the odds of a device drawing one already remembered are negligible
/// against the sixty-second window, and a collision would cost a plain refusal anyway, not a
/// vulnerability.
pub const NONCE_LEN: usize = 16;

/// Authenticated request: the caller proved possession of `device_id`'s private key.
pub struct Signed {
    pub device_id: String,
    pub body: Bytes,
}

/// The message actually signed.
///
/// The method and the path are part of it: without them, a signature valid for `GET /stock` would
/// be replayable on `POST /envelopes`. The body is included by its fingerprint, which avoids
/// holding it in memory twice.
///
/// The nonce is what makes the message unique when everything else is identical — two similar
/// requests in the same second would otherwise produce the same signature, Ed25519 being
/// deterministic. It is **inside the signed message**, so a third party cannot replay a captured
/// request by merely changing the header's nonce.
pub fn signing_payload(
    method: &str,
    path: &str,
    timestamp: u64,
    nonce: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(method.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(path.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(timestamp.to_string().as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(nonce);
    payload.push(b'\n');
    payload.extend_from_slice(&Sha256::digest(body));
    payload
}

impl<S> FromRequest<S> for Signed
where
    S: Send + Sync,
    PgPool: axum::extract::FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        use axum::extract::FromRef;

        // Everything coming from the request is extracted into owned values before the first
        // `await`: holding a borrow on `request` across a suspension point would make the future
        // non-`Send`, and axum requires `Send` handlers.
        let (device_id, timestamp, signature, nonce, method, path) = {
            let headers = request.headers();
            let header = |name: &str| -> Option<String> {
                headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
            };

            let device_id = header(HEADER_DEVICE).ok_or(ApiError::Unauthorized)?;
            let timestamp: u64 = header(HEADER_TIMESTAMP)
                .and_then(|t| t.parse().ok())
                .ok_or(ApiError::Unauthorized)?;
            let signature = header(HEADER_SIGNATURE).ok_or(ApiError::Unauthorized)?;
            let nonce = header(HEADER_NONCE).ok_or(ApiError::Unauthorized)?;

            let method = request.method().as_str().to_owned();
            let path = request
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_else(|| request.uri().path().to_owned());

            (device_id, timestamp, signature, nonce, method, path)
        };

    let nonce = BASE64_STANDARD
        .decode(nonce)
        .ok()
        .filter(|bytes| bytes.len() == NONCE_LEN)
        .ok_or(ApiError::Unauthorized)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApiError::Unauthorized)?
            .as_secs();
        if now.abs_diff(timestamp) > MAX_CLOCK_SKEW {
            return Err(ApiError::Unauthorized);
        }

        let pool = PgPool::from_ref(state);
        let body = Bytes::from_request(request, state)
            .await
            .map_err(|_| ApiError::BadRequest("unreadable body"))?;

        let auth_key: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT auth_key FROM devices WHERE id = $1")
                .bind(&device_id)
                .fetch_optional(&pool)
                .await?;

        // An unknown device and an invalid signature return the same error: telling them apart
        // would allow enumerating registered devices.
        let (auth_key,) = auth_key.ok_or(ApiError::Unauthorized)?;

        let verifying_key: [u8; 32] = auth_key.try_into().map_err(|_| ApiError::Unauthorized)?;
        let verifying_key =
            VerifyingKey::from_bytes(&verifying_key).map_err(|_| ApiError::Unauthorized)?;

        let signature = BASE64_STANDARD
            .decode(signature)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .map(|bytes| Signature::from_bytes(&bytes))
            .ok_or(ApiError::Unauthorized)?;

        verifying_key
            .verify_strict(&signing_payload(&method, &path, timestamp, &nonce, &body), &signature)
            .map_err(|_| ApiError::Unauthorized)?;

        // Anti-replay, **after** verification: remembering an invalid signature would let anyone
        // fill the table without holding a key.
        //
        // Awaited, unlike presence used to be. A detached write would protect nothing — the
        // replay would pass while it is in flight. That is the price of the guarantee, and it
        // applies to every signed request.
        //
        // Uniqueness is carried by the primary key: a `SELECT` then an `INSERT` would let two
        // concurrent requests both through.
        let first_time = sqlx::query(
            "INSERT INTO request_nonces (device_id, nonce) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(&device_id)
        .bind(&nonce)
        .execute(&pool)
        .await?;

        if first_time.rows_affected() == 0 {
            return Err(ApiError::Unauthorized);
        }

        Ok(Self { device_id, body })
    }
}

impl Signed {
    /// Deserialises the signed body. The signature covers the exact bytes received, so
    /// deserialisation only happens after verification.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> ApiResult<T> {
        serde_json::from_slice(&self.body).map_err(|_| ApiError::BadRequest("invalid JSON"))
    }
}
