//! HTTP endpoints.
//!
//! The server is a blind mailbox: it routes opaque blobs, keeps the total message order per
//! group, and can decrypt nothing.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::AppState;
use crate::auth::Signed;
use crate::error::{ApiError, ApiResult};
use crate::presence;
use crate::stream::{Hub, Notice};
use crate::throttle::{Writes, Written};

/// Cap on the number of KeyPackages published in one request. Without it, a single device can
/// fill the database on its own.
const MAX_KEY_PACKAGES_PER_REQUEST: usize = 100;

/// A device row as served: id, auth key, MLS key, attestation. Named so that the query
/// signatures stay readable.
type DeviceRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

/// A device and its revocation state, as served to clients.
type RevocableDeviceRow =
    (String, Vec<u8>, Vec<u8>, Vec<u8>, Option<i64>, Option<Vec<u8>>, Option<i64>);

/// Cap on a post body, aligned with the HTTP layer's limit.
///
/// Defined here because the anonymous path reads the body itself, outside the `Signed` extractor
/// and therefore outside the layer's limit. Without an explicit cap it would be the only
/// unbounded path in the server.
const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Cap on envelopes returned per call. The client pages with the `after` cursor.
const MAX_ENVELOPES_PER_PAGE: i64 = 200;

/// Small-body routes: MLS messages, KeyPackages, group management.
///
/// Kept apart from attachments so each family carries its own size limit. A single cap would
/// force us either to forbid files or to allow megabytes on endpoints that never need them.
/// **Open** routes, meaning routes where authentication is not even possible.
///
/// They predate the existence of an identity: an account creation cannot be signed with a key
/// the server does not know yet. They are isolated here to carry the only bound left to them —
/// a per-address rate limit.
///
/// Split out like [`attachment_router`] already is, for the same reason: a family of routes that
/// needs a particular layer carries it alone, rather than imposing it on all of them.
///
/// **Account creation is what justifies the whole thing.** It writes to the transparency log,
/// whose entries cannot be taken back without breaking the consistency proofs. See
/// `crate::throttle` for what the limit closes, and for what it does not.
pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/accounts", post(create_account))
        .route("/v1/devices", post(register_device))
        .route("/v1/pairings/{pairing_id}", post(deposit_pairing).get(claim_pairing))
        .with_state(state)
}

/// The authenticated routes.
///
/// # Why the handle-taking read routes do not call `crate::handle::validate`
///
/// `list_account_devices`, `log_proof`, `rotate_account` and `read_presence` all take a handle
/// and all of them only ever *look one up*. Validating there would be free to write and would be
/// a small mistake: it splits one outcome into two. Today a handle that is not an account —
/// malformed or merely unknown — comes back as a single 404, and `read_presence` simply omits it
/// from the list. Adding a 400 would let an unauthenticated-adjacent caller separate "this string
/// could never be an account" from "this string could be one and is not", which is a distinction
/// the reader has no use for and a prober does.
///
/// It would also buy nothing on the storage side. Since `create_account` is the only way a
/// handle enters `accounts`, and `migrations/0013_handle_format.sql` holds the same rule as a
/// CHECK, a malformed handle cannot match a row — the query is a guaranteed miss, and a
/// guaranteed miss is exactly the behaviour wanted.
///
/// The write path is the opposite case and does validate: `create_account` and `register_device`
/// *create* the value, and a value created out of shape stays out of shape forever.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/gateway", get(crate::gateway::handler))
        .route("/v1/presence", post(read_presence))
        .route("/v1/presence/optout", post(set_presence_optout))
        .route("/v1/push/token", post(set_push_token))
        .route("/v1/push/forget", post(forget_push_token))
        .route("/v1/accounts/{handle}/devices", get(list_account_devices))
        .route("/v1/accounts/{handle}/rotate", post(rotate_account))
        .route("/v1/log/sth", get(log_head))
        .route("/v1/log/proof/{handle}", get(log_proof))
        .route("/v1/log/consistency", get(log_consistency))
        .route("/v1/devices/{device_id}/revoke", post(revoke_device))
        .route("/v1/vault/{group_id}", post(store_vault).get(fetch_vault))
        .route("/v1/key-packages", post(publish_key_packages))
        .route("/v1/key-packages/stock", get(key_package_stock))
        .route("/v1/key-packages/{device_id}/claim", post(claim_key_package))
        .route("/v1/groups", get(list_groups))
        .route("/v1/groups/{group_id}/members", post(add_members))
        .route("/v1/groups/{group_id}/members/remove", post(remove_members))
        .route("/v1/groups/{group_id}/signals", post(post_signal))
        .route(
            "/v1/groups/{group_id}/envelopes",
            post(post_envelope).get(fetch_envelopes),
        )
        .with_state(state)
}

/// Attachment routes, isolated to carry a higher body limit.
///
/// Takes the whole [`AppState`] rather than a bare pool, unlike when it was written: an upload
/// is counted against a per-device quota, and the counter lives in the state. The handlers still
/// extract `State<PgPool>` — `FromRef` derives it — so only the family's own limiter had to be
/// threaded through.
pub fn attachment_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/groups/{group_id}/attachments", post(upload_attachment))
        .route(
            "/v1/groups/{group_id}/attachments/{attachment_id}",
            get(download_attachment),
        )
        .with_state(state)
}

fn decode_b64(value: &str) -> ApiResult<Vec<u8>> {
    BASE64_STANDARD
        .decode(value)
        .map_err(|_| ApiError::BadRequest("invalid base64"))
}

pub(crate) fn decode_group_id(value: &str) -> ApiResult<Vec<u8>> {
    let bytes = hex::decode(value).map_err(|_| ApiError::BadRequest("invalid group_id"))?;
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(ApiError::BadRequest("invalid group_id length"));
    }
    Ok(bytes)
}

/// Cap on an ephemeral signal.
///
/// An encrypted typing indicator fits in a few dozen bytes; this cap is not a format constraint
/// but the bound that keeps this path — which reads the body itself, outside the HTTP layer —
/// from being the only unbounded one in the server.
pub(crate) const MAX_SIGNAL_BYTES: usize = 4096;

/// Verifies a membership MAC over an already built canonical message.
///
/// Extracted so that envelope posting and signal posting share exactly the same check: two
/// copies would drift apart, and the forgotten copy is the one that becomes the hole.
fn verify_group_mac(posting_key: &[u8], message: &[u8], mac: &[u8]) -> ApiResult<()> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut hmac = <Hmac<Sha256>>::new_from_slice(posting_key)
        .expect("HMAC-SHA256 accepts any key length");
    hmac.update(message);
    hmac.verify_slice(mac).map_err(|_| ApiError::Forbidden)
}

/// Relays an ephemeral signal to connected members, **writing nothing**.
///
/// # Why a route separate from envelope posting
///
/// Because an envelope is kept, and kept for a long time: `crate::purge_once` only deletes one
/// past thirty days and five hundred sequences behind the group's head, and a quiet conversation
/// never reaches that second condition at all. Routing a typing indicator through that path
/// would keep the trace of who hesitated before answering for a month in a busy group and
/// forever in a calm one.
///
/// The retention does not soften the reason, it only renames it: what used to be "kept forever"
/// is now "kept long enough that keeping it is the same mistake".
///
/// This path has no table. The signal exists for the duration of a relay, then no longer exists.
///
/// # No replay protection, deliberately
///
/// Unlike envelope posting, no nonce is consumed: replaying a stale signal has no observable
/// effect past its client-side expiry, and recording a nonce every three seconds per
/// conversation would grow a table for nothing — writing to disk exactly what this route exists
/// not to write.
///
/// Abuse stays bounded by what matters: you must hold the group key, hence be a member, and a
/// member already has a more harmful option — posting envelopes, which *are* kept.
async fn post_signal(
    State(pool): State<PgPool>,
    State(hub): State<Arc<Hub>>,
    Path(group_id): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<axum::http::StatusCode> {
    let group_id = decode_group_id(&group_id)?;

    // Owned extraction before the first `await`: see the note in `anonymous_body`.
    let (nonce, mac) = {
        let headers = request.headers();
        let header = |name: &str| -> ApiResult<Vec<u8>> {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| BASE64_STANDARD.decode(value).ok())
                .ok_or(ApiError::BadRequest("signal header missing or unreadable"))
        };

        (header(HEADER_NONCE)?, header(HEADER_MAC)?)
    };

    let body = axum::body::to_bytes(request.into_body(), MAX_SIGNAL_BYTES)
        .await
        .map_err(|_| ApiError::BadRequest("unreadable body"))?;

    verify_signal(&pool, &group_id, &nonce, &mac, &body).await?;

    hub.publish(Notice::Signal { group_id, payload: body.to_vec() });

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Checks that an ephemeral signal comes from a group member, without learning which one.
///
/// Extracted so that the HTTP path and the gateway's `signal` frame share **exactly** the same
/// check. Same argument that led to extracting [`verify_group_mac`]: two copies drift apart, and
/// the one nobody remembered to fix becomes the hole.
///
/// Publishes nothing: the caller decides on the broadcast, because the gateway and the HTTP
/// route do not hold the hub the same way.
pub(crate) async fn verify_signal(
    pool: &PgPool,
    group_id: &[u8],
    nonce: &[u8],
    mac: &[u8],
    body: &[u8],
) -> ApiResult<()> {
    use sha2::{Digest, Sha256};

    if nonce.len() != 16 {
        return Err(ApiError::BadRequest("invalid signal nonce"));
    }

    if body.len() > MAX_SIGNAL_BYTES {
        return Err(ApiError::BadRequest("signal too large"));
    }

    let (posting_key,): (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT posting_key FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_optional(pool)
            .await?
            .ok_or(ApiError::NotFound)?;

    // A group with no posting key has not migrated to the anonymous path yet: refuse rather
    // than fall back to an identity check, which would make the gateway the one place in the
    // server where a signal reveals its author.
    let posting_key = posting_key.ok_or(ApiError::Forbidden)?;

    let message = attest::signal_message(group_id, nonce, &Sha256::digest(body))
        .map_err(|_| ApiError::BadRequest("malformed signal"))?;

    verify_group_mac(&posting_key, &message, mac)
}

/// Checks that the caller is a member of the group.
///
/// A random group id is **not** access control: without this check, anyone who guesses or
/// intercepts an id reads the whole mailbox.
async fn require_membership(pool: &PgPool, group_id: &[u8], device_id: &str) -> ApiResult<()> {
    // The join on `devices` is what cuts a revoked device off from the stream, without waiting
    // for the group to commit its removal.
    //
    // **This is defence in depth, not the real protection.** A revoked device still holds the
    // group secrets: it decrypts anything it intercepts by another route, and nothing here
    // stops it. Only the MLS `Remove` — which re-keys the tree — actually cuts it off from what
    // follows. This filter closes the immediate leak during the seconds or hours between the
    // revocation and the commit.
    let member: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM group_members m
         JOIN devices d ON d.id = m.device_id
         WHERE m.group_id = $1 AND m.device_id = $2 AND d.revoked_at IS NULL",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await?;

    member.map(|_| ()).ok_or(ApiError::Forbidden)
}

/// Same question, asked by a caller that does not fail on a refusal.
///
/// The gateway answers a rejected `subscribe` with an error frame and keeps the session open,
/// where an HTTP route returns a status and stops. The check remains the one in
/// [`require_membership`] — one query, one definition of "member".
pub(crate) async fn is_member(
    pool: &PgPool,
    group_id: &[u8],
    device_id: &str,
) -> ApiResult<bool> {
    match require_membership(pool, group_id, device_id).await {
        Ok(()) => Ok(true),
        Err(ApiError::Forbidden) => Ok(false),
        Err(other) => Err(other),
    }
}

#[derive(Deserialize)]
struct CreateAccount {
    handle: String,
    /// Account's Ed25519 public key (AIK), base64.
    identity_key: String,
}

/// Creates a pseudonymous account. Unsigned — no known key exists yet.
///
/// This is **trust on first use**: the server believes the first claimant of a handle. Claiming
/// the same handle with the same key is idempotent (reinstall); with a different key it is
/// refused, which prevents a pseudonym from being silently taken over.
///
/// What TOFU does not prove: that the first claimant was legitimate. There is no answer to that
/// without an external authority or key transparency — out of scope, documented in the README.
async fn create_account(
    State(pool): State<PgPool>,
    Json(payload): Json<CreateAccount>,
) -> ApiResult<Json<serde_json::Value>> {
    // The one place a handle enters the system. Every other route reads a handle that got in
    // through here, so this is where the format is imposed rather than merely hoped for — see
    // `crate::handle` for what `^[a-z0-9_]{3,32}$` buys and what it explicitly does not.
    crate::handle::validate(&payload.handle).map_err(ApiError::BadRequest)?;

    let identity_key = decode_b64(&payload.identity_key)?;
    if identity_key.len() != 32 {
        return Err(ApiError::BadRequest("Ed25519 key expected (32 bytes)"));
    }

    let mut tx = pool.begin().await?;

    let inserted = sqlx::query(
        "INSERT INTO accounts (handle, identity_key) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&payload.handle)
    .bind(&identity_key)
    .execute(&mut *tx)
    .await?;

    // The account and its log entry in the **same** transaction. A key published without an
    // inclusion proof would be rejected by every client: the account would exist without being
    // reachable, and nothing would say why.
    if inserted.rows_affected() > 0 {
        crate::log::append(&mut tx, &payload.handle, &identity_key).await?;
    }

    tx.commit().await?;

    if inserted.rows_affected() == 0 {
        let existing: (Vec<u8>,) =
            sqlx::query_as("SELECT identity_key FROM accounts WHERE handle = $1")
                .bind(&payload.handle)
                .fetch_one(&pool)
                .await?;

        if existing.0 != identity_key {
            return Err(ApiError::Conflict("handle already taken by another account"));
        }
    }

    Ok(Json(serde_json::json!({ "handle": payload.handle })))
}

#[derive(Deserialize)]
struct RegisterDevice {
    id: String,
    handle: String,
    /// Ed25519 public key used to authenticate HTTP requests, base64.
    auth_key: String,
    /// This device's MLS signature public key, base64.
    mls_key: String,
    /// Account signature over all of the fields above, base64.
    attestation: String,
}

/// Registers a device and its attested attachment to an account.
///
/// Unsigned by the device — it has no known key yet — but **the attestation is verified**. This
/// is the only place in the server that does cryptography, and it is access control: without it
/// anyone could declare a device in anyone's account, which would hand the server (and everyone
/// else) the power to get invited into other people's conversations.
///
/// This check is **not** the guarantee clients rely on: each of them re-verifies for itself on
/// read. A server that lied here would only fool itself.
async fn register_device(
    State(pool): State<PgPool>,
    Json(payload): Json<RegisterDevice>,
) -> ApiResult<Json<serde_json::Value>> {
    if payload.id.is_empty() || payload.id.len() > 128 {
        return Err(ApiError::BadRequest("invalid device id"));
    }

    // The device id is qualified by the handle: `alice:phone`.
    //
    // Otherwise the id space is global and the first arrival hogs the common names — the second
    // user who wants to call their phone "phone" is refused registration, despite holding a
    // perfectly legitimate account. The prefix makes the namespace local to the account; the
    // attestation guarantees nobody can claim someone else's prefix.
    //
    // This is a **split**, not a `starts_with`, and that only became correct with
    // `crate::handle`. A handle can no longer contain `:`, so the first `:` in a device id is
    // unambiguously the separator and the left-hand side is the whole handle and nothing else.
    // Before the format existed, `alice:phone` was itself a legal handle, so the device id
    // `alice:phone:laptop` started with the prefix of *two* different accounts and the check
    // handed the second one a foothold in the first one's namespace. Validating the handle here
    // as well as splitting is what closes the other half: a prefix comparison against an
    // unvalidated handle would still let a colon-bearing string through if this route were ever
    // reached before `create_account` — which it can be, since a device may be registered
    // against an account that does not exist and the lookup below is what refuses it.
    crate::handle::validate(&payload.handle).map_err(ApiError::BadRequest)?;

    let Some((prefix, _name)) = payload.id.split_once(':') else {
        return Err(ApiError::BadRequest(
            "device id must be prefixed with the account handle",
        ));
    };
    if prefix != payload.handle {
        return Err(ApiError::BadRequest(
            "device id must be prefixed with the account handle",
        ));
    }

    let auth_key = decode_b64(&payload.auth_key)?;
    if auth_key.len() != 32 {
        return Err(ApiError::BadRequest("Ed25519 key expected (32 bytes)"));
    }

    let mls_key = decode_b64(&payload.mls_key)?;
    if mls_key.is_empty() || mls_key.len() > 128 {
        return Err(ApiError::BadRequest("invalid MLS signature key"));
    }

    let attestation = decode_b64(&payload.attestation)?;

    let account: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT identity_key FROM accounts WHERE handle = $1")
            .bind(&payload.handle)
            .fetch_optional(&pool)
            .await?;
    let (identity_key,) = account.ok_or(ApiError::NotFound)?;

    let claim = attest::DeviceClaim {
        handle: &payload.handle,
        device_id: &payload.id,
        auth_key: &auth_key,
        mls_key: &mls_key,
    };
    attest::verify(&identity_key, &claim, &attestation)
        .map_err(|_| ApiError::BadRequest("invalid attestation"))?;

    // `DO UPDATE` on the attestation only, and only if the keys are unchanged.
    //
    // This is what lets a device **re-attest after an account rotation**: its original
    // attestation, signed by the dead key, no longer verifies for anyone. Without this update,
    // the very device that triggered the rotation would be rejected by every client, including
    // its own.
    //
    // The operation cannot install a dubious attestation: it was just verified against the
    // account's current key, a few lines above. The `WHERE` clause does forbid changing an
    // existing device's keys — that would be another device under the same name.
    let inserted = sqlx::query(
        "INSERT INTO devices (id, handle, auth_key, mls_key, attestation)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO UPDATE SET attestation = EXCLUDED.attestation
         WHERE devices.auth_key = EXCLUDED.auth_key AND devices.mls_key = EXCLUDED.mls_key",
    )
    .bind(&payload.id)
    .bind(&payload.handle)
    .bind(&auth_key)
    .bind(&mls_key)
    .bind(&attestation)
    .execute(&pool)
    .await?;

    if inserted.rows_affected() == 0 {
        // Idempotent re-registration after a reinstall, refused if any field differs: a device
        // changes neither its keys nor its account, it creates a new one.
        let existing: (String, Vec<u8>, Vec<u8>) =
            sqlx::query_as("SELECT handle, auth_key, mls_key FROM devices WHERE id = $1")
                .bind(&payload.id)
                .fetch_one(&pool)
                .await?;

        if existing != (payload.handle.clone(), auth_key, mls_key) {
            return Err(ApiError::Conflict("id already taken by another device"));
        }
    }

    Ok(Json(serde_json::json!({ "id": payload.id })))
}

#[derive(Serialize)]
struct AccountDevice {
    id: String,
    auth_key: String,
    mls_key: String,
    attestation: String,
    /// Revocation timestamp in Unix seconds, `None` if the device is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<u64>,
    /// Matching certificate, base64. Present exactly when `revoked_at` is — the database
    /// enforces it (`revocation_matches_revoked_at`, migration 0005).
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation: Option<String>,
    /// This device's last activity, **served to the account owner only**.
    ///
    /// Per-device detail never leaves towards a third party: it would say how many devices a
    /// person owns and which one they use at what time, a leak distinct from "online". For the
    /// owner, on the other hand, it is what makes a genuinely active ghost device visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<i64>,
}

#[derive(Serialize)]
struct AccountDevices {
    handle: String,
    identity_key: String,
    devices: Vec<AccountDevice>,
}

/// Lists an account's devices, with their attestations.
///
/// **The caller must re-verify every attestation itself.** This endpoint is the exact surface a
/// malicious server would use to slip in a ghost device; everything it returns is a claim, not
/// a fact. The test
/// `a_ghost_device_injected_in_sql_does_not_pass_client_verification` pins that down.
///
/// What the server can still do: omit a legitimate device. The victim then notices that one of
/// their devices receives nothing — noisy, and of no use to a spy.
async fn list_account_devices(
    State(pool): State<PgPool>,
    Path(handle): Path<String>,
    signed: Signed,
) -> ApiResult<Json<AccountDevices>> {
    let account: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT identity_key FROM accounts WHERE handle = $1")
            .bind(&handle)
            .fetch_optional(&pool)
            .await?;
    let (identity_key,) = account.ok_or(ApiError::NotFound)?;

    // Revoked devices are served TOO, with their certificate. Hiding them would leave the
    // client unable to tell a revocation from an omission — and omission is precisely what this
    // server can still do. A device that vanishes without a certificate is therefore a signal,
    // not a normal event.
    let rows: Vec<RevocableDeviceRow> = sqlx::query_as(
        "SELECT id, auth_key, mls_key, attestation,
                EXTRACT(EPOCH FROM revoked_at)::BIGINT, revocation,
                EXTRACT(EPOCH FROM last_seen_at)::BIGINT
         FROM devices
         WHERE handle = $1
         ORDER BY id",
    )
    .bind(&handle)
    .fetch_all(&pool)
    .await?;

    // Per-device detail is served to the account owner only.
    let owner = caller_handle(&pool, &signed.device_id).await? == handle;

    Ok(Json(AccountDevices {
        handle,
        identity_key: BASE64_STANDARD.encode(identity_key),
        devices: rows
            .into_iter()
            .map(
                |(id, auth_key, mls_key, attestation, revoked_at, revocation, last_seen)| {
                    AccountDevice {
                        id,
                        auth_key: BASE64_STANDARD.encode(auth_key),
                        mls_key: BASE64_STANDARD.encode(mls_key),
                        attestation: BASE64_STANDARD.encode(attestation),
                        revoked_at: revoked_at.map(|t| t as u64),
                        revocation: revocation.map(|r| BASE64_STANDARD.encode(r)),
                        last_seen: if owner { last_seen } else { None },
                    }
                },
            )
            .collect(),
    }))
}

// ------------------------------------------------------------------- transparency log

#[derive(Serialize)]
struct SignedHead {
    size: u64,
    root: String,
    timestamp: u64,
    signature: String,
    /// The log's public key, so the client can verify the signature.
    ///
    /// Serving it here is a **knowing** compromise: a client that discovers it from the very
    /// server it is meant to watch gains nothing against a malicious server on first contact.
    /// It should ship with the application, or be attested by a separate operator. Gossip
    /// between clients is what partially makes up for this flaw.
    log_key: String,
}

/// The signed head, and the tree it was computed from.
///
/// Both come out of a single [`crate::log::snapshot`] rather than two reads: a head signed over
/// one state of the table and a proof built from another would be a proof that does not verify
/// against the head shipped beside it — the kind of inconsistency a client is right to read as a
/// forked log.
async fn signed_head(
    pool: &PgPool,
) -> ApiResult<(SignedHead, Arc<crate::log::Snapshot>)> {
    let key = crate::log::signing_key(pool).await?;
    let snapshot = crate::log::snapshot(pool).await?;
    let (head, signature) = crate::log::head(&snapshot, &key);

    Ok((
        SignedHead {
            size: head.size,
            root: BASE64_STANDARD.encode(head.root),
            timestamp: head.timestamp,
            signature: BASE64_STANDARD.encode(signature),
            log_key: BASE64_STANDARD.encode(key.verifying_key().to_bytes()),
        },
        snapshot,
    ))
}

/// Current head of the log.
///
/// This is what clients exchange with each other, inside their encrypted conversations, to
/// detect a server keeping two logs. Each of them sees a consistent log; only comparing heads
/// reveals the fork.
async fn log_head(State(pool): State<PgPool>, _signed: Signed) -> ApiResult<Json<SignedHead>> {
    let (head, _) = signed_head(&pool).await?;
    Ok(Json(head))
}

#[derive(Serialize)]
struct InclusionProof {
    handle: String,
    identity_key: String,
    index: usize,
    proof: Vec<String>,
    head: SignedHead,
}

/// Proof that the key served for this account really is in the log.
///
/// **The client must re-verify.** This route proves nothing by itself: it supplies the material
/// that lets the client conclude on its own, with the same `transparency` crate, without
/// trusting us. That is the entire point.
async fn log_proof(
    State(pool): State<PgPool>,
    Path(handle): Path<String>,
    _signed: Signed,
) -> ApiResult<Json<InclusionProof>> {
    let (head, snapshot) = signed_head(&pool).await?;

    let (seq, identity_key) =
        crate::log::latest(&pool, &handle).await?.ok_or(ApiError::NotFound)?;
    let index = crate::log::index_of(&pool, seq).await?;

    let proof = transparency::inclusion_proof(&snapshot.leaves, index)
        .map_err(|_| ApiError::BadRequest("index outside the log"))?;

    Ok(Json(InclusionProof {
        handle,
        identity_key: BASE64_STANDARD.encode(identity_key),
        index,
        proof: proof.iter().map(|h| BASE64_STANDARD.encode(h)).collect(),
        head,
    }))
}

#[derive(Deserialize)]
struct ConsistencyQuery {
    /// Log size as the client last saw it.
    from: usize,
}

#[derive(Serialize)]
struct ConsistencyProof {
    proof: Vec<String>,
    head: SignedHead,
}

/// Proof that today's log extends the one the client has already seen.
///
/// This is the property that separates an auditable log from a database: the server cannot go
/// back and replace an already published key without everyone who saw the old head noticing.
async fn log_consistency(
    State(pool): State<PgPool>,
    Query(query): Query<ConsistencyQuery>,
    _signed: Signed,
) -> ApiResult<Json<ConsistencyProof>> {
    let (head, snapshot) = signed_head(&pool).await?;

    let proof = transparency::consistency_proof(&snapshot.leaves, query.from)
        .map_err(|_| ApiError::BadRequest("invalid log size"))?;

    Ok(Json(ConsistencyProof {
        proof: proof.iter().map(|h| BASE64_STANDARD.encode(h)).collect(),
        head,
    }))
}

#[derive(Deserialize)]
struct RotateAccount {
    /// New Ed25519 public key for the account, base64.
    new_identity_key: String,
    /// Signature of the rotation by the **old** key, base64.
    rotation: String,
    rotated_at: u64,
}

/// Changes an account's identity key.
///
/// # Why this route exists
///
/// Every device on an account holds the seed: that is what makes them peers, each able to
/// attest and revoke like the others. The price is that a stolen device holds the whole
/// account, and revoking it achieves nothing — whoever holds it attests a new one a second
/// later.
///
/// Rotation is the only answer. Its main effect is **mechanical and free**: by changing
/// `identity_key` it makes every existing attestation unverifiable, since clients recompute
/// them against the current key. The rotating device re-attests immediately; the others will
/// have to be re-paired.
///
/// # What the server cannot arbitrate
///
/// The thief holds the same key and can rotate first. The server has no way to tell the two
/// apart: it applies the first valid rotation it sees. The only recourse is the fingerprint
/// change alert on the correspondents' side — hence the importance of not making it routine.
async fn rotate_account(
    State(pool): State<PgPool>,
    Path(handle): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let payload: RotateAccount = signed.json()?;
    let new_identity_key = decode_b64(&payload.new_identity_key)?;
    let rotation = decode_b64(&payload.rotation)?;

    if new_identity_key.len() != 32 {
        return Err(ApiError::BadRequest("identity key of invalid length"));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(payload.rotated_at) > crate::auth::MAX_CLOCK_SKEW {
        return Err(ApiError::BadRequest("rotation timestamp outside the window"));
    }

    // The caller must be a device of the account: the rotation signature already proves it, but
    // requiring it here avoids processing a stranger's request all the way to the verification.
    let caller: Option<(String,)> = sqlx::query_as("SELECT handle FROM devices WHERE id = $1")
        .bind(&signed.device_id)
        .fetch_optional(&pool)
        .await?;
    if caller.map(|(h,)| h).as_deref() != Some(handle.as_str()) {
        return Err(ApiError::Forbidden);
    }

    let current: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT identity_key FROM accounts WHERE handle = $1")
            .bind(&handle)
            .fetch_optional(&pool)
            .await?;
    let (previous_identity_key,) = current.ok_or(ApiError::NotFound)?;

    let claim = attest::RotationClaim {
        handle: &handle,
        new_identity_key: &new_identity_key,
        rotated_at: payload.rotated_at,
    };
    attest::verify_rotation(&previous_identity_key, &claim, &rotation)
        .map_err(|_| ApiError::Forbidden)?;

    let mut tx = pool.begin().await?;

    sqlx::query("UPDATE accounts SET identity_key = $2 WHERE handle = $1")
        .bind(&handle)
        .bind(&new_identity_key)
        .execute(&mut *tx)
        .await?;

    // A rotation **appends** to the log, it replaces nothing: this is what lets a client see
    // that a key changed rather than watch it vanish, and what stops the server from quietly
    // rewriting an identity.
    crate::log::append(&mut tx, &handle, &new_identity_key).await?;

    // The other devices' KeyPackages go with the old key: they carry credentials nobody can
    // tie back to the account any more, and would be used to add those devices to new groups.
    // The caller's are kept — it is about to re-attest.
    sqlx::query(
        "DELETE FROM key_packages WHERE device_id IN
         (SELECT id FROM devices WHERE handle = $1 AND id <> $2)",
    )
    .bind(&handle)
    .bind(&signed.device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Stored attestations are not erased: they simply become unverifiable, and that is exactly
    // what we want visible. A client that receives an attestation which fails to verify rejects
    // it — the same path as for a ghost device, covered by the same test.
    Ok(Json(serde_json::json!({ "handle": handle, "rotated_at": payload.rotated_at })))
}

#[derive(Deserialize)]
struct RevokeDevice {
    /// Revocation certificate signed by the account (domain `wac-revoke-v1`), base64.
    ///
    /// The device attestation no longer serves as the proof. It proved possession of the AIK,
    /// which was enough for the server — but it says nothing about a revocation, so the server
    /// remained the only source for other clients. A separate certificate is verifiable by any
    /// group member, which is what lets them commit the MLS removal without taking our word.
    revocation: String,
    /// Timestamp covered by the signature, in Unix seconds.
    revoked_at: u64,
}

/// Revokes a device. Requires possession of the account key.
///
/// The HTTP request signature would not be enough: it proves possession of *some* device of the
/// account, so a compromised device could revoke itself out of danger, or revoke the others to
/// be left alone in place.
async fn revoke_device(
    State(pool): State<PgPool>,
    Path(device_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let payload: RevokeDevice = signed.json()?;
    let revocation = decode_b64(&payload.revocation)?;

    // Same window as the request signature. Without it, an account could pre-mint certificates
    // dated in the future, and a database theft would make them usable later; backdating would
    // serve to claim a device was already out at the time it legitimately received a message.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(payload.revoked_at) > crate::auth::MAX_CLOCK_SKEW {
        return Err(ApiError::BadRequest("revocation timestamp outside the window"));
    }

    let row: Option<DeviceRow> = sqlx::query_as(
        "SELECT d.handle, d.auth_key, d.mls_key, a.identity_key
         FROM devices d JOIN accounts a ON a.handle = d.handle
         WHERE d.id = $1",
    )
    .bind(&device_id)
    .fetch_optional(&pool)
    .await?;
    let (handle, _auth_key, _mls_key, identity_key) = row.ok_or(ApiError::NotFound)?;

    // The caller must belong to the same account as its target: without this check, any
    // account could revoke another's devices.
    let caller: Option<(String,)> = sqlx::query_as("SELECT handle FROM devices WHERE id = $1")
        .bind(&signed.device_id)
        .fetch_optional(&pool)
        .await?;
    if caller.map(|(h,)| h) != Some(handle.clone()) {
        return Err(ApiError::Forbidden);
    }

    let claim = attest::RevocationClaim {
        handle: &handle,
        device_id: &device_id,
        revoked_at: payload.revoked_at,
    };
    attest::verify_revocation(&identity_key, &claim, &revocation)
        .map_err(|_| ApiError::Forbidden)?;

    // `revoked_at` takes the signed value, not `now()`: the two must coincide, otherwise the
    // certificate served to other clients would not match the row and their verification would
    // fail. The window above already bounds the gap.
    //
    // Idempotent: a second revocation of the same device does not replace the certificate in
    // place. Without that guard, a compromised device still holding the AIK could rewrite the
    // timestamp at will.
    sqlx::query(
        "UPDATE devices SET revoked_at = to_timestamp($2), revocation = $3
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(&device_id)
    .bind(payload.revoked_at as f64)
    .bind(&revocation)
    .execute(&pool)
    .await?;

    // The KeyPackage stock goes with the device: they must no longer be usable to add it to a
    // new group.
    sqlx::query("DELETE FROM key_packages WHERE device_id = $1")
        .bind(&device_id)
        .execute(&pool)
        .await?;

    Ok(Json(serde_json::json!({ "revoked": device_id })))
}

/// Lifetime of a pairing packet.
///
/// It contains what it takes to take over an account. A short window limits the value of a
/// database theft: past it, the packet is worthless even if it was never claimed.
const PAIRING_TTL_SECONDS: i64 = 300;

#[derive(Deserialize)]
struct DepositPairing {
    /// Already sealed packet, base64.
    payload: String,
}

/// Deposits a sealed pairing packet.
///
/// Signed by the origin device: otherwise anyone could fill the table, and above all overwrite
/// the legitimate packet with their own while the user is looking at their QR code.
///
/// The server only sees a blob. Both X25519 public halves travelled through the QR, out of its
/// reach; it can neither open the packet nor forge one the new device would accept.
async fn deposit_pairing(
    State(pool): State<PgPool>,
    Path(pairing_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let pairing_id = hex::decode(&pairing_id)
        .map_err(|_| ApiError::BadRequest("invalid pairing id"))?;
    if pairing_id.len() != 16 {
        return Err(ApiError::BadRequest("pairing id of invalid length"));
    }

    let payload: DepositPairing = signed.json()?;
    let blob = decode_b64(&payload.payload)?;
    if blob.is_empty() || blob.len() > 64 * 1024 {
        return Err(ApiError::BadRequest("pairing packet of invalid length"));
    }

    // `ON CONFLICT DO NOTHING`: an id already in use is not overwritten. Otherwise a malicious
    // device that guessed the id would replace the legitimate packet.
    let inserted = sqlx::query(
        "INSERT INTO pairings (id, payload, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3))
         ON CONFLICT DO NOTHING",
    )
    .bind(&pairing_id)
    .bind(&blob)
    .bind(PAIRING_TTL_SECONDS as f64)
    .execute(&pool)
    .await?;

    if inserted.rows_affected() == 0 {
        return Err(ApiError::Conflict("pairing already in progress for this id"));
    }

    Ok(Json(serde_json::json!({ "deposited": true })))
}

/// Claims the pairing packet. **Unsigned**: the new device has no identity known to the server
/// yet — that is precisely what pairing is about to give it.
///
/// Security therefore rests on encryption, not authentication: without the ephemeral private
/// key the packet is unreadable. The id alone is worth nothing.
///
/// The read is **single-use**. A second claim that succeeded would mean a third party got hold
/// of the packet; a pairing that fails beats a pairing silently shared.
async fn claim_pairing(
    State(pool): State<PgPool>,
    Path(pairing_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let pairing_id = hex::decode(&pairing_id)
        .map_err(|_| ApiError::BadRequest("invalid pairing id"))?;

    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "UPDATE pairings SET claimed_at = now()
         WHERE id = $1 AND claimed_at IS NULL AND expires_at > now()
         RETURNING payload",
    )
    .bind(&pairing_id)
    .fetch_optional(&pool)
    .await?;

    let (payload,) = row.ok_or(ApiError::NotFound)?;

    Ok(Json(serde_json::json!({ "payload": BASE64_STANDARD.encode(payload) })))
}

#[derive(Deserialize)]
struct PublishKeyPackages {
    /// Serialized KeyPackages, base64.
    packages: Vec<String>,
}

/// Replenishes the caller's KeyPackage stock.
///
/// The client must watch its stock and top it up: at zero, nobody can open a conversation with
/// this device any more.
async fn publish_key_packages(
    State(pool): State<PgPool>,
    State(writes): State<Arc<Writes>>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    // A signature identifies the caller; it does not bound it. One registered device could
    // append `MAX_KEY_PACKAGES_PER_REQUEST` rows as fast as the network allowed, and the stock
    // is only consumed one package at a time by people opening conversations — so what is
    // published mostly stays. See `crate::throttle` for the number and for what it does not fix.
    if !writes.allows(Written::KeyPackages, &signed.device_id) {
        return Err(ApiError::TooManyRequests);
    }

    let payload: PublishKeyPackages = signed.json()?;

    if payload.packages.is_empty() {
        return Err(ApiError::BadRequest("no key package provided"));
    }
    if payload.packages.len() > MAX_KEY_PACKAGES_PER_REQUEST {
        return Err(ApiError::BadRequest("too many key packages in one request"));
    }

    let packages: Vec<Vec<u8>> = payload
        .packages
        .iter()
        .map(|p| decode_b64(p))
        .collect::<ApiResult<_>>()?;

    // The server does not validate KeyPackage contents: it does not speak MLS. The client
    // validates them on receipt — and that validation proves nothing about the identity behind
    // them anyway (see `crypto_core::identity::parse_key_package`).
    sqlx::query(
        "INSERT INTO key_packages (device_id, payload)
         SELECT $1, * FROM UNNEST($2::bytea[])",
    )
    .bind(&signed.device_id)
    .bind(&packages)
    .execute(&pool)
    .await?;

    Ok(Json(serde_json::json!({ "published": packages.len() })))
}

#[derive(Serialize)]
struct Store {
    remaining: i64,
}

async fn key_package_stock(State(pool): State<PgPool>, signed: Signed) -> ApiResult<Json<Store>> {
    let (remaining,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM key_packages WHERE device_id = $1")
            .bind(&signed.device_id)
            .fetch_one(&pool)
            .await?;

    Ok(Json(Store { remaining }))
}

#[derive(Serialize)]
struct ClaimedKeyPackage {
    package: String,
    /// Remaining stock of the target device, so the client can warn it.
    remaining: i64,
}

/// Consumes a KeyPackage from the target device.
///
/// `DELETE ... RETURNING` over a `FOR UPDATE SKIP LOCKED` subquery: the removal is atomic and
/// two concurrent calls cannot get the same KeyPackage. This is the critical point of the whole
/// server — a KeyPackage's init key is single-use, and OpenMLS does not prevent its reuse.
async fn claim_key_package(
    State(pool): State<PgPool>,
    State(claims): State<Arc<crate::throttle::Claims>>,
    Path(device_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<ClaimedKeyPackage>> {
    // **Quota per caller-target pair.**
    //
    // This route irreversibly consumes a KeyPackage from the target, and any authenticated
    // device can aim at it — the caller has no relationship to prove. Unbounded, any account
    // could empty anyone's stock and make them **unreachable for any new conversation**: exactly
    // what the client already says about its own stock, "at zero, nobody can open a conversation
    // with this device any more".
    //
    // The client's automatic replenishment mitigates without fixing: it only runs on fetch, and
    // an offline victim does not replenish at all.
    //
    // The quota is on the pair, not on the caller alone: opening conversations with many
    // correspondents is legitimate, hammering a single one is not. An honest caller needs only
    // one KeyPackage per target device; the margin covers retries after a network failure.
    //
    // What this does not close: the counter lives in memory, hence per instance, and several
    // colluding accounts get around the bound. See `crate::throttle`.
    let quota = format!("{}:{}", signed.device_id, device_id);
    if !claims.allows(&quota) {
        return Err(ApiError::TooManyRequests);
    }

    // A revoked device must no longer be addable to a group. The stock is already purged on
    // revocation; this clause closes the window between the two queries and guards against a
    // stock republished by a stolen device.
    let revoked: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM devices WHERE id = $1 AND revoked_at IS NOT NULL")
            .bind(&device_id)
            .fetch_optional(&pool)
            .await?;
    if revoked.is_some() {
        return Err(ApiError::NotFound);
    }

    let claimed: Option<(Vec<u8>,)> = sqlx::query_as(
        "DELETE FROM key_packages
         WHERE id = (
             SELECT id FROM key_packages
             WHERE device_id = $1
             ORDER BY id
             FOR UPDATE SKIP LOCKED
             LIMIT 1
         )
         RETURNING payload",
    )
    .bind(&device_id)
    .fetch_optional(&pool)
    .await?;

    let (package,) = claimed.ok_or(ApiError::NotFound)?;

    let (remaining,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM key_packages WHERE device_id = $1")
            .bind(&device_id)
            .fetch_one(&pool)
            .await?;

    Ok(Json(ClaimedKeyPackage {
        package: BASE64_STANDARD.encode(package),
        remaining,
    }))
}

/// Lists the groups where the caller is declared a member.
///
/// This is how a device finds out it was added to a conversation while offline: it has no other
/// way to learn the group id.
///
/// The endpoint only reflects metadata the server already holds (`group_members`). It therefore
/// discloses nothing new — but it is a reminder that the server knows who talks to whom.
async fn list_groups(State(pool): State<PgPool>, signed: Signed) -> ApiResult<Json<Vec<String>>> {
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT group_id FROM group_members WHERE device_id = $1 ORDER BY group_id")
            .bind(&signed.device_id)
            .fetch_all(&pool)
            .await?;

    Ok(Json(rows.into_iter().map(|(id,)| hex::encode(id)).collect()))
}

#[derive(Deserialize)]
struct AddMembers {
    device_ids: Vec<String>,
    /// The group's posting key, base64. Supplied **at creation only**.
    ///
    /// It cannot be changed afterwards: a member replacing it would silence all the others,
    /// with no error to explain why. Rotating it would require redistributing it over MLS
    /// first, which is not done here.
    #[serde(default)]
    posting_key: Option<String>,
}

/// Declares who may read a group's mailbox.
///
/// The server does not know the group's real composition — it lives in the MLS tree, encrypted.
/// This list is transport-level access control, distinct from and potentially divergent with
/// cryptographic membership. The truth stays the MLS tree: a device listed here but absent from
/// the tree fetches blobs it cannot decrypt.
async fn add_members(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let group_id = decode_group_id(&group_id)?;
    let payload: AddMembers = signed.json()?;

    if payload.device_ids.is_empty() {
        return Err(ApiError::BadRequest("no device provided"));
    }

    let mut tx = pool.begin().await?;

    // Creates the group if it does not exist. `RETURNING` yields nothing on conflict, hence the
    // `fetch_optional`: a row means the caller just created the group and therefore legitimately
    // becomes its first member.
    let posting_key = match &payload.posting_key {
        Some(encoded) => {
            let key = decode_b64(encoded)?;
            if key.len() != 32 {
                return Err(ApiError::BadRequest("posting key of invalid length"));
            }
            Some(key)
        }
        None => None,
    };

    let created: Option<(Vec<u8>,)> = sqlx::query_as(
        "INSERT INTO groups (id, posting_key) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(&group_id)
    .bind(&posting_key)
    .fetch_optional(&mut *tx)
    .await?;

    if created.is_some() {
        sqlx::query("INSERT INTO group_members (group_id, device_id) VALUES ($1, $2)")
            .bind(&group_id)
            .bind(&signed.device_id)
            .execute(&mut *tx)
            .await?;
    } else {
        // Existing group: only a member can add others.
        let member: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2")
                .bind(&group_id)
                .bind(&signed.device_id)
                .fetch_optional(&mut *tx)
                .await?;
        if member.is_none() {
            return Err(ApiError::Forbidden);
        }
    }

    sqlx::query(
        "INSERT INTO group_members (group_id, device_id)
         SELECT $1, * FROM UNNEST($2::text[])
         ON CONFLICT DO NOTHING",
    )
    .bind(&group_id)
    .bind(&payload.device_ids)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(serde_json::json!({ "added": payload.device_ids.len() })))
}

#[derive(Deserialize)]
struct RemoveMembers {
    device_ids: Vec<String>,
}

/// Removes devices from a group's distribution list.
///
/// Symmetric counterpart to [`add_members`], under the same rule: only a member acts. The server
/// knows no more here than anywhere else — it is blind to the group's contents and **enforces no
/// administration policy**.
///
/// # Why the server does not arbitrate roles
///
/// Admin roles live in an MLS group context extension, hence in the encrypted state. The server
/// cannot read them, and handing them over in the clear would give it back the power everything
/// else takes away. It is the **clients** that reject an unauthorized commit, each on its own.
/// This endpoint does transport-level access control and nothing more.
///
/// Accepted consequence: a member can remove anyone from the distribution list without the
/// server objecting. There is nothing to gain — the others keep receiving the MLS commit through
/// their own fetches, and the victim notices it receives nothing any more. This is noisy
/// censorship, the same register as device omission.
async fn remove_members(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let group_id = decode_group_id(&group_id)?;
    let payload: RemoveMembers = signed.json()?;

    if payload.device_ids.is_empty() {
        return Err(ApiError::BadRequest("no device provided"));
    }

    // Note this checks the caller, not the target: a revoked device must still be removable by
    // a member.
    require_membership(&pool, &group_id, &signed.device_id).await?;

    let removed = sqlx::query(
        "DELETE FROM group_members
         WHERE group_id = $1 AND device_id = ANY($2::text[])",
    )
    .bind(&group_id)
    .bind(&payload.device_ids)
    .execute(&pool)
    .await?
    .rows_affected();

    Ok(Json(serde_json::json!({ "removed": removed })))
}

/// Cap on vault entries per request and per page.
const MAX_VAULT_ENTRIES: usize = 200;

#[derive(Deserialize)]
struct VaultEntry {
    seq: i64,
    /// Message already encrypted under the vault key, base64.
    payload: String,
}

#[derive(Deserialize)]
struct StoreVault {
    entries: Vec<VaultEntry>,
}

/// Returns the account of the signing device.
///
/// The vault is indexed by account, never by device: that is what lets a brand new device
/// recover the history deposited by another.
async fn caller_handle(pool: &PgPool, device_id: &str) -> ApiResult<String> {
    let row: Option<(String,)> = sqlx::query_as("SELECT handle FROM devices WHERE id = $1")
        .bind(device_id)
        .fetch_optional(pool)
        .await?;

    row.map(|(handle,)| handle).ok_or(ApiError::Forbidden)
}

/// Stores entries in the caller's vault.
///
/// The server only sees blobs: the key is derived from the recovery phrase, which it does not
/// hold. `ON CONFLICT DO NOTHING` makes the store idempotent — two devices of the same account
/// archive the same conversation without stepping on each other.
async fn store_vault(
    State(pool): State<PgPool>,
    State(writes): State<Arc<Writes>>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    // Membership below stops the vault being used as free storage under someone else's group;
    // it does nothing about a member archiving the same group without end. The quota is what
    // bounds the volume, and it is deliberately checked before the two membership queries: a
    // refusal should not cost the database anything.
    if !writes.allows(Written::Vault, &signed.device_id) {
        return Err(ApiError::TooManyRequests);
    }

    let group_id = decode_group_id(&group_id)?;
    let payload: StoreVault = signed.json()?;

    if payload.entries.is_empty() {
        return Err(ApiError::BadRequest("no entry provided"));
    }
    if payload.entries.len() > MAX_VAULT_ENTRIES {
        return Err(ApiError::BadRequest("too many entries in one request"));
    }

    // Group membership is required: otherwise an account could archive under any group id and
    // use it as free storage.
    require_membership(&pool, &group_id, &signed.device_id).await?;
    let handle = caller_handle(&pool, &signed.device_id).await?;

    let seqs: Vec<i64> = payload.entries.iter().map(|e| e.seq).collect();
    let blobs: Vec<Vec<u8>> =
        payload.entries.iter().map(|e| decode_b64(&e.payload)).collect::<ApiResult<_>>()?;

    sqlx::query(
        "INSERT INTO vault_entries (handle, group_id, seq, payload)
         SELECT $1, $2, * FROM UNNEST($3::bigint[], $4::bytea[])
         ON CONFLICT DO NOTHING",
    )
    .bind(&handle)
    .bind(&group_id)
    .bind(&seqs)
    .bind(&blobs)
    .execute(&pool)
    .await?;

    Ok(Json(serde_json::json!({ "stored": seqs.len() })))
}

#[derive(Serialize)]
struct VaultRow {
    seq: i64,
    payload: String,
}

/// Returns the caller's vault for a group.
///
/// Only the owning account gets in: the `handle` comes from the signing device, never from a
/// parameter. That is what stops someone from reading another's vault by knowing their
/// pseudonym.
async fn fetch_vault(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    Query(query): Query<FetchQuery>,
    signed: Signed,
) -> ApiResult<Json<Vec<VaultRow>>> {
    let group_id = decode_group_id(&group_id)?;
    let handle = caller_handle(&pool, &signed.device_id).await?;

    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, payload FROM vault_entries
         WHERE handle = $1 AND group_id = $2 AND seq > $3
         ORDER BY seq
         LIMIT $4",
    )
    .bind(&handle)
    .bind(&group_id)
    .bind(query.after)
    .bind(MAX_VAULT_ENTRIES as i64)
    .fetch_all(&pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(seq, payload)| VaultRow { seq, payload: BASE64_STANDARD.encode(payload) })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct PostEnvelope {
    /// Opaque MLS blob, base64.
    payload: String,
}

#[derive(Serialize)]
struct EnvelopePosted {
    seq: i64,
}

/// Posts an envelope and assigns it its sequence number.
///
/// The increment and the insert are in the same transaction, and the `UPDATE` locks the group
/// row: two concurrent posts are serialized. MLS requires every member to apply commits in the
/// same order — two members whose epochs diverge cannot read each other at all any more.
/// Verifies an anonymous post and returns the envelope.
///
/// # What is authenticated
///
/// `HMAC(group key, "wac-post-v1" ‖ group_id ‖ nonce ‖ SHA256(body))`.
///
/// The `group_id` prevents replaying a MAC in another group. The nonce makes it unique, and its
/// uniqueness is enforced **by the database**, not by a read followed by a write — an
/// application-level check would leave a concurrency window between the two.
///
/// The body's digest is included rather than the body itself: without it, a middleman could
/// substitute the envelope under a legitimate MAC.
async fn anonymous_body(
    pool: &PgPool,
    group_id: &[u8],
    request: axum::extract::Request,
) -> ApiResult<Vec<u8>> {
    use sha2::{Digest, Sha256};

    // Headers are extracted as owned values **before** the first `await`. Holding a borrow on
    // `request` across a suspension point would make the future non-`Send`, and axum requires
    // `Send` handlers — the resulting error does not point at the cause. Same precaution as in
    // `auth::Signed`.
    let (nonce, mac) = {
        let headers = request.headers();
        let header = |name: &str| -> ApiResult<Vec<u8>> {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| BASE64_STANDARD.decode(value).ok())
                .ok_or(ApiError::BadRequest("anonymous post header missing or unreadable"))
        };

        (header(HEADER_NONCE)?, header(HEADER_MAC)?)
    };

    if nonce.len() != 16 {
        return Err(ApiError::BadRequest("invalid post nonce"));
    }

    let (posting_key,): (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT posting_key FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_optional(pool)
            .await?
            .ok_or(ApiError::NotFound)?;

    // A group with no posting key does not accept anonymous posts. Answer 403 rather than
    // silently fall back to the signed path: a client that believes itself anonymous and is not
    // is worse than a client that fails.
    let posting_key = posting_key.ok_or(ApiError::Forbidden)?;

    let body = axum::body::to_bytes(request.into_body(), MAX_ENVELOPE_BYTES)
        .await
        .map_err(|_| ApiError::BadRequest("unreadable body"))?;

    let payload: PostEnvelope =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("invalid body"))?;
    let blob = decode_b64(&payload.payload)?;

    let message = attest::post_message(group_id, &nonce, &Sha256::digest(&body))
        .map_err(|_| ApiError::BadRequest("malformed post"))?;

    verify_group_mac(&posting_key, &message, &mac)?;

    // Uniqueness is a primary key constraint: a replay fails on insert, with no possible
    // concurrency window.
    let inserted =
        sqlx::query("INSERT INTO posting_nonces (group_id, nonce) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(group_id)
            .bind(&nonce)
            .execute(pool)
            .await?;

    if inserted.rows_affected() == 0 {
        return Err(ApiError::Forbidden);
    }

    Ok(blob)
}

/// Headers of the **anonymous** post.
///
/// Their presence switches the route to the sealed sender path: no device signature is then
/// required or accepted, and the server does not learn who posts.
const HEADER_NONCE: &str = "x-group-nonce";
const HEADER_MAC: &str = "x-group-mac";

/// Posts an envelope into a group.
///
/// # Two authorization paths, one effect
///
/// **Signed**: the device proves its identity. The server learns who writes, when, and in which
/// group. This is the historical path, kept for groups created before sealed sender.
///
/// **Anonymous**: the poster only proves it holds the group key, hence that it is a member. The
/// server cannot say which one. That is all it needs in order not to act as an open mailbox.
///
/// Both end in the same envelope: the real sender is authenticated **by MLS**, inside the
/// ciphertext, and the recipients read it. What disappears is what the server knows about it.
#[derive(Deserialize)]
struct PushToken {
    provider: String,
    token: String,
}

/// Registers the calling device's wake token.
///
/// Signed, hence tied to an already known device: otherwise anyone could make someone else's
/// phone buzz by guessing an id.
///
/// The provider is taken as-is and not checked against a list: the server has nothing to decide
/// here, and a closed list would force a redeploy the day a platform changes its name. A token
/// aimed at a provider that is not wired up is simply ignored when waking.
async fn set_push_token(State(pool): State<PgPool>, signed: Signed) -> ApiResult<()> {
    let payload: PushToken = signed.json()?;

    if payload.token.is_empty() || payload.provider.is_empty() {
        return Err(ApiError::BadRequest("empty wake token"));
    }

    crate::push::register(&pool, &signed.device_id, &payload.provider, &payload.token).await?;
    Ok(())
}

/// Drops the token. The device stops being woken, and the server stops having an address.
///
/// Distinct from a "disabled" setting that would keep the row: what is not stored cannot be
/// subpoenaed later, nor leak with a database.
async fn forget_push_token(State(pool): State<PgPool>, signed: Signed) -> ApiResult<()> {
    crate::push::forget(&pool, &signed.device_id).await?;
    Ok(())
}

async fn post_envelope(
    State(pool): State<PgPool>,
    State(hub): State<Arc<Hub>>,
    State(waker): State<Arc<dyn crate::push::Waker>>,
    State(writes): State<Arc<Writes>>,
    Path(group_id): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<Json<EnvelopePosted>> {
    let group_id = decode_group_id(&group_id)?;

    let anonymous = request.headers().contains_key(HEADER_MAC);

    let mut sender = None;

    let blob = if anonymous {
        anonymous_body(&pool, &group_id, request).await?
    } else {
        let signed = <Signed as axum::extract::FromRequest<PgPool>>::from_request(request, &pool)
            .await?;
        // **Only the signed path is counted, and the gap is not an oversight.**
        //
        // The anonymous path has no device to count: that is the whole point of sealed sender,
        // and re-attributing a post in order to bound it would hand back the exact power the
        // mechanism took away. Counting the group instead would bound the group — a busy
        // conversation would throttle its own members to punish whichever one of them is
        // abusing it — so it is not done either.
        //
        // What remains open, plainly: anyone holding a group's posting key can grow `envelopes`
        // in that group without any rate bound from this server. That is a member, and a member
        // can already do it through the signed path at 120 a minute; the anonymous path removes
        // the ceiling, not the requirement to be a member.
        if !writes.allows(Written::Envelopes, &signed.device_id) {
            return Err(ApiError::TooManyRequests);
        }

        let payload: PostEnvelope = signed.json()?;
        require_membership(&pool, &group_id, &signed.device_id).await?;
        sender = Some(signed.device_id.clone());
        decode_b64(&payload.payload)?
    };

    if blob.is_empty() {
        return Err(ApiError::BadRequest("empty envelope"));
    }

    let mut tx = pool.begin().await?;

    let (seq,): (i64,) =
        sqlx::query_as("UPDATE groups SET next_seq = next_seq + 1 WHERE id = $1 RETURNING next_seq")
            .bind(&group_id)
            .fetch_one(&mut *tx)
            .await?;

    sqlx::query("INSERT INTO envelopes (group_id, seq, payload) VALUES ($1, $2, $3)")
        .bind(&group_id)
        .bind(seq)
        .bind(&blob)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // After the commit, never before: announcing an envelope that a rolled back transaction
    // would have made vanish would send clients looking for a `seq` that does not exist.
    hub.publish(Notice::Envelope { group_id: group_id.clone(), seq });

    // Waking only concerns **disconnected** devices: the connected ones were just served by the
    // line above. The server does not know which is which, so it wakes them all — one wake too
    // many costs a silent notification, one wake missing costs a message that never arrives.
    //
    // `sender` is `None` on an anonymous post: sealed sender took from the server the power to
    // know who posts, and it is out of the question to hand it back to save one notification.
    crate::push::wake_detached(pool.clone(), waker, group_id, sender);

    Ok(Json(EnvelopePosted { seq }))
}

#[derive(Serialize)]
struct AttachmentUploaded {
    id: String,
}

/// Uploads an already encrypted attachment.
///
/// The body is the raw blob, unencoded: base64 would cost a third of the bandwidth for nothing.
/// The server does not inspect it and knows neither its name, nor its type, nor its key — all
/// of that travels encrypted in the MLS message that will reference this id.
async fn upload_attachment(
    State(pool): State<PgPool>,
    State(writes): State<Arc<Writes>>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<AttachmentUploaded>> {
    // The heaviest write the server accepts: `MAX_ATTACHMENT_BYTES` a call, kept forever, with
    // no way to tell an attachment nobody will fetch from one somebody still needs. The quota
    // slows the fill; it does not stop it, and `crate::throttle` says so rather than implying
    // otherwise.
    //
    // Counted before the membership query and before the body is looked at — but **after** the
    // `Signed` extractor, which has already read the whole body off the socket. The bytes are
    // therefore spent even on a refusal; only the disk is spared. Refusing earlier would mean
    // refusing before knowing who is calling.
    if !writes.allows(Written::Attachments, &signed.device_id) {
        return Err(ApiError::TooManyRequests);
    }

    let group_id = decode_group_id(&group_id)?;
    require_membership(&pool, &group_id, &signed.device_id).await?;

    if signed.body.is_empty() {
        return Err(ApiError::BadRequest("empty attachment"));
    }

    let (id,): (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO attachments (group_id, payload) VALUES ($1, $2) RETURNING id",
    )
    .bind(&group_id)
    .bind(signed.body.as_ref())
    .fetch_one(&pool)
    .await?;

    Ok(Json(AttachmentUploaded { id: id.to_string() }))
}

/// Serves an encrypted attachment back.
///
/// The blob is served as-is. If it was tampered with or substituted, the client's AEAD will fail
/// to open it: it is the client, not the server, that guarantees the file's integrity.
///
/// The MIME type returned is deliberately `application/octet-stream`: these bytes are opaque to
/// the server, and announcing a guessed type would invite the browser to interpret them — an SVG
/// or an HTML rendered inline would execute script on this origin.
async fn download_attachment(
    State(pool): State<PgPool>,
    Path((group_id, attachment_id)): Path<(String, String)>,
    signed: Signed,
) -> ApiResult<axum::response::Response> {
    use axum::http::header;
    use axum::response::IntoResponse;

    let group_id = decode_group_id(&group_id)?;
    require_membership(&pool, &group_id, &signed.device_id).await?;

    let attachment_id: uuid::Uuid = attachment_id
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid attachment id"))?;

    // The `group_id` is part of the clause: without it, a member of one group could read
    // another group's attachments by guessing an id.
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT payload FROM attachments WHERE id = $1 AND group_id = $2")
            .bind(attachment_id)
            .bind(&group_id)
            .fetch_optional(&pool)
            .await?;

    let (payload,) = row.ok_or(ApiError::NotFound)?;

    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_DISPOSITION, "attachment"),
        ],
        payload,
    )
        .into_response())
}

#[derive(Deserialize)]
struct FetchQuery {
    /// Cursor: only return envelopes strictly after this.
    #[serde(default)]
    after: i64,
}

#[derive(Serialize)]
struct Envelope {
    seq: i64,
    payload: String,
}

/// A page of the mailbox, and where the mailbox now begins.
///
/// # Why this is not a bare array any more
///
/// Since `crate::purge_once` deletes envelopes, an empty page has become ambiguous: it means
/// either "nothing new" or "everything you had not read is gone". A client that cannot tell them
/// apart concludes the first, waits, and stays silently stuck on an MLS ratchet that will never
/// advance again — the "would break silently" that `migrations/0009_partitioning.sql` refused to
/// risk, and the reason a purge without this field would be a corruption rather than a deletion.
///
/// `oldest` is the smallest sequence the group still holds. The client compares it to its own
/// cursor: `cursor < oldest - 1` means the envelopes in between no longer exist. It is then in a
/// position to say so, stop trying to decrypt, and ask to be re-added — none of which it can do
/// while it believes it is up to date.
///
/// **This is an unversioned breaking change to the response body**, taken deliberately rather
/// than added as an optional sibling field: an optional field is one a client can keep ignoring,
/// and a client that ignores this one is exactly the failure being fixed.
///
/// What it does not solve: it reports that a gap exists, never what was in it. The content, if
/// the account archives, comes back from the vault; the MLS state does not come back at all and
/// the device has to be re-introduced to the group.
#[derive(Serialize)]
struct EnvelopePage {
    oldest: i64,
    envelopes: Vec<Envelope>,
}

async fn fetch_envelopes(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    Query(query): Query<FetchQuery>,
    signed: Signed,
) -> ApiResult<Json<EnvelopePage>> {
    let group_id = decode_group_id(&group_id)?;
    require_membership(&pool, &group_id, &signed.device_id).await?;

    let oldest = oldest_surviving(&pool, &group_id).await?;

    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, payload FROM envelopes
         WHERE group_id = $1 AND seq > $2
         ORDER BY seq
         LIMIT $3",
    )
    .bind(&group_id)
    .bind(query.after)
    .bind(MAX_ENVELOPES_PER_PAGE)
    .fetch_all(&pool)
    .await?;

    Ok(Json(EnvelopePage {
        oldest,
        envelopes: rows
            .into_iter()
            .map(|(seq, payload)| Envelope { seq, payload: BASE64_STANDARD.encode(payload) })
            .collect(),
    }))
}

/// Smallest sequence a group still holds, or the first one it has yet to hand out.
///
/// Shared by the HTTP fetch and by the gateway's catch-up so the two cannot drift: a gap detected
/// on one path and not the other would be worse than no detection at all, since the client would
/// then have a source telling it everything is fine.
///
/// The fallback for a group with no envelope left is `next_seq + 1`, and it is not cosmetic. For
/// a brand new group `next_seq` is 0, so `oldest` is 1 and a client at cursor 0 — the value that
/// means "I know nothing" — computes no gap, which is right: it has missed nothing. For a group
/// whose entire history was purged, `oldest` sits one past the last sequence ever issued, so
/// every cursor behind it reports a gap, which is also right. Returning 0 in both cases would
/// have made the empty group a permanent false negative.
///
/// One statement rather than a `MIN` plus a `next_seq` read: two round trips could straddle a
/// concurrent post and report an `oldest` no consistent snapshot ever had.
pub(crate) async fn oldest_surviving(pool: &PgPool, group_id: &[u8]) -> ApiResult<i64> {
    let (oldest,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(
             (SELECT MIN(seq) FROM envelopes WHERE group_id = $1),
             g.next_seq + 1
         )
         FROM groups g WHERE g.id = $1",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await?;

    Ok(oldest)
}

/// Cap on handles per presence request.
///
/// Same reason as for KeyPackages: bound what a single request can ask for. With one reason of
/// its own on top — unbounded, this route would be a convenient way to sweep an entire address
/// book in one go.
const MAX_PRESENCE_HANDLES: usize = 64;

#[derive(Deserialize)]
struct PresenceRequest {
    handles: Vec<String>,
}

#[derive(Serialize)]
struct PresenceEntry {
    handle: String,
    last_seen: i64,
}

#[derive(Serialize)]
struct PresenceResponse {
    /// The server clock, served with the response.
    ///
    /// The client compares two clocks to decide whether someone is online. `MAX_CLOCK_SKEW`
    /// exists precisely because they drift: comparing a server timestamp against local time
    /// would make the dot flicker for every user with a badly set clock.
    now: i64,
    accounts: Vec<PresenceEntry>,
}

/// Presence of the requested correspondents.
///
/// # Why POST rather than GET
///
/// So the handles stay out of the URL, hence out of the access logs of every proxy crossed. Same
/// argument that ruled out `EventSource` for the stream. The body is already covered by the
/// signature, there is nothing to add.
///
/// # Why not push it over the stream
///
/// The hub is indexed by group, presence is an account-level fact: pushing would mean a
/// broadcast per group and per heartbeat, through channels that exist for correctness. And above
/// all, the green dot would then depend on the stream — a stalled stream would show everyone
/// offline, which is a *wrong* interface, not merely a late one.
async fn read_presence(State(pool): State<PgPool>, signed: Signed) -> ApiResult<Json<PresenceResponse>> {
    let payload: PresenceRequest = signed.json()?;

    if payload.handles.len() > MAX_PRESENCE_HANDLES {
        return Err(ApiError::BadRequest("too many handles"));
    }

    let seen = presence::read(&pool, &signed.device_id, &payload.handles).await?;
    // `SystemTime` rather than a date dependency: we only serve a number of seconds.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(Json(PresenceResponse {
        now,
        accounts: seen
            .into_iter()
            .map(|s| PresenceEntry { handle: s.handle, last_seen: s.last_seen })
            .collect(),
    }))
}

#[derive(Deserialize)]
struct OptoutRequest {
    optout: bool,
}

/// Turns the presence opt-out on or off.
///
/// The opt-out is **reciprocal**: it cuts reading too. Without that symmetry the setting would
/// let you see without being seen, which is exactly what it claims to prevent. The same rule
/// already applies to read receipts.
///
/// It is honoured on write, in `presence::touch`: nothing is recorded. A setting that merely
/// filtered on read would leave the server keeping the register anyway.
async fn set_presence_optout(State(pool): State<PgPool>, signed: Signed) -> ApiResult<()> {
    let payload: OptoutRequest = signed.json()?;
    let handle = caller_handle(&pool, &signed.device_id).await?;

    sqlx::query("UPDATE accounts SET presence_optout = $2 WHERE handle = $1")
        .bind(&handle)
        .bind(payload.optout)
        .execute(&pool)
        .await?;

    // The past has no business surviving the opt-out: what was already recorded stops being
    // served, and stops existing too. Keeping it would make the setting a lie the moment it is
    // set.
    if payload.optout {
        sqlx::query("UPDATE devices SET last_seen_at = NULL WHERE handle = $1")
            .bind(&handle)
            .execute(&pool)
            .await?;
    }

    Ok(())
}
