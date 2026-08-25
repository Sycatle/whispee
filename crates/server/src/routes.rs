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
use crate::throttle::{Recovery, Writes, Written};

/// Cap on the number of KeyPackages published in one request. Without it, a single device can
/// fill the database on its own.
const MAX_KEY_PACKAGES_PER_REQUEST: usize = 100;

/// A device row as served: id, auth key, MLS key, attestation. Named so that the query
/// signatures stay readable.
type DeviceRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

/// One escrow row as the claim route reads it: account, live handle, kind, parameters, sealed
/// seed. Named for the reason the two above are — the tuple is unreadable inline, and clippy
/// says so.
type EscrowRow = (String, Option<String>, String, Vec<u8>, Vec<u8>);

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
///
/// **`recovery/claim` is the fifth, and it is here for a different reason.** The others precede
/// an identity; this one *follows the loss of every device that held one*. A caller recovering an
/// account has no key to sign with — that is the situation being answered — so no amount of
/// design makes it authenticable.
///
/// It carries a second, far narrower limit of its own on top of the address quota, because what
/// it bounds is not table growth but password guessing. See `throttle::Recovery`, and
/// `migrations/0018_recovery_escrow.sql` for why a failed attempt cannot be counted per account.
pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/accounts", post(create_account))
        .route("/v1/devices", post(register_device))
        .route("/v1/pairings/{pairing_id}", post(deposit_pairing).get(claim_pairing))
        .route("/v1/recovery/claim", post(claim_recovery))
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
        .route("/v1/contact-policy", post(set_contact_policy))
        .route("/v1/push/token", post(set_push_token))
        .route("/v1/push/forget", post(forget_push_token))
        .route("/v1/accounts/{account}/devices", get(list_account_devices))
        .route("/v1/accounts/{account}/rotate", post(rotate_account))
        .route("/v1/accounts/{account}/handle", post(rename_account))
        .route("/v1/accounts/{account}/chain", get(account_chain))
        .route("/v1/handles/{handle}", get(resolve_handle))
        .route("/v1/log/sth", get(log_head))
        .route("/v1/log/proof/{account}", get(log_proof))
        .route("/v1/log/consistency", get(log_consistency))
        .route("/v1/devices/{device_id}/revoke", post(revoke_device))
        .route("/v1/vault/{group_id}", post(store_vault).get(fetch_vault).delete(drop_vault))
        .route("/v1/recovery", get(list_recovery).post(set_recovery))
        .route("/v1/recovery/forget", post(forget_recovery))
        .route("/v1/key-packages", post(publish_key_packages))
        .route("/v1/key-packages/stock", get(key_package_stock))
        .route("/v1/key-packages/{device_id}/claim", post(claim_key_package))
        .route("/v1/groups", get(list_groups))
        .route("/v1/groups/{group_id}/members", post(add_members))
        .route("/v1/groups/{group_id}/members/remove", post(remove_members))
        .route("/v1/groups/{group_id}/signals", post(post_signal))
        .route("/v1/groups/{group_id}/call/token", post(call_token))
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

/// What a client asks for when it wants to join a call.
#[derive(Deserialize)]
struct CallRequest {
    /// Which call. It is the client's, not ours: it is derived from nothing we know.
    call: String,
    /// The name to appear under in the room.
    ///
    /// Chosen by the caller and **not verified**, which is deliberate rather than tolerated: the
    /// route is authenticated by the group MAC precisely so that this server does not learn who
    /// is placing a call, and checking the identity would be learning it. See `crate::call`.
    identity: String,
}

/// Where to reach the call, and with what.
#[derive(Serialize)]
struct CallAdmission {
    url: String,
    token: String,
    /// The relay, when there is one. A deployment reachable on a direct path needs none.
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<CallRelay>,
}

#[derive(Serialize)]
struct CallRelay {
    urls: Vec<String>,
    username: String,
    credential: String,
}

/// Hands out admission to a call's room.
///
/// # Why the group MAC, and not a signature
///
/// The same reason [`post_signal`] uses it: a signed request would tell this server which device
/// is calling, in real time. The MAC proves membership of the group and nothing else — which is
/// exactly the amount of proof handing out a room token requires.
///
/// Note what this does **not** hide, because the module header says it and it bears repeating
/// here where the code is: this server still sees that a call is being joined, when, and towards
/// which group. That is more than it learns from an envelope, and it is irreducible — somebody
/// has to sign the token.
///
/// # Why 503 rather than 404 when unconfigured
///
/// A deployment running no media server is not missing this route, it is refusing the feature.
/// The client reads the difference and hides the call button instead of retrying.
async fn call_token(
    State(pool): State<PgPool>,
    State(media): State<Arc<crate::call::Media>>,
    Path(group_id): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<Json<CallAdmission>> {
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

    // The MAC covers the body, so the call id and the identity below are the ones a member
    // asked for — not ones an intermediary substituted.
    verify_signal(&pool, &group_id, &nonce, &mac, &body).await?;

    let asked: CallRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("malformed call request"))?;

    if !crate::call::acceptable(&asked.call, &asked.identity) {
        return Err(ApiError::BadRequest("unusable call identifier"));
    }

    let sfu = media.sfu.as_ref().ok_or(ApiError::Unavailable)?;
    let room = crate::call::room_name(&group_id, &asked.call);

    Ok(Json(CallAdmission {
        url: sfu.url.clone(),
        token: sfu.token(&room, &asked.identity),
        relay: media.relay.as_ref().map(|relay| {
            let (username, credential) = relay.credential();
            CallRelay { urls: relay.urls.clone(), username, credential }
        }),
    }))
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

/// Creates a pseudonymous account, and claims a handle for it. Unsigned — no key exists yet.
///
/// # The account is its key; the handle is a name it answers to
///
/// The id is derived here rather than accepted from the caller: it is a hash of the identity key
/// in the very same request, so nobody can assert an id that does not belong to the key they are
/// presenting. That property is what the whole identity design rests on, and it costs one line —
/// see `crates/attest/src/lib.rs::account_id`.
///
/// The key is recorded twice, as `identity_key` and as `genesis_key`. They are equal today and
/// diverge on the first rotation: the first moves, the second is what the id was computed from
/// and never does.
///
/// # What is idempotent, and what is a conflict
///
/// Re-creating the **same account** — same key, hence same id — is idempotent, which is how a
/// device that lost its storage gets its account back.
///
/// Claiming a handle another account holds is a conflict, as it always was. Claiming one that has
/// been *released* is also a conflict, and that part is new: a tombstoned handle is never
/// re-issued, because every stale reference to it — a bookmark, a mention in a message written
/// last year — would otherwise name somebody else. See `migrations/0014_account_identity.sql`.
///
/// What TOFU does not prove: that the first claimant was legitimate. There is no answer to that
/// without an external authority or key transparency — out of scope, documented in the README.
async fn create_account(
    State(pool): State<PgPool>,
    Json(payload): Json<CreateAccount>,
) -> ApiResult<Json<serde_json::Value>> {
    // One of the two places a handle enters the system — `rename_account` is the other — so this
    // is where the format is imposed rather than merely hoped for. See `crate::handle` for what
    // `^[a-z0-9_]{3,32}$` buys and what it explicitly does not.
    crate::handle::validate(&payload.handle).map_err(ApiError::BadRequest)?;

    let identity_key = decode_b64(&payload.identity_key)?;
    if identity_key.len() != 32 {
        return Err(ApiError::BadRequest("Ed25519 key expected (32 bytes)"));
    }

    let id = attest::account_id(&identity_key);

    let mut tx = pool.begin().await?;

    let inserted = sqlx::query(
        "INSERT INTO accounts (id, identity_key, genesis_key) VALUES ($1, $2, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(&id)
    .bind(&identity_key)
    .execute(&mut *tx)
    .await?;

    // Its storage counter, in the same transaction as the account. The row has to exist before
    // the first write, because charging is an `UPDATE` whose `WHERE` carries the ceiling — see
    // `crate::storage` for why that cannot be an upsert.
    sqlx::query("INSERT INTO account_storage (account) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&id)
        .execute(&mut *tx)
        .await?;

    // The account and its log entry in the **same** transaction. A key published without an
    // inclusion proof would be rejected by every client: the account would exist without being
    // reachable, and nothing would say why.
    if inserted.rows_affected() > 0 {
        // The genesis entry: no predecessor, so nothing authorises it but the fact that its
        // fingerprint *is* the id being created. A client checks that itself.
        crate::log::append(&mut tx, &id, &identity_key, None).await?;
    }

    // The handle, in the same transaction as the account it names.
    //
    // `ON CONFLICT DO NOTHING` covers the reinstall — the same account re-claiming the name it
    // already holds — and says nothing about the two failures below, which is why those are told
    // apart by a read rather than by a row count. A name somebody else holds and a name nobody
    // holds any more are different sentences to be given.
    // What the account answers to today, if anything. Read before the claim, so that the
    // "already named" case below can be told from the "name is taken" one.
    let held: Option<(String,)> =
        sqlx::query_as("SELECT handle FROM handles WHERE account = $1 AND released_at IS NULL")
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await?;

    let claimed =
        sqlx::query("INSERT INTO handles (handle, account) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(&payload.handle)
            .bind(&id)
            .execute(&mut *tx)
            .await?;

    if claimed.rows_affected() == 0 {
        let owner: Option<(Option<String>,)> =
            sqlx::query_as("SELECT account FROM handles WHERE handle = $1")
                .bind(&payload.handle)
                .fetch_optional(&mut *tx)
                .await?;

        match owner {
            Some((Some(existing),)) if existing == id => {}
            // A tombstone: the name existed, was given up, and does not come back.
            Some((None,)) => return Err(ApiError::Conflict("handle is retired")),
            _ => return Err(ApiError::Conflict("handle already taken by another account")),
        }
    } else if held.is_some() {
        // The account already answers to a name, and has just been handed a second one.
        //
        // The unique index would refuse this as a constraint violation, which reaches the caller
        // as a 500 — an internal error for something they did on purpose. It is a rename, and a
        // rename has a route of its own, with a cooldown this one does not apply. Saying so is
        // the difference between a bug report and an instruction.
        return Err(ApiError::Conflict("this account already has a handle; rename it instead"));
    }

    tx.commit().await?;

    Ok(Json(serde_json::json!({ "account": id, "handle": payload.handle })))
}

/// Resolves a handle to the account that answers to it. **The directory, and nothing more.**
///
/// # What this route can do, and why that is survivable
///
/// It can lie. It can answer late, refuse to answer, or hand back somebody else's id. Nothing
/// here stops it, and nothing needs to: the id it returns is a hash of a key, and the key is
/// inside the credential the caller is about to verify. A wrong id does not become a verifying
/// one, so the worst this route can do is send somebody to the wrong account — which is the
/// failure this product already has at first contact and already answers, with an out-of-band
/// fingerprint comparison.
///
/// That is the whole reason ids are derived rather than assigned. A server that mints them could
/// serve Alice one answer and Carol another about the same name, and there would be nothing to
/// compare. Here there is nothing to compare because there is nothing to disagree about.
///
/// # A tombstone answers `410`, not `404`
///
/// They are different facts and a client should be able to say which it met. A name nobody ever
/// took may still be claimed; a name that was given up never will be, and telling somebody to try
/// again later would be a lie.
///
/// Unsigned, like `create_account`: a name has to be resolvable before an account exists to
/// resolve it with.
async fn resolve_handle(
    State(pool): State<PgPool>,
    Path(handle): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT account FROM handles WHERE handle = $1")
            .bind(&handle)
            .fetch_optional(&pool)
            .await?;

    match row {
        Some((Some(account),)) => Ok(Json(serde_json::json!({ "handle": handle, "account": account }))),
        Some((None,)) => Err(ApiError::Gone),
        None => Err(ApiError::NotFound),
    }
}

#[derive(Deserialize)]
struct RenameAccount {
    handle: String,
}

/// Gives an account a new handle, and retires the old one.
///
/// # This is a registration route wearing a hat
///
/// It creates a row in the same namespace `create_account` does, from a caller who already has an
/// account — which makes it the cheaper of the two doors into that namespace, not the safer one.
/// It is signed, so it is rate-limited per device by the middleware the way every signed route
/// is; what that does **not** bound is how often one account may cycle through names, which is
/// the abuse specific to this route. See the cooldown below.
///
/// # The old name is retired, not freed
///
/// Releasing it would be the obvious thing and it is the dangerous one. Every stale reference to
/// `@bob` — a bookmark, a screenshot, a mention in a message written last year — would name
/// whoever claimed it next, and that is an impersonation nobody had to mount: it arrives on its
/// own, on a schedule the attacker picks by waiting. The row stays, with its account cleared.
///
/// # What this route does not do
///
/// It does not touch the account, its key, its devices, its device ids, its attestations or
/// anything in any conversation. That is the entire point of the identity work: a handle is a
/// name an account answers to, and moving it moves nothing else. Correspondents learn the new
/// name from its owner over MLS, never from this server — see `docs/specs/2026-08-21-account-identity.md`.
async fn rename_account(
    State(pool): State<PgPool>,
    Path(account): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let payload: RenameAccount = signed.json()?;

    // The other of the two places a handle enters the system. Same authority, same rule.
    crate::handle::validate(&payload.handle).map_err(ApiError::BadRequest)?;

    // The caller must be a device of the account it is renaming. Unlike rotation, there is no
    // signature over the claim to fall back on — a rename carries no certificate, because there
    // is nothing for a third party to verify: the name means nothing to anybody who did not ask
    // this server for it. So this check is the whole of the authorisation.
    if caller_account(&pool, &signed.device_id).await? != account {
        return Err(ApiError::Forbidden);
    }

    let mut tx = pool.begin().await?;

    // Retire whatever the account answers to today.
    //
    // `released_at` and a cleared account together: the CHECK in the migration insists on both,
    // so a half-retired row cannot exist. Nothing is deleted — a deleted row is a name back in
    // circulation.
    let retired: Option<(String, Option<i64>, bool)> = sqlx::query_as(
        "UPDATE handles SET account = NULL, released_at = now()
         WHERE account = $1 AND released_at IS NULL
         RETURNING handle, EXTRACT(EPOCH FROM (now() - claimed_at))::BIGINT, from_rename",
    )
    .bind(&account)
    .fetch_optional(&mut *tx)
    .await?;

    // A cooldown between **changes**, which is not the same as the age of the current name.
    //
    // Not decoration: renaming freely is how somebody escapes being blocked, or grinds through
    // names until they land on one that reads like somebody else's. A day is long enough to make
    // that tedious and short enough that a person who mistyped their own name is not stuck with
    // it for a week.
    //
    // `from_rename` is what stops it firing on the first one. A handle claimed at sign-up is
    // minutes old, so measuring its age would tell somebody who has never renamed that they
    // renamed too recently — which was the bug, and it hit the single most likely case: not
    // liking the name you were given the moment you were given it.
    if let Some((_, Some(held_for), true)) = &retired
        && *held_for < RENAME_COOLDOWN_SECONDS
    {
        return Err(ApiError::Conflict("this account was renamed too recently"));
    }

    let claimed = sqlx::query(
        "INSERT INTO handles (handle, account, from_rename) VALUES ($1, $2, true)
         ON CONFLICT DO NOTHING",
    )
    .bind(&payload.handle)
    .bind(&account)
    .execute(&mut *tx)
    .await?;

    if claimed.rows_affected() == 0 {
        let owner: Option<(Option<String>,)> =
            sqlx::query_as("SELECT account FROM handles WHERE handle = $1")
                .bind(&payload.handle)
                .fetch_optional(&mut *tx)
                .await?;
        return match owner {
            Some((None,)) => Err(ApiError::Conflict("handle is retired")),
            _ => Err(ApiError::Conflict("handle already taken by another account")),
        };
    }

    tx.commit().await?;

    Ok(Json(serde_json::json!({
        "account": account,
        "handle": payload.handle,
        "retired": retired.map(|(handle, _, _)| handle),
    })))
}

/// How long an account keeps a name before it may take another. One day.
const RENAME_COOLDOWN_SECONDS: i64 = 24 * 60 * 60;

#[derive(Deserialize)]
struct RegisterDevice {
    id: String,
    /// The account id this device belongs to. Was the handle; a handle can move, an account
    /// cannot — which is what makes every device id this route ever issued survive a rename.
    account: String,
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

    // The device id is qualified by the account: `a1b2…f0:phone`.
    //
    // Otherwise the id space is global and the first arrival hogs the common names — the second
    // user who wants to call their phone "phone" is refused registration, despite holding a
    // perfectly legitimate account. The prefix makes the namespace local to the account; the
    // attestation guarantees nobody can claim someone else's prefix.
    //
    // The prefix is the **account id** now, and that repairs something the handle version could
    // not. A device id used to name the account by a string that had to be able to move — except
    // that it could not, which was the whole reason handles were unrenameable. An id never moves,
    // so a rename leaves every device id ever issued intact.
    //
    // This is a **split**, not a `starts_with`, and it stays one for the reason it became one: an
    // id cannot contain `:`, so the first `:` is unambiguously the separator and the left-hand
    // side is the whole account and nothing else. Checking the shape here as well as splitting
    // closes the other half — a prefix comparison against an unvalidated string would let a
    // colon-bearing value through if this route were reached before `create_account`, which it
    // can be, since a device may be registered against an account that does not exist and the
    // lookup below is what refuses it.
    if !attest::is_account_id(&payload.account) {
        return Err(ApiError::BadRequest("invalid account id"));
    }

    let Some((prefix, _name)) = payload.id.split_once(':') else {
        return Err(ApiError::BadRequest(
            "device id must be prefixed with the account id",
        ));
    };
    if prefix != payload.account {
        return Err(ApiError::BadRequest(
            "device id must be prefixed with the account id",
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
        sqlx::query_as("SELECT identity_key FROM accounts WHERE id = $1")
            .bind(&payload.account)
            .fetch_optional(&pool)
            .await?;
    let (identity_key,) = account.ok_or(ApiError::NotFound)?;

    let claim = attest::DeviceClaim {
        account: &payload.account,
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
        "INSERT INTO devices (id, account, auth_key, mls_key, attestation)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO UPDATE SET attestation = EXCLUDED.attestation
         WHERE devices.auth_key = EXCLUDED.auth_key AND devices.mls_key = EXCLUDED.mls_key",
    )
    .bind(&payload.id)
    .bind(&payload.account)
    .bind(&auth_key)
    .bind(&mls_key)
    .bind(&attestation)
    .execute(&pool)
    .await?;

    if inserted.rows_affected() == 0 {
        // Idempotent re-registration after a reinstall, refused if any field differs: a device
        // changes neither its keys nor its account, it creates a new one.
        let existing: (String, Vec<u8>, Vec<u8>) =
            sqlx::query_as("SELECT account, auth_key, mls_key FROM devices WHERE id = $1")
                .bind(&payload.id)
                .fetch_one(&pool)
                .await?;

        if existing != (payload.account.clone(), auth_key, mls_key) {
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
    account: String,
    identity_key: String,
    devices: Vec<AccountDevice>,
    /// Whether this account has refused presence, **served to the account owner only**.
    ///
    /// # Why it is readable at all
    ///
    /// It was write-only, and a write-only setting has no way to reach a device that was not
    /// there when it was written. The signalling settings travel between an account's devices as
    /// a sealed message inside the conversations they share; a device restored from the recovery
    /// phrase has no conversation yet, so it has no channel, so it would draw the switch in its
    /// default position — "on" — for an account the server has already stopped recording.
    ///
    /// The other two settings do not need this: with no conversation there is nobody to emit a
    /// receipt or a typing indicator to, so a device that has not heard them yet cannot be
    /// contradicting them. Presence is the one that is true of the account the moment it is set.
    ///
    /// # Why only the owner
    ///
    /// The same reason as `last_seen` above, and a sharper one: this field answers "does this
    /// person refuse to be observed", which is a fact about someone worth more to a stranger than
    /// to its owner. `caller_account` is what decides, from the signing device — never from a
    /// parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    presence_optout: Option<bool>,
    /// Who may start a conversation with this account, **served to the owner only**.
    ///
    /// Read back for the reason `presence_optout` is: a device restored from the recovery phrase
    /// has never been told, and a screen that drew "Anyone" for an account the server is already
    /// refusing on behalf of would be lying in the direction that matters.
    ///
    /// Owner only, and here the reason is sharper than for presence. This answers "will this
    /// person accept a stranger", which is worth more to a stranger than to its owner — and
    /// publishing it would undo the refusal the `Forbidden` at `add_members` is careful to keep
    /// indistinguishable.
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_policy: Option<String>,
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
    Path(account): Path<String>,
    signed: Signed,
) -> ApiResult<Json<AccountDevices>> {
    let found: Option<(Vec<u8>, bool, String)> = sqlx::query_as(
        "SELECT identity_key, presence_optout, contact_policy FROM accounts WHERE id = $1",
    )
    .bind(&account)
    .fetch_optional(&pool)
    .await?;
    let (identity_key, presence_optout, contact_policy) = found.ok_or(ApiError::NotFound)?;

    // Revoked devices are served TOO, with their certificate. Hiding them would leave the
    // client unable to tell a revocation from an omission — and omission is precisely what this
    // server can still do. A device that vanishes without a certificate is therefore a signal,
    // not a normal event.
    let rows: Vec<RevocableDeviceRow> = sqlx::query_as(
        "SELECT id, auth_key, mls_key, attestation,
                EXTRACT(EPOCH FROM revoked_at)::BIGINT, revocation,
                EXTRACT(EPOCH FROM last_seen_at)::BIGINT
         FROM devices
         WHERE account = $1
         ORDER BY id",
    )
    .bind(&account)
    .fetch_all(&pool)
    .await?;

    // Per-device detail is served to the account owner only.
    let owner = caller_account(&pool, &signed.device_id).await? == account;

    Ok(Json(AccountDevices {
        account,
        identity_key: BASE64_STANDARD.encode(identity_key),
        presence_optout: owner.then_some(presence_optout),
        contact_policy: owner.then_some(contact_policy),
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
    account: String,
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
    Path(account): Path<String>,
    _signed: Signed,
) -> ApiResult<Json<InclusionProof>> {
    let (head, snapshot) = signed_head(&pool).await?;

    let (seq, identity_key) =
        crate::log::latest(&pool, &account).await?.ok_or(ApiError::NotFound)?;
    let index = crate::log::index_of(&pool, seq).await?;

    let proof = transparency::inclusion_proof(&snapshot.leaves, index)
        .map_err(|_| ApiError::BadRequest("index outside the log"))?;

    Ok(Json(InclusionProof {
        account,
        identity_key: BASE64_STANDARD.encode(identity_key),
        index,
        proof: proof.iter().map(|h| BASE64_STANDARD.encode(h)).collect(),
        head,
    }))
}

#[derive(Serialize)]
struct ChainEntry {
    seq: i64,
    identity_key: String,
    /// Absent on the genesis entry, which has no predecessor to be authorised by.
    #[serde(skip_serializing_if = "Option::is_none")]
    rotation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotated_at: Option<i64>,
}

/// Every identity key an account has published, oldest first, with what authorised each.
///
/// # What the caller does with it, and why the server proves nothing here
///
/// Three checks, all local:
///
/// 1. The first entry's key fingerprints to the account id. **This is the anchor** — it is what
///    makes an id self-authenticating rather than something the directory asserts.
/// 2. Each later entry is signed by the key of the one before it, over `wac-rotate-v2`.
/// 3. Each entry is in the tree, via the inclusion proof at `/v1/log/proof`.
///
/// None of those needs the server to be honest. It can withhold a link, and a chain with a hole
/// fails check 2 — which the client reports rather than papering over. It cannot forge one: it
/// does not hold any account key, and that is the whole reason rotations are signed by their
/// predecessor rather than merely recorded.
async fn account_chain(
    State(pool): State<PgPool>,
    Path(account): Path<String>,
    _signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let links = crate::log::chain(&pool, &account).await?;
    if links.is_empty() {
        return Err(ApiError::NotFound);
    }

    let entries: Vec<ChainEntry> = links
        .into_iter()
        .map(|link| ChainEntry {
            seq: link.seq,
            identity_key: BASE64_STANDARD.encode(link.identity_key),
            rotation: link.rotation.map(|bytes| BASE64_STANDARD.encode(bytes)),
            rotated_at: link.rotated_at,
        })
        .collect();

    Ok(Json(serde_json::json!({ "account": account, "chain": entries })))
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
    Path(account): Path<String>,
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
    let caller: Option<(String,)> = sqlx::query_as("SELECT account FROM devices WHERE id = $1")
        .bind(&signed.device_id)
        .fetch_optional(&pool)
        .await?;
    if caller.map(|(a,)| a).as_deref() != Some(account.as_str()) {
        return Err(ApiError::Forbidden);
    }

    let current: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT identity_key FROM accounts WHERE id = $1")
            .bind(&account)
            .fetch_optional(&pool)
            .await?;
    let (previous_identity_key,) = current.ok_or(ApiError::NotFound)?;

    let claim = attest::RotationClaim {
        account: &account,
        new_identity_key: &new_identity_key,
        rotated_at: payload.rotated_at,
    };
    attest::verify_rotation(&previous_identity_key, &claim, &rotation)
        .map_err(|_| ApiError::Forbidden)?;

    let mut tx = pool.begin().await?;

    // `identity_key` moves; `genesis_key` does not, and that is what keeps the id stable across
    // a rotation. An account that has rotated is the same account under the same name, which is
    // the entire reason the id is anchored on the first key rather than on the current one.
    sqlx::query("UPDATE accounts SET identity_key = $2 WHERE id = $1")
        .bind(&account)
        .bind(&new_identity_key)
        .execute(&mut *tx)
        .await?;

    // A rotation **appends** to the log, it replaces nothing: this is what lets a client see
    // that a key changed rather than watch it vanish, and what stops the server from quietly
    // rewriting an identity.
    //
    // The signature travels with it now. It was verified a few lines above and used to be thrown
    // away, which left every other client taking our word that the key change was the account's
    // own doing — a gap that became load-bearing once the account id was anchored on the genesis
    // key. See `migrations/0015_rotation_chain.sql`.
    crate::log::append(&mut tx, &account, &new_identity_key, Some((&rotation, payload.rotated_at)))
        .await?;

    // **The escrow goes with the old seed.** Rotation is the answer to a stolen device, and a
    // stolen device holds the seed; leaving the escrow behind would leave the thing being
    // rotated away from sitting on the server, openable by a password the thief may also have
    // watched being typed. There is no partial version of this: the ciphertext is of the *old*
    // seed and it is worthless to its owner the moment the key moves.
    //
    // The client is expected to re-post a factor afterwards. It is not done here because it
    // cannot be: sealing needs the new seed and the user's password, neither of which the
    // server has ever held.
    sqlx::query("DELETE FROM recovery_escrows WHERE account = $1")
        .bind(&account)
        .execute(&mut *tx)
        .await?;

    // The other devices' KeyPackages go with the old key: they carry credentials nobody can
    // tie back to the account any more, and would be used to add those devices to new groups.
    // The caller's are kept — it is about to re-attest.
    sqlx::query(
        "DELETE FROM key_packages WHERE device_id IN
         (SELECT id FROM devices WHERE account = $1 AND id <> $2)",
    )
    .bind(&account)
    .bind(&signed.device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Stored attestations are not erased: they simply become unverifiable, and that is exactly
    // what we want visible. A client that receives an attestation which fails to verify rejects
    // it — the same path as for a ghost device, covered by the same test.
    Ok(Json(serde_json::json!({ "account": account, "rotated_at": payload.rotated_at })))
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
        "SELECT d.account, d.auth_key, d.mls_key, a.identity_key
         FROM devices d JOIN accounts a ON a.id = d.account
         WHERE d.id = $1",
    )
    .bind(&device_id)
    .fetch_optional(&pool)
    .await?;
    let (account, _auth_key, _mls_key, identity_key) = row.ok_or(ApiError::NotFound)?;

    // The caller must belong to the same account as its target: without this check, any
    // account could revoke another's devices.
    let caller: Option<(String,)> = sqlx::query_as("SELECT account FROM devices WHERE id = $1")
        .bind(&signed.device_id)
        .fetch_optional(&pool)
        .await?;
    if caller.map(|(a,)| a) != Some(account.clone()) {
        return Err(ApiError::Forbidden);
    }

    let claim = attest::RevocationClaim {
        account: &account,
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

    /*
      The contact policy, and the only place it can be applied.

      Being added to a group is a transport act — a row in this table — so the server is the only
      party that can decline to write it. That is what separates this from `blocked`, which lets
      the envelopes arrive and declines to read them; `storage.ts` has named this half as the one
      that would prevent, and until now it did not exist.

      Refused as `Forbidden` and nothing more specific. A reply that said "this account is not
      accepting" would make the setting an oracle: anybody could learn anybody's policy by trying
      to add them, which is a fact about a person, published by the mechanism meant to protect
      them. `Forbidden` is what this route already answers to a non-member, so a probe cannot tell
      a closed door from a group it is not in.

      All or nothing, before any insert. A partial add would leave the caller's MLS tree naming
      devices the distribution list does not carry — the welcome would be encrypted for somebody
      who never receives it, and the conversation would be broken in a way that looks like a
      network fault.

      # What this governs, and what it does not

      Membership, and therefore delivery. It is *not* a barrier every path consults, and the one
      that does not is `call_token`: admission to a call proves possession of the group's posting
      key, by the same MAC as an ephemeral signal, and never reads this table. That is deliberate —
      it is what keeps the server from learning who is calling — and it is not a way around this
      check, because the posting key is handed out inside the group. An account this route refuses
      never joins, so never receives it.

      What remains is an account that already held the key and no longer should: a former member,
      until the epoch turns. It can still obtain a token, and finds a room it cannot read — the
      frame key comes from the current MLS epoch's exporter, which it no longer has. The protection
      there is MLS's, as it is everywhere else in this project, and not this column's.
    */
    // Read inside the transaction rather than through `caller_account`, which takes the pool: the
    // membership rows this decision is about are being written in here, and a check made against
    // a different snapshot than the insert is a check that can disagree with it.
    let caller: (String,) = sqlx::query_as("SELECT account FROM devices WHERE id = $1")
        .bind(&signed.device_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::Forbidden)?;
    let caller = caller.0;

    for device_id in &payload.device_ids {
        if !may_contact(&mut tx, &caller, device_id, &group_id).await? {
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
async fn caller_account(pool: &PgPool, device_id: &str) -> ApiResult<String> {
    let row: Option<(String,)> = sqlx::query_as("SELECT account FROM devices WHERE id = $1")
        .bind(device_id)
        .fetch_optional(pool)
        .await?;

    row.map(|(account,)| account).ok_or(ApiError::Forbidden)
}

/// Stores entries in the caller's vault.
///
/// The server only sees blobs: the key is derived from the recovery phrase, which it does not
/// hold. `ON CONFLICT DO NOTHING` makes the store idempotent — two devices of the same account
/// archive the same conversation without stepping on each other.
async fn store_vault(
    State(pool): State<PgPool>,
    State(writes): State<Arc<Writes>>,
    State(quota): State<Arc<crate::storage::Quota>>,
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
    let account = caller_account(&pool, &signed.device_id).await?;

    let seqs: Vec<i64> = payload.entries.iter().map(|e| e.seq).collect();
    let blobs: Vec<Vec<u8>> =
        payload.entries.iter().map(|e| decode_b64(&e.payload)).collect::<ApiResult<_>>()?;

    let mut tx = pool.begin().await?;

    // Insert first, charge what the insert actually stored.
    //
    // The order looks wrong and is not. `ON CONFLICT DO NOTHING` means a re-uploaded entry is not
    // stored, and charging before the insert would charge for it anyway — two devices of one
    // account archiving the same conversation would pay twice for one row, and the counter would
    // drift above what the tables hold, permanently, since nothing credits an overcharge.
    // `RETURNING` names the rows that were really written.
    //
    // Nothing races: both statements are in one transaction, the charge is still the single
    // conditional `UPDATE` that makes the ceiling safe under concurrency, and a refusal returns
    // before the commit, so the insert goes with it. What it costs is that a doomed write does
    // its insert before being refused — the disk is untouched either way, only the work is
    // wasted, and paying that on the rare refusal buys an exact counter on every acceptance.
    //
    // The bytes are the stored ones, not the request's: base64 is a third larger, and charging
    // for the encoding would make the ceiling depend on the transport rather than on the disk.
    let stored: Vec<(i32,)> = sqlx::query_as(
        "INSERT INTO vault_entries (account, group_id, seq, payload)
         SELECT $1, $2, * FROM UNNEST($3::bigint[], $4::bytea[])
         ON CONFLICT DO NOTHING
         RETURNING octet_length(payload)",
    )
    .bind(&account)
    .bind(&group_id)
    .bind(&seqs)
    .bind(&blobs)
    .fetch_all(&mut *tx)
    .await?;

    let charged: i64 = stored.iter().map(|(bytes,)| *bytes as i64).sum();

    if !crate::storage::charge(&mut tx, &quota, &account, charged).await? {
        return Err(ApiError::InsufficientStorage);
    }

    tx.commit().await?;

    Ok(Json(serde_json::json!({ "stored": seqs.len() })))
}

/// Drops the caller's vault for one group.
///
/// # Why the caller's and not the group's
///
/// The vault is indexed by account: two members of one conversation each hold their own archive
/// of it, sealed under their own key. Deleting by group would let either of them destroy the
/// other's copy of a shared history — which is not what turning on a lifetime asks for, and is
/// not something one member gets to do to another.
///
/// # Why no membership check
///
/// The statement can only ever reach rows keyed to the caller's own account, so a non-member
/// deleting their vault for a group they were never in removes nothing and leaks nothing.
/// Requiring membership would instead leave somebody who was *removed* from a group unable to
/// erase their own archive of it — the one case where erasing it matters most.
///
/// The bytes are credited in the same transaction that removes the rows: see `crate::storage`
/// for what drifts when a deletion path forgets.
async fn drop_vault(
    State(pool): State<PgPool>,
    State(writes): State<Arc<Writes>>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    // Throttled on a counter of its own, and **not** the one the deposit uses. Sharing it looked
    // like economy and was a defect: the client archives on every send, so a user who had sent ten
    // messages in the last minute and then turned a lifetime on hit the quota here — after
    // `setLifetime` had already published the commit. The room's memory had changed for everybody
    // and the archive stayed, which is the one outcome the feature exists to prevent. See
    // `DEFAULT_VAULT_DROPS_PER_MINUTE` for why the deletion quota sits above the deposit quota.
    //
    // Still bounded: each call is a `DELETE … RETURNING` and a counter update inside one
    // transaction, which is work a signed device could otherwise ask for without end.
    if !writes.allows(Written::VaultDrops, &signed.device_id) {
        return Err(ApiError::TooManyRequests);
    }

    let group_id = decode_group_id(&group_id)?;
    let account = caller_account(&pool, &signed.device_id).await?;

    let mut tx = pool.begin().await?;

    let (removed, bytes): (i64, i64) = sqlx::query_as(
        "WITH gone AS (
             DELETE FROM vault_entries
              WHERE account = $1 AND group_id = $2
          RETURNING octet_length(payload) AS bytes
         )
         SELECT count(*)::bigint, COALESCE(SUM(bytes), 0)::bigint FROM gone",
    )
    .bind(&account)
    .bind(&group_id)
    .fetch_one(&mut *tx)
    .await?;

    crate::storage::credit(&mut tx, &account, bytes).await?;
    tx.commit().await?;

    Ok(Json(serde_json::json!({ "removed": removed })))
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
    let account = caller_account(&pool, &signed.device_id).await?;

    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, payload FROM vault_entries
         WHERE account = $1 AND group_id = $2 AND seq > $3
         ORDER BY seq
         LIMIT $4",
    )
    .bind(&account)
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

/// Length of a lookup value: `SHA-256` of the client's lookup key.
const RECOVERY_LOOKUP_LEN: usize = 32;

/// Length of the encoded KDF parameters. See `crypto_core::escrow::Params`.
const RECOVERY_PARAMS_LEN: usize = 13;

/// Length of a sealed escrow: a 12-byte nonce, the 64-byte seed, a 16-byte GCM tag.
///
/// Fixed, and checked rather than merely expected. A variable-length blob under a
/// caller-chosen key is a storage channel, and this is the one table whose rows are written by
/// a caller and read back by an unauthenticated route.
const RECOVERY_SEALED_LEN: usize = 92;

#[derive(Deserialize)]
struct SetRecovery {
    /// `password` or `passkey`.
    kind: String,
    /// `SHA-256` of the lookup key, base64. Names the row; the pre-image stays on the client.
    lookup: String,
    /// Encoded KDF parameters, base64. Opaque here, covered by the seal's AAD there.
    params: String,
    /// The sealed account seed, base64.
    sealed: String,
}

fn decode_exact(value: &str, expected: usize, what: &'static str) -> ApiResult<Vec<u8>> {
    let bytes = decode_b64(value)?;
    if bytes.len() != expected {
        return Err(ApiError::BadRequest(what));
    }
    Ok(bytes)
}

/// Validates the escrow kind against the same two names the schema allows.
///
/// Checked here rather than left to the CHECK constraint: a violated constraint surfaces as a
/// database error, which this server deliberately turns into a 500 with no detail. A caller
/// sending a typo deserves to be told it was a bad request.
fn recovery_kind(kind: &str) -> ApiResult<&str> {
    match kind {
        "password" | "passkey" => Ok(kind),
        _ => Err(ApiError::BadRequest("unknown recovery kind")),
    }
}

/// Deposits, or replaces, one recovery factor for the caller's account.
///
/// # What the server is being handed
///
/// The account seed, encrypted. Nothing else on this server is that: envelopes are unreadable
/// *and* worthless without the MLS state, where this is the root secret itself, sitting still
/// under a key derived from a password. `migrations/0018_recovery_escrow.sql` states the whole
/// cost; it is not repeated here, but it is the reason this route exists at all only when the
/// user asked for it.
///
/// The server verifies lengths and the caller's identity and nothing more. It cannot check that
/// the ciphertext holds what the client says it holds, and there is no version of this route
/// where it could.
///
/// # Why one factor of each kind, and not many
///
/// A second password is a second guess for an attacker and a forgotten one for its owner. The
/// `UNIQUE (account, kind)` constraint says so; the delete below is what makes *replacing* a
/// password work rather than colliding with it.
async fn set_recovery(State(pool): State<PgPool>, signed: Signed) -> ApiResult<Json<serde_json::Value>> {
    let payload: SetRecovery = signed.json()?;
    let kind = recovery_kind(&payload.kind)?;

    let lookup = decode_exact(&payload.lookup, RECOVERY_LOOKUP_LEN, "lookup of invalid length")?;
    let params =
        decode_exact(&payload.params, RECOVERY_PARAMS_LEN, "escrow parameters of invalid length")?;
    let sealed = decode_exact(&payload.sealed, RECOVERY_SEALED_LEN, "escrow of invalid length")?;

    let account = caller_account(&pool, &signed.device_id).await?;

    let mut tx = pool.begin().await?;

    // The old row goes first, in the same transaction: replacing a password changes the lookup,
    // so an upsert keyed on `lookup` would leave the previous one behind — a second, stale
    // password that still opens the account and that its owner believes they have changed.
    sqlx::query("DELETE FROM recovery_escrows WHERE account = $1 AND kind = $2")
        .bind(&account)
        .bind(kind)
        .execute(&mut *tx)
        .await?;

    let inserted = sqlx::query(
        "INSERT INTO recovery_escrows (lookup, account, kind, params, sealed)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (lookup) DO NOTHING",
    )
    .bind(&lookup)
    .bind(&account)
    .bind(kind)
    .bind(&params)
    .bind(&sealed)
    .execute(&mut *tx)
    .await?;

    // `DO NOTHING` rather than `DO UPDATE`: the surviving conflict is a lookup that belongs to
    // **another** account, and overwriting it would let a caller who guessed it — or collided
    // with it — destroy someone else's only way back in. A 409 is a refusal the caller can act
    // on by choosing a different password; a silent overwrite is not.
    if inserted.rows_affected() == 0 {
        return Err(ApiError::Conflict("this recovery secret is already in use"));
    }

    tx.commit().await?;

    Ok(Json(serde_json::json!({ "kind": kind })))
}

#[derive(Serialize)]
struct RecoveryFactor {
    kind: String,
    created_at: i64,
}

/// Lists the caller's recovery factors, without the blobs.
///
/// For a settings screen that has to say what is switched on. The ciphertext is deliberately
/// absent: an authenticated device already holds the seed, so serving it here would add a way
/// to get the escrow that the recovery route's rate limit does not cover.
async fn list_recovery(
    State(pool): State<PgPool>,
    signed: Signed,
) -> ApiResult<Json<Vec<RecoveryFactor>>> {
    let account = caller_account(&pool, &signed.device_id).await?;

    // `EXTRACT(EPOCH …)` rather than a timestamp type, as everywhere else in this file: no
    // date library is in the tree, and the wire format for a time here is Unix seconds.
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT kind, EXTRACT(EPOCH FROM created_at)::BIGINT
         FROM recovery_escrows WHERE account = $1 ORDER BY kind",
    )
    .bind(&account)
    .fetch_all(&pool)
    .await?;

    Ok(Json(
        rows.into_iter().map(|(kind, created_at)| RecoveryFactor { kind, created_at }).collect(),
    ))
}

#[derive(Deserialize)]
struct ForgetRecovery {
    kind: String,
}

/// Removes one recovery factor.
///
/// Idempotent: forgetting a factor that is not there is a success. The alternative — a 404 —
/// would turn "make sure this is off" into a call the client has to special-case, and would
/// report a failure for a state the caller asked for and now has.
async fn forget_recovery(
    State(pool): State<PgPool>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let payload: ForgetRecovery = signed.json()?;
    let kind = recovery_kind(&payload.kind)?;
    let account = caller_account(&pool, &signed.device_id).await?;

    let removed = sqlx::query("DELETE FROM recovery_escrows WHERE account = $1 AND kind = $2")
        .bind(&account)
        .bind(kind)
        .execute(&pool)
        .await?;

    Ok(Json(serde_json::json!({ "forgotten": removed.rows_affected() })))
}

#[derive(Deserialize)]
struct ClaimRecovery {
    /// `SHA-256` of the lookup key, base64.
    lookup: String,
}

#[derive(Serialize)]
struct ClaimedRecovery {
    account: String,
    /// The account's current handle, or `null` if it holds none.
    ///
    /// Served because a recovering client needs it and cannot derive it: the handle is an alias
    /// the server keeps, not something the seed produces. A client is right not to trust it —
    /// `docs/specs/2026-08-21-account-identity.md` says the displayed handle is never re-fetched
    /// from the server — but the account id beside it *is* checkable against the recovered key,
    /// and that check is what makes the pair safe to use.
    handle: Option<String>,
    kind: String,
    params: String,
    sealed: String,
}

/// Serves one escrow to whoever can name it. **Unauthenticated, by necessity.**
///
/// # Why this cannot require a signature
///
/// The caller has lost every device. There is no key left to sign with; that is the situation
/// this route answers. The authentication is therefore inside the request rather than around
/// it: naming the row already requires having done the expensive derivation, which requires
/// the password.
///
/// # What the answers say, and what they refuse to say
///
/// A wrong lookup and an account with no escrow are the same 404. So this is not an oracle for
/// which accounts exist, which have recovery enabled, or whether a password was close. Nothing
/// in the response distinguishes "there is no such row" from "you guessed wrong", because the
/// server genuinely cannot tell them apart — it holds a hash and compares it.
///
/// # The bound, and what it does not bound
///
/// Two limits stack: the address quota every open route carries, and `throttle::Recovery`'s
/// far narrower one. Together they close the **online** door to guessing. They do nothing about
/// the offline one: an attacker holding `recovery_escrows` never calls this route at all. That
/// asymmetry is the feature's central cost and it is written down in the migration.
async fn claim_recovery(
    State(pool): State<PgPool>,
    State(recovery): State<Arc<Recovery>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(payload): Json<ClaimRecovery>,
) -> ApiResult<Json<ClaimedRecovery>> {
    // Counted before the lookup, so a refusal costs the database nothing — and so that the
    // quota bounds attempts rather than successes.
    if !recovery.allows(&format!("recovery:{}", peer.ip())) {
        return Err(ApiError::TooManyRequests);
    }

    let lookup = decode_exact(&payload.lookup, RECOVERY_LOOKUP_LEN, "lookup of invalid length")?;

    // One query, joined: a second round trip for the handle would take a different amount of
    // time depending on whether the first found anything, which is the timing side of the
    // indistinguishability this route is built for.
    let row: Option<EscrowRow> = sqlx::query_as(
        "SELECT e.account, h.handle, e.kind, e.params, e.sealed
         FROM recovery_escrows e
         LEFT JOIN handles h ON h.account = e.account AND h.released_at IS NULL
         WHERE e.lookup = $1",
    )
    .bind(&lookup)
    .fetch_optional(&pool)
    .await?;

    let (account, handle, kind, params, sealed) = row.ok_or(ApiError::NotFound)?;

    Ok(Json(ClaimedRecovery {
        account,
        handle,
        kind,
        params: BASE64_STANDARD.encode(params),
        sealed: BASE64_STANDARD.encode(sealed),
    }))
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
    State(quota): State<Arc<crate::storage::Quota>>,
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

    // Recorded, not merely known: charging the uploader means keeping who they were. That is a
    // metadata leak the migration and `docs/THREAT-MODEL.md` both state, and it is what buys the
    // heaviest write this server accepts a personal bound.
    let account = caller_account(&pool, &signed.device_id).await?;
    let mut tx = pool.begin().await?;

    if !crate::storage::charge(&mut tx, &quota, &account, signed.body.len() as i64).await? {
        return Err(ApiError::InsufficientStorage);
    }

    let (id,): (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO attachments (group_id, account, payload) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&group_id)
    .bind(&account)
    .bind(signed.body.as_ref())
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

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
const MAX_PRESENCE_ACCOUNTS: usize = 64;

#[derive(Deserialize)]
struct PresenceRequest {
    accounts: Vec<String>,
}

#[derive(Serialize)]
struct PresenceEntry {
    account: String,
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

    if payload.accounts.len() > MAX_PRESENCE_ACCOUNTS {
        return Err(ApiError::BadRequest("too many accounts"));
    }

    let seen = presence::read(&pool, &signed.device_id, &payload.accounts).await?;
    // `SystemTime` rather than a date dependency: we only serve a number of seconds.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(Json(PresenceResponse {
        now,
        accounts: seen
            .into_iter()
            .map(|s| PresenceEntry { account: s.account, last_seen: s.last_seen })
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
#[derive(Deserialize)]
struct ContactPolicyRequest {
    policy: String,
}

/// Sets who may start a conversation with the calling account.
///
/// The account comes from the signing device and never from a parameter, as everywhere else here:
/// a route that took the account as input would let anybody close anybody's door.
async fn set_contact_policy(State(pool): State<PgPool>, signed: Signed) -> ApiResult<()> {
    let payload: ContactPolicyRequest = signed.json()?;

    // Validated here as well as in the schema. The constraint is the backstop; this is what turns
    // a typo into a 400 the caller can read rather than a 500 out of Postgres.
    if !matches!(payload.policy.as_str(), "open" | "known" | "closed") {
        return Err(ApiError::BadRequest("unknown contact policy"));
    }

    let account = caller_account(&pool, &signed.device_id).await?;

    sqlx::query("UPDATE accounts SET contact_policy = $2 WHERE id = $1")
        .bind(&account)
        .bind(&payload.policy)
        .execute(&pool)
        .await?;

    Ok(())
}

/// May `caller` add this device to `group_id`?
///
/// # Why the current group is excluded from the test
///
/// `known` means "already meets this account somewhere else". `add_members` creates the group and
/// inserts the caller *before* this runs, so a test that counted the group being built would find
/// the caller in it and answer yes to everybody — the setting would enforce nothing, and it would
/// look like it worked, which is worse than not shipping it.
///
/// # Why this reads `group_members` and learns nothing
///
/// That table is the server's own, and "do these two accounts meet somewhere" is a question it
/// could answer at any moment without being asked. Enforcing the policy therefore costs no new
/// knowledge; the only new fact is the policy, which is the fact its owner is asking the server
/// to act on.
async fn may_contact(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    caller: &str,
    device_id: &str,
    group_id: &[u8],
) -> ApiResult<bool> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT d.account, a.contact_policy
         FROM devices d JOIN accounts a ON a.id = d.account
         WHERE d.id = $1",
    )
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await?;

    // A device this server has never heard of. Not our refusal to make: the insert below does
    // nothing with it anyway, and answering "forbidden" here would turn this route into a test
    // for whether a device id exists.
    let Some((account, policy)) = row else {
        return Ok(true);
    };

    // Our own devices, always. `propagateOwnDevices` adds them to every conversation, and an
    // account whose policy locked its own phone out of its own threads would be unusable in a way
    // nobody would think to test.
    if account == caller {
        return Ok(true);
    }

    match policy.as_str() {
        "open" => Ok(true),
        "closed" => Ok(false),
        "known" => {
            let shared: Option<(i32,)> = sqlx::query_as(
                "SELECT 1
                 FROM group_members mine
                 JOIN devices d_mine ON d_mine.id = mine.device_id
                 JOIN group_members theirs ON theirs.group_id = mine.group_id
                 JOIN devices d_theirs ON d_theirs.id = theirs.device_id
                 WHERE d_mine.account = $1 AND d_theirs.account = $2 AND mine.group_id <> $3
                 LIMIT 1",
            )
            .bind(caller)
            .bind(&account)
            .bind(group_id)
            .fetch_optional(&mut **tx)
            .await?;

            Ok(shared.is_some())
        }
        // Unreachable while the schema constraint holds. Refusing rather than allowing is the
        // direction to fail in, for a setting whose whole purpose is to refuse.
        _ => Ok(false),
    }
}

async fn set_presence_optout(State(pool): State<PgPool>, signed: Signed) -> ApiResult<()> {
    let payload: OptoutRequest = signed.json()?;
    let account = caller_account(&pool, &signed.device_id).await?;

    sqlx::query("UPDATE accounts SET presence_optout = $2 WHERE id = $1")
        .bind(&account)
        .bind(payload.optout)
        .execute(&pool)
        .await?;

    // The past has no business surviving the opt-out: what was already recorded stops being
    // served, and stops existing too. Keeping it would make the setting a lie the moment it is
    // set.
    if payload.optout {
        sqlx::query("UPDATE devices SET last_seen_at = NULL WHERE account = $1")
            .bind(&account)
            .execute(&pool)
            .await?;
    }

    Ok(())
}
