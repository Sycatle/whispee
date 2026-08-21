//! Delivery service: the transport MLS does not define.
//!
//! # What this server can see
//!
//! Nothing of the content. But it does see, and saying so matters:
//!
//! * who is registered, and since when;
//! * which device belongs to which group (table `group_members`);
//! * who writes in which group, when, and the size of each message;
//! * who claims whose KeyPackage — hence who starts a conversation with whom;
//! * when each account is awake, to the minute (`devices.last_seen_at`).
//!
//! That is WhatsApp's trade-off. Shrinking it takes sealed sender, padding and zero-knowledge
//! credentials. None of that is done here, and claiming otherwise would be worse than not
//! doing it.

pub mod auth;
pub mod error;
pub mod gateway;
pub mod log;
pub mod presence;
pub mod push;
pub mod routes;
pub mod stream;
pub mod throttle;

use std::sync::Arc;

use axum::extract::FromRef;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// State shared by the handlers: the database, and the connected listeners.
///
/// `FromRef` is what lets existing handlers keep extracting `State<PgPool>` untouched —
/// including the [`auth::Signed`] extractor, which only requires that a `PgPool` be derivable
/// from the state.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub hub: Arc<stream::Hub>,
    /// Rate limit on the open routes, counted per address.
    pub throttle: Arc<throttle::Throttle>,
    /// Limit on KeyPackage consumption, counted per caller-target pair.
    ///
    /// Kept separate from the previous one because the two are not the same order of magnitude:
    /// a single bound would be either too loose to protect a stock, or too tight to let anyone
    /// sign up.
    pub claims: Arc<throttle::Claims>,
    /// Per-device ceilings on the authenticated write routes.
    ///
    /// Separate again, and for the same reason: a device may legitimately post a hundred
    /// messages in a minute and has no business uploading a hundred attachments in one. See
    /// `throttle::Writes` for each number and for what none of them solve.
    pub writes: Arc<throttle::Writes>,
    /// What wakes sleeping devices.
    ///
    /// [`push::Silent`] by default, and that is a design choice, not a placeholder: a deployment
    /// that talks to neither Apple nor Google must stay fully functional. See `push` for what
    /// this wake-up costs in metadata.
    pub push: Arc<dyn push::Waker>,
}

impl FromRef<AppState> for PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

impl FromRef<AppState> for Arc<stream::Hub> {
    fn from_ref(state: &AppState) -> Self {
        state.hub.clone()
    }
}

impl FromRef<AppState> for Arc<throttle::Throttle> {
    fn from_ref(state: &AppState) -> Self {
        state.throttle.clone()
    }
}

impl FromRef<AppState> for Arc<dyn push::Waker> {
    fn from_ref(state: &AppState) -> Self {
        state.push.clone()
    }
}

impl FromRef<AppState> for Arc<throttle::Claims> {
    fn from_ref(state: &AppState) -> Self {
        state.claims.clone()
    }
}

impl FromRef<AppState> for Arc<throttle::Writes> {
    fn from_ref(state: &AppState) -> Self {
        state.writes.clone()
    }
}

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    // One connection more than before: inter-instance listening (`stream::Hub::attach`) holds
    // one permanently on its `LISTEN`. Not adjusting this number would amount to taking a
    // connection away from serving requests.
    let pool = PgPoolOptions::new()
        .max_connections(11)
        .connect(database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    // The log's key is created on first start, never twice: two keys would sign two logs, and
    // clients would see a fork caused by us.
    log::ensure_signing_key(&pool).await?;

    // Accounts predating the log must enter it, otherwise clients would reject all their keys
    // for lack of an inclusion proof.
    log::backfill(&pool).await?;

    Ok(pool)
}

/// Refuses an open request when the address has exceeded its quota.
///
/// # Why the socket address, and nothing else
///
/// `X-Forwarded-For` is freely forged: reading it would make the limit a formality, a header to
/// write in order to bypass it. The server therefore only knows what the TCP stack tells it.
/// The trade-off is real and accepted — behind a proxy, every request carries the proxy's
/// address, and it is then up to the proxy to carry the limit.
///
/// # Why 429 and not 403
///
/// The caller did nothing forbidden; it only did too much. Distinguishing the two lets an
/// honest client retry later instead of concluding it is banned.
async fn rate_limit(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::ConnectInfo(pair): axum::extract::ConnectInfo<std::net::SocketAddr>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    if state.throttle.allows(&format!("ip:{}", pair.ip())) {
        return next.run(request).await;
    }

    tracing::debug!(address = %pair.ip(), "open route quota exceeded");
    (axum::http::StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response()
}

/// How long an anonymous post's nonce is remembered.
///
/// Unlike the request-nonce window below, this one cannot be derived from anything, and
/// pretending otherwise would be the comfortable answer: an anonymous post carries **no
/// timestamp**. Its MAC covers the group,
/// the nonce and the body digest, nothing that ages — `migrations/0007_sealed_sender.sql` says
/// so plainly. There is therefore no window past which a replay stops being accepted, and the
/// only retention that protects completely is "forever", which is exactly the unbounded growth
/// being fixed.
///
/// So this is a chosen number, not a derived one. Seven days is far longer than any capture is
/// useful to hold on to, and short enough that the table stops being a one-way ratchet.
///
/// **What it costs, stated rather than hidden:** past a week, a captured anonymous post becomes
/// replayable again, once per purge cycle it survives. What that buys an attacker is one extra
/// row in `envelopes` and one spurious wake-up per replay — the MLS client discards the
/// duplicate, the application ratchet having already consumed that generation. It is a storage
/// nuisance, not a way into a conversation. The trade is a bounded nuisance in exchange for a
/// table that no longer grows for the lifetime of the deployment.
const POSTING_NONCE_RETENTION_DAYS: u32 = 7;

/// Age below which an envelope is never deleted, whatever else is true of it.
///
/// Thirty days is the offline window a device is allowed. Past it, and **only in conjunction
/// with [`ENVELOPE_MIN_TAIL`]**, its mailbox may lose envelopes it never read — which breaks its
/// MLS application ratchet, not merely its display. The number is therefore not a storage
/// parameter dressed up as a policy: it is the answer to "how long may a phone stay in a drawer
/// before its owner has to be re-added to their own conversations".
///
/// What it does not solve: a device gone longer than that, in a group busy enough to have moved
/// five hundred envelopes on, is broken and has to be re-invited. The purge makes that case rare
/// and — through the `oldest` field of the fetch response — detectable. It does not make it
/// impossible, and no retention that actually deletes anything could.
const ENVELOPE_RETENTION_DAYS: u32 = 30;

/// Envelopes kept at the tail of every group, regardless of age.
///
/// This is the half of the rule that protects quiet conversations. Age alone would empty a
/// two-person thread of three hundred messages exchanged over two years — messages that cost the
/// server nothing to keep and whose deletion the participants would experience as data loss for
/// no gain. With this clause, **a group that has never reached five hundred envelopes is never
/// touched, at any age**.
///
/// Five hundred rather than a round hundred because it must comfortably exceed
/// `routes::MAX_ENVELOPES_PER_PAGE` (200): a client that comes back and paginates must never
/// have the ground move under it inside a single catch-up.
///
/// What it does not solve: it is a count, not a size. Five hundred envelopes carrying 25 MiB
/// attachment descriptors and five hundred carrying "ok" occupy the same slot in this rule. The
/// bound that would answer that is a stored-bytes quota per account, which `throttle` names and
/// this server still does not have.
const ENVELOPE_MIN_TAIL: i64 = 500;

/// Age past which an attachment is deleted, whatever the state of its envelope.
///
/// Longer than [`ENVELOPE_RETENTION_DAYS`] on purpose, and the reason is specific: a message
/// restored from the vault carries its attachment descriptor with it, so the descriptor outlives
/// the envelope that delivered it and stays resolvable for a while afterwards. Three months is
/// that "while".
///
/// **Stated plainly, because a user will meet it: an attachment older than three months is no
/// longer downloadable.** The bytes are gone from the server, the vault archives the message and
/// not the file, and saving what matters is the recipient's job. A server that promised
/// otherwise would be promising to be a backup service.
const ATTACHMENT_RETENTION_DAYS: u32 = 90;

/// What one pass of the purge erased, per table.
#[derive(Debug, Default)]
pub struct Purged {
    pub request_nonces: u64,
    pub posting_nonces: u64,
    pub pairings: u64,
    pub envelopes: u64,
    pub attachments: u64,
    /// Groups nobody is a member of any more.
    ///
    /// Counts the `groups` rows only. What the cascade takes with them — their envelopes and
    /// attachments — is deliberately **not** added to the two counters above: those report what
    /// the retention rules deleted, and mixing in a cascade would make the numbers unusable for
    /// the only thing they are read for, which is noticing that a retention rule has started
    /// biting harder than expected.
    pub groups: u64,
}

/// Erases what replay protection and pairing no longer need.
///
/// # `request_nonces`
///
/// A nonce only needs to be remembered for as long as the request could still be accepted, that
/// is, the clock tolerance window. Beyond it, `auth::Signed` rejects the request on its
/// timestamp, and keeping the nonce would protect nothing.
///
/// Twice the window is kept, so as not to race the clock: erasing a still-acceptable nonce would
/// reopen exactly the hole the table exists to close.
///
/// # `posting_nonces`
///
/// Same purpose for the sealed-sender path, but no window to lean on. See
/// [`POSTING_NONCE_RETENTION_DAYS`] for the number and for what choosing it gives up.
///
/// # `pairings`
///
/// The cheapest of the three to argue: `claim_pairing` already filters on `expires_at > now()`,
/// so an expired row is invisible to every reader before it is deleted. Removing it changes no
/// observable behaviour at all — it only stops a five-minute drop box from being kept for the
/// lifetime of the process. No margin is needed for the same reason: there is nothing left to
/// race with.
///
/// The statement has no index to lean on and scans the table. That is deliberate rather than
/// overlooked: once this purge exists the table holds roughly the pairings started in the last
/// five minutes, and an index on `expires_at` would cost a write on every deposit to speed up a
/// scan over a handful of rows.
///
/// # `envelopes`
///
/// The one this server said it would never do, and the argument for why it now can is in
/// `migrations/0012_retention.sql` rather than repeated here. The short form: the condition is a
/// **conjunction** of [`ENVELOPE_RETENTION_DAYS`] and [`ENVELOPE_MIN_TAIL`], so a quiet
/// conversation is never emptied by age and a briefly absent device is never evicted by volume.
///
/// # `attachments`
///
/// Age alone, at [`ATTACHMENT_RETENTION_DAYS`] — longer than the envelope retention, for the
/// reason written on that constant. There is no tail clause here and there should not be: an
/// attachment is addressed by id, not by sequence, so "the last five hundred" means nothing
/// about it.
///
/// # Abandoned `groups`
///
/// `remove_members` empties `group_members` and nothing has ever deleted the `groups` row, so a
/// group everyone has left keeps its envelopes forever — out of reach of every human being,
/// including the ones who wrote them, since every read path starts with a membership check.
/// Deleting the row lets the `ON DELETE CASCADE` from 0001 and 0009 collect the envelopes and
/// the attachments.
///
/// # Why one task and not six
///
/// They share a cadence and each is a single statement. A second `tokio::spawn` would buy
/// nothing but a second place to forget a table in — and forgetting one is precisely how
/// `posting_nonces` and `pairings` came to have no purge at all while `posting_nonces_used_at_idx`
/// sat in migration 0007 indexing a cleanup nobody had written.
///
/// This task is not a convenience. Without it, `request_nonces` grows by one row per
/// authenticated request and `posting_nonces` by one row plus one index entry per sealed-sender
/// post, forever.
fn purge_expired(pool: PgPool) {
    tokio::spawn(async move {
        let mut pace = tokio::time::interval(std::time::Duration::from_secs(60));

        loop {
            pace.tick().await;

            match purge_once(&pool).await {
                Ok(purged) => {
                    let total = purged.request_nonces
                        + purged.posting_nonces
                        + purged.pairings
                        + purged.envelopes
                        + purged.attachments
                        + purged.groups;
                    if total > 0 {
                        tracing::debug!(
                            request_nonces = purged.request_nonces,
                            posting_nonces = purged.posting_nonces,
                            pairings = purged.pairings,
                            envelopes = purged.envelopes,
                            attachments = purged.attachments,
                            groups = purged.groups,
                            "expired rows purged"
                        );
                    }
                }
                // A momentarily unavailable database is not fatal: the next purge catches up.
                // Failing loudly would make an operational incident look like a security defect.
                Err(error) => tracing::debug!(%error, "purge deferred"),
            }
        }
    });
}

/// One pass of the purge.
///
/// Separated from the loop above so the tests can run a pass on demand: waiting a minute for the
/// tick would make the test either slow or flaky, and a test that never observes the deletion
/// proves nothing about it.
///
/// The retentions are compile-time constants interpolated into the statements, as the nonce
/// purge already did — there is no caller-supplied value anywhere near them.
pub async fn purge_once(pool: &PgPool) -> Result<Purged, sqlx::Error> {
    let request_nonces = sqlx::query(&format!(
        "DELETE FROM request_nonces WHERE seen_at < now() - interval '{} seconds'",
        auth::MAX_CLOCK_SKEW * 2
    ))
    .execute(pool)
    .await?
    .rows_affected();

    let posting_nonces = sqlx::query(&format!(
        "DELETE FROM posting_nonces WHERE used_at < now() - interval '{POSTING_NONCE_RETENTION_DAYS} days'"
    ))
    .execute(pool)
    .await?
    .rows_affected();

    let pairings = sqlx::query("DELETE FROM pairings WHERE expires_at < now()")
        .execute(pool)
        .await?
        .rows_affected();

    // The join on `groups` is what makes the tail clause meaningful: `next_seq` is the only place
    // the length of a conversation is recorded, and it is maintained in the same transaction as
    // every insert, so it cannot lag behind the rows it is compared against.
    //
    // `<=` rather than `<`, and the arithmetic is worth spelling out because an off-by-one here
    // deletes one envelope more than the tail promises. Sequences start at 1: `post_envelope`
    // increments `next_seq` and returns the incremented value. A group holding exactly five
    // hundred envelopes therefore has `next_seq = 500` and sequences 1..=500, so `next_seq - 500`
    // is 0 and nothing matches. The five hundred and first post makes seq 1 deletable, and five
    // hundred still remain.
    let envelopes = sqlx::query(&format!(
        "DELETE FROM envelopes e
         USING groups g
         WHERE e.group_id = g.id
           AND e.created_at < now() - interval '{ENVELOPE_RETENTION_DAYS} days'
           AND e.seq <= g.next_seq - {ENVELOPE_MIN_TAIL}"
    ))
    .execute(pool)
    .await?
    .rows_affected();

    let attachments = sqlx::query(&format!(
        "DELETE FROM attachments WHERE created_at < now() - interval '{ATTACHMENT_RETENTION_DAYS} days'"
    ))
    .execute(pool)
    .await?
    .rows_affected();

    // Last, so the two counters above report what the retention rules deleted rather than what a
    // cascade happened to carry off with a group.
    //
    // The second clause is what stops this from racing group creation. `add_members` creates the
    // `groups` row and inserts its first member in one transaction, so under READ COMMITTED no
    // reader ever sees the row without its member — but that is an invariant of one function, and
    // this statement runs every sixty seconds against whatever the codebase becomes. Requiring
    // that no envelope younger than the retention exists makes the deletion depend on observable
    // silence rather than on a transaction boundary holding somewhere else.
    //
    // What that clause does NOT do, and it is worth saying since it reads as a grace period: a
    // group with no envelope at all satisfies it vacuously and is deleted the moment its last
    // member leaves. That is intended. A member-less, envelope-less group holds nothing, nobody
    // can read it, and the only thing its row carries is a posting key for a mailbox with no
    // mail.
    let groups = sqlx::query(&format!(
        "DELETE FROM groups g
         WHERE NOT EXISTS (SELECT 1 FROM group_members m WHERE m.group_id = g.id)
           AND NOT EXISTS (
               SELECT 1 FROM envelopes e
               WHERE e.group_id = g.id
                 AND e.created_at >= now() - interval '{ENVELOPE_RETENTION_DAYS} days'
           )"
    ))
    .execute(pool)
    .await?
    .rows_affected();

    Ok(Purged { request_nonces, posting_nonces, pairings, envelopes, attachments, groups })
}

/// Ceiling for an attachment, encryption included.
///
/// AES-GCM encryption only adds a 16-byte tag: in practice the limit therefore applies to the
/// size of the original file.
pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// Origins allowed to call the API from a browser.
///
/// Never a wildcard: `Access-Control-Allow-Origin: *` would let any site trigger requests to
/// this server from a user's browser. Requests stay signed, so a third-party site could not
/// authenticate anything — but allowing broadly without reason is exactly what turns a minor
/// defect into a breach.
fn cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, Method, HeaderValue};
    use tower_http::cors::CorsLayer;

    // The desktop application's origins are in the default, not only in the documentation: they
    // are fixed — the operating system imposes them, they depend on no deployment — and
    // forgetting them produces a "Failed to fetch" the browser emits before sending anything, so
    // without leaving a trace in the server logs.
    //
    // `tauri://localhost` on Linux and macOS, `http://tauri.localhost` on Windows and Android.
    let origins: Vec<HeaderValue> = std::env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| {
            "http://127.0.0.1:5173,http://localhost:5173,tauri://localhost,http://tauri.localhost"
                .into()
        })
        .split(',')
        .filter_map(|origin| origin.trim().parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        // Every header the client sends must be listed here, otherwise the browser blocks the
        // request **before** it leaves: the server sees nothing, and the client only gets a
        // "Failed to fetch" that does not name the cause. Integration tests do not go through
        // the preflight and therefore cannot catch the omission.
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("x-device-id"),
            HeaderName::from_static("x-timestamp"),
            HeaderName::from_static("x-signature"),
            // Replay protection. Missing from here, the browser blocks **every** signed request
            // at the preflight, before it is sent: the server never sees it.
            HeaderName::from_static("x-nonce"),
            // Anonymous post (sealed sender), also used by ephemeral signals.
            HeaderName::from_static("x-group-nonce"),
            HeaderName::from_static("x-group-mac"),
        ])
}

pub fn app(pool: PgPool) -> axum::Router {
    app_with(pool, throttle::Limits::from_environment())
}

/// Variant with imposed limits.
///
/// Exists for the tests: the harness disables them — it creates dozens of accounts, publishes
/// KeyPackages and posts envelopes in a few seconds from the loopback, which no realistic quota
/// would allow — and each test that checks one limit bites turns exactly that one back on.
pub fn app_with(pool: PgPool, limits: throttle::Limits) -> axum::Router {
    app_with_waker(pool, limits, Arc::new(push::Silent))
}

/// The same application, with a chosen wake-up emitter.
///
/// Exists for the tests: what the server sends to the provider — and above all **to whom** — is
/// a confidentiality property, not a routing detail. Checking it requires seeing the addresses
/// go by, hence being able to substitute the emitter.
pub fn app_with_waker(
    pool: PgPool,
    limits: throttle::Limits,
    push: Arc<dyn push::Waker>,
) -> axum::Router {
    use tower_http::limit::RequestBodyLimitLayer;
    use tower_http::trace::TraceLayer;

    // KeyPackages and MLS envelopes are small: a tight ceiling prevents a single request from
    // exhausting the server's memory. Attachments have their own, far higher ceiling, applied
    // to their routes only.
    let state = AppState {
        pool: pool.clone(),
        hub: stream::Hub::new(),
        throttle: Arc::new(limits.throttle),
        claims: Arc::new(limits.claims),
        writes: Arc::new(limits.writes),
        // The default is `Silent`, set by `app_with`: wiring up Apple or Google requires secrets
        // a deployment must provide knowingly, after reading what the wake-up leaks.
        push,
    };

    // Wires the hub onto Postgres, which allows running several instances without their clients
    // losing sight of each other. Detaches tasks: this function must therefore be called from a
    // tokio runtime.
    state.hub.attach(pool.clone());

    purge_expired(pool.clone());

    let messages = routes::router(state.clone()).layer(RequestBodyLimitLayer::new(1024 * 1024));
    // The attachment router now carries the whole state rather than just the pool: uploads are
    // counted against a per-device quota, and the counter lives in the state. The alternative —
    // a second, process-wide limiter reachable from a bare `PgPool` — would have been a
    // duplicate of the machinery already here, which is exactly how two limits come to disagree.
    let attachments = routes::attachment_router(state.clone())
        .layer(RequestBodyLimitLayer::new(MAX_ATTACHMENT_BYTES));

    // The open routes additionally carry the rate limit. It applies to them alone: elsewhere the
    // signature identifies the caller, and abuse is handled by revoking the device rather than
    // by penalising an address shared with innocents.
    let public = routes::public_router(state.clone())
        .layer(axum::middleware::from_fn_with_state(state, rate_limit))
        .layer(RequestBodyLimitLayer::new(1024 * 1024));

    messages
        .merge(attachments)
        .merge(public)
        .layer(cors_layer())
        .layer(TraceLayer::new_for_http())
}
