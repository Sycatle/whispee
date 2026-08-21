//! Presence registry: who is awake, to the minute.
//!
//! # What this module adds to the threat model
//!
//! A registry that cuts across conversations, and no encrypted formulation avoids it: to show
//! that an account is connected, someone has to know. That someone is the server, and what it
//! learns is everyone's waking hours. See `migrations/0008_presence.sql` for what bounds the
//! leak.
//!
//! # What this module must never do
//!
//! **Be called from an anonymous path.** Sealed envelope posts and typing signals prove group
//! membership with a MAC, not identity: the server does not know who posts, and must not learn
//! it. Writing a presence touch there would require re-attributing the post to a device —
//! exactly the power sealed sender took away. A test freezes that.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use sqlx::PgPool;

/// Rewrite cadence. Bounds the freshness of the value, and is the only number that costs
/// anything.
///
/// The "online" threshold is a display choice and lives on the client: the server returns a
/// timestamp, never a boolean. A boolean would freeze the policy into the protocol and rule out
/// "last seen at 14:02" from the same data.
pub const PRESENCE_REFRESH: Duration = Duration::from_secs(60);

/// In-memory damping, in front of the SQL guard.
///
/// Kept in a `static` rather than in the application state: the attachment router only has
/// `PgPool` as state, and the `Signed` extractor is generic over `S`. In any case the real
/// protection is the `WHERE` clause below — it stays correct across several instances, this cache
/// does not.
static LAST_TOUCH: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Notes that a device is awake, at most once per `PRESENCE_REFRESH`.
///
/// Without damping, a client would write once per request: with ten conversations and a fetch
/// every thirty seconds, that is one write per second per device, for information unchanged
/// between two heartbeats.
///
/// The update stays HOT — `last_seen_at` is not indexed — so it rewrites no index entry. An
/// account that opted out of presence is never written: the opt-out is honoured here, at the
/// source, and not by filtering on read.
pub async fn touch(pool: &PgPool, device_id: &str) -> sqlx::Result<()> {
    {
        let mut cache = LAST_TOUCH.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(last) = cache.get(device_id)
            && last.elapsed() < PRESENCE_REFRESH
        {
            return Ok(());
        }
        cache.insert(device_id.to_owned(), Instant::now());
    }

    sqlx::query(
        "UPDATE devices d
            SET last_seen_at = date_trunc('minute', now())
          FROM accounts a
         WHERE d.id = $1
           AND a.handle = d.handle
           AND a.presence_optout = false
           AND (d.last_seen_at IS NULL OR d.last_seen_at < now() - interval '60 seconds')",
    )
    .bind(device_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Touches without ever failing the caller.
///
/// Used from the authentication extractor, which sits on the latency path of every signed
/// request. A presence write that failed a message send would be a regression of the main
/// function in exchange for a coloured dot.
pub fn touch_detached(pool: PgPool, device_id: String) {
    tokio::spawn(async move {
        if let Err(error) = touch(&pool, &device_id).await {
            tracing::debug!(%error, "presence not recorded");
        }
    });
}

/// Last activity of an account, in seconds since the epoch.
pub struct Seen {
    pub handle: String,
    pub last_seen: i64,
}

/// Reads the presence of the requested accounts, for a given caller.
///
/// # Access control
///
/// A handle is only served if the caller shares at least one group with it — or if it is their
/// own account. Without that clause, the route would be an activity oracle on any pseudonym on
/// the server.
///
/// Reciprocity: an account that opted out of broadcasting its presence does not get anyone
/// else's. Otherwise the setting would let you see without being seen, which is exactly what it
/// claims to prevent.
///
/// # What does not come out
///
/// Per-device detail. Only the `MAX` per account is served: how many devices a person has and
/// their respective habits are a leak distinct from "online".
///
/// An unknown handle and a handle with no shared group produce the same result — their absence.
/// Distinguishing them would make the route an account-existence oracle.
pub async fn read(pool: &PgPool, device_id: &str, handles: &[String]) -> sqlx::Result<Vec<Seen>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT d.handle, EXTRACT(EPOCH FROM MAX(d.last_seen_at))::BIGINT
           FROM devices d
          WHERE d.revoked_at IS NULL
            AND d.handle = ANY($2)
            AND EXISTS (
                  SELECT 1 FROM devices me
                   JOIN accounts a ON a.handle = me.handle
                  WHERE me.id = $1 AND a.presence_optout = false
                )
            AND (
                 d.handle = (SELECT handle FROM devices WHERE id = $1)
              OR EXISTS (
                   SELECT 1
                     FROM group_members me
                     JOIN group_members them ON them.group_id = me.group_id
                     JOIN devices other ON other.id = them.device_id
                    WHERE me.device_id = $1 AND other.handle = d.handle
                 )
            )
          GROUP BY d.handle
         HAVING MAX(d.last_seen_at) IS NOT NULL",
    )
    .bind(device_id)
    .bind(handles)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(handle, last_seen)| Seen { handle, last_seen }).collect())
}
