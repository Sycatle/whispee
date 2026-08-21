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
/// Kept in a `static` rather than in the application state: the `Signed` extractor is generic
/// over `S`, and threading a cache through it would constrain every router that wants to touch
/// presence. In any case the real protection is the `WHERE` clause below — it stays correct
/// across several instances, this cache does not.
static LAST_TOUCH: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Past this many tracked devices, stale entries are swept.
///
/// Without it this map holds one entry per device id ever seen, for the lifetime of the process,
/// and never gives one back: a cache that exists to spare the database a write would have become
/// a way to fill memory instead. Same reasoning and same number as `throttle::SWEEP_THRESHOLD`,
/// deliberately — two caches with the same shape and two different ceilings would only invite
/// the question of which one is right.
///
/// The sweep runs on insertion rather than on a timer: a process that has stopped touching
/// presence has stopped growing the map, so there is nothing to collect and no task worth waking
/// to discover it.
///
/// What it does not do is bound the map at the threshold. An entry younger than
/// [`PRESENCE_REFRESH`] is still doing its job and is kept, so a burst of more than
/// `SWEEP_THRESHOLD` distinct devices inside one minute leaves the map above the threshold until
/// they age out. That is the correct trade — evicting a live entry costs a database write, which
/// is the only thing this cache exists to avoid.
const SWEEP_THRESHOLD: usize = 4096;

/// Decides whether this device is due a presence write, and records the decision.
///
/// Split out of [`touch`] so it can be tested without a database: what is worth pinning down here
/// is the damping and the sweep, neither of which involves SQL. Synchronous on purpose — the lock
/// is never held across an `await`, which is what makes a `std::sync::Mutex` the right one.
fn is_due(device_id: &str) -> bool {
    let mut cache = LAST_TOUCH.lock().unwrap_or_else(|e| e.into_inner());

    if cache.len() > SWEEP_THRESHOLD {
        cache.retain(|_, last| last.elapsed() < PRESENCE_REFRESH);
    }

    if let Some(last) = cache.get(device_id)
        && last.elapsed() < PRESENCE_REFRESH
    {
        return false;
    }

    cache.insert(device_id.to_owned(), Instant::now());
    true
}

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
    if !is_due(device_id) {
        return Ok(());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// [`LAST_TOUCH`] is process-wide, so two of these tests running at once would read each
    /// other's entries. Serialising them is cheaper and clearer than making each one tolerant of
    /// a map it does not control.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn reset() -> std::sync::MutexGuard<'static, ()> {
        let guard = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        LAST_TOUCH.lock().unwrap_or_else(|e| e.into_inner()).clear();
        guard
    }

    fn tracked() -> usize {
        LAST_TOUCH.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// An entry aged past the refresh window, without waiting for it.
    fn stale() -> Instant {
        Instant::now()
            .checked_sub(PRESENCE_REFRESH * 2)
            .expect("the process clock is younger than two refresh windows")
    }

    #[test]
    fn a_device_is_written_once_per_refresh_window() {
        let _guard = reset();

        assert!(is_due("alice:laptop"), "the first heartbeat must reach the database");
        assert!(!is_due("alice:laptop"), "the second would rewrite an unchanged value");
    }

    #[test]
    fn one_device_does_not_damp_another() {
        let _guard = reset();

        assert!(is_due("alice:laptop"));
        assert!(is_due("bob:phone"), "the damping is per device, not global");
    }

    /// **The test that pins down the sweep.**
    ///
    /// Without it this map grows by one entry per device id ever seen and never shrinks — for the
    /// whole life of the process. `throttle::Throttle` has carried a threshold for exactly this
    /// reason since it was written; this cache did not, and the difference was an oversight
    /// rather than a decision.
    #[test]
    fn the_cache_gives_back_what_it_no_longer_needs() {
        let _guard = reset();

        {
            let mut cache = LAST_TOUCH.lock().unwrap_or_else(|e| e.into_inner());
            for device in 0..=SWEEP_THRESHOLD {
                cache.insert(format!("ghost:{device}"), stale());
            }
        }

        assert!(tracked() > SWEEP_THRESHOLD, "the sweep has nothing to trigger it yet");

        assert!(is_due("alice:laptop"), "a device unknown to the cache is always due");

        assert_eq!(tracked(), 1, "only the device that just touched should remain");
    }

    /// The sweep keeps what is still doing its job.
    ///
    /// Evicting an entry younger than [`PRESENCE_REFRESH`] would cost exactly the database write
    /// the cache exists to avoid — the map would stay small by being useless.
    #[test]
    fn the_sweep_spares_the_entries_that_are_still_damping() {
        let _guard = reset();

        {
            let mut cache = LAST_TOUCH.lock().unwrap_or_else(|e| e.into_inner());
            for device in 0..SWEEP_THRESHOLD {
                cache.insert(format!("ghost:{device}"), stale());
            }
            cache.insert("alice:laptop".to_owned(), Instant::now());
        }

        assert!(is_due("bob:phone"), "an unknown device is due");

        assert!(!is_due("alice:laptop"), "a fresh entry was swept and cost a needless write");
    }
}
