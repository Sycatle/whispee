//! Auditable log of account keys, server side.
//!
//! # What the server does here, and what it does not
//!
//! It **builds** the tree and **signs** the heads. It verifies nothing on the client's behalf:
//! every proof it emits is re-verified client side, with the same [`transparency`] crate, against
//! the log's public key. That is the only way a log means anything — otherwise you are asking the
//! watched party to guarantee the watching.
//!
//! # The structural weakness, not to be hidden
//!
//! The log is signed by the same party it watches. A malicious server can therefore keep **two**
//! consistent logs and serve one to each side. Nothing in this file prevents that, and nothing
//! could: detection belongs to *gossip* between clients, comparing heads inside messages the
//! server can neither read nor forge.
//!
//! A serious deployment would hand the log to one or more separate operators. Here there is a
//! single process, and saying so beats letting people guess.

use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use transparency::{Hash, TreeHead};

/// Loads the log's signing key, creating it on first start.
///
/// `ON CONFLICT DO NOTHING` rather than a "read then write": two processes starting together
/// would otherwise produce two keys, hence two logs, and clients would see a fork we caused
/// ourselves.
pub async fn ensure_signing_key(pool: &PgPool) -> Result<(), sqlx::Error> {
    let fresh = SigningKey::generate(&mut rand_core::OsRng);

    sqlx::query("INSERT INTO log_key (id, signing_key) VALUES (TRUE, $1) ON CONFLICT DO NOTHING")
        .bind(fresh.to_bytes().as_slice())
        .execute(pool)
        .await?;

    Ok(())
}

/// Re-reads the log key.
///
/// Re-read on every request rather than cached in the application state. That is one database
/// round trip per proof, accepted for this project: a cached signing key is the kind of state
/// that survives a rotation you believed had happened.
pub async fn signing_key(pool: &PgPool) -> Result<SigningKey, sqlx::Error> {
    let (stored,): (Vec<u8>,) =
        sqlx::query_as("SELECT signing_key FROM log_key WHERE id = TRUE").fetch_one(pool).await?;

    let bytes: [u8; 32] = stored.try_into().expect("log_signing_key_is_ed25519 constraint");
    Ok(SigningKey::from_bytes(&bytes))
}

/// Appends an account key to the log.
///
/// The leaf hash is computed **here**, by the shared crate, and never in SQL: a second
/// implementation of the formula diverges sooner or later, and a silent divergence in an
/// auditable log is worse than no log at all.
///
/// To be called in the same transaction as the account write: a key published without a log entry
/// would be rejected by every client.
pub async fn append(
    tx: &mut sqlx::PgConnection,
    account: &str,
    identity_key: &[u8],
    // `rotation` is the signature authorising this key, and the instant it covers. `None` on the
    // genesis entry, which has no predecessor to be authorised by: its authority is that its
    // fingerprint **is** the account id, and a client checks that directly rather than being told
    // it. Every later entry carries the link — see `migrations/0015_rotation_chain.sql` for why
    // the chain is published at all.
    rotation: Option<(&[u8], u64)>,
) -> Result<(), sqlx::Error> {
    let leaf = transparency::leaf_hash(&transparency::entry(account, identity_key));

    sqlx::query(
        "INSERT INTO log_entries (account, identity_key, leaf, rotation, rotated_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(account)
    .bind(identity_key)
    .bind(leaf.as_slice())
    .bind(rotation.map(|(signature, _)| signature))
    .bind(rotation.map(|(_, at)| at as i64))
    .execute(tx)
    .await?;

    Ok(())
}

/// One published key of an account, and what authorised it.
///
/// Ordered by `seq`, which is the tree's own order: the first is the genesis key, whose
/// fingerprint is the account id.
pub struct ChainLink {
    pub seq: i64,
    pub identity_key: Vec<u8>,
    pub rotation: Option<Vec<u8>>,
    pub rotated_at: Option<i64>,
}

/// Every key an account has published, oldest first.
///
/// The server can withhold a link and cannot forge one. A chain with a hole fails to verify on
/// the client, which says so rather than assuming continuity — omission stays possible and stays
/// detectable, which is the asymmetry the whole project rests on.
pub async fn chain(pool: &PgPool, account: &str) -> Result<Vec<ChainLink>, sqlx::Error> {
    let rows: Vec<(i64, Vec<u8>, Option<Vec<u8>>, Option<i64>)> = sqlx::query_as(
        "SELECT seq, identity_key, rotation, rotated_at FROM log_entries
         WHERE account = $1 ORDER BY seq",
    )
    .bind(account)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(seq, identity_key, rotation, rotated_at)| ChainLink {
            seq,
            identity_key,
            rotation,
            rotated_at,
        })
        .collect())
}

/// Brings accounts created before the log existed into it.
///
/// Without this catch-up their keys would have no inclusion proof and clients would reject them
/// all — the log would make the system less usable rather than safer.
///
/// The order is deterministic (`created_at, account`): two runs must produce the same tree, or a
/// restart would look like a rewrite.
pub async fn backfill(pool: &PgPool) -> Result<usize, sqlx::Error> {
    let missing: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT a.id, a.identity_key FROM accounts a
         WHERE NOT EXISTS (SELECT 1 FROM log_entries l WHERE l.account = a.id)
         ORDER BY a.created_at, a.id",
    )
    .fetch_all(pool)
    .await?;

    let mut tx = pool.begin().await?;
    for (account, identity_key) in &missing {
        // A backfilled account has no rotation to record: this is its first published key.
        append(&mut tx, account, identity_key, None).await?;
    }
    tx.commit().await?;

    Ok(missing.len())
}

/// What identifies the exact contents of `log_entries`, in two numbers.
///
/// # Why these two and not a version counter
///
/// A counter would have to be written by every appender and read by every instance, which is a
/// second piece of state that can disagree with the table. These two are *derived from* the
/// table, so they cannot.
///
/// They are sufficient because of what `seq` is. `BIGSERIAL` never goes backwards and never
/// reissues a value, so `last_seq` can only grow, and it grows on every insert. Rows can only
/// leave through the `ON DELETE CASCADE` on `accounts`, and any departure lowers `size`.
/// Restoring `size` afterwards takes an insert, which raises `last_seq` past the value we
/// recorded. So an unchanged pair means an unchanged table — including the awkward case of a
/// transaction that was granted a low `seq` and commits after a later one, which shows up as a
/// change in `size`.
///
/// **What it does not detect** is a row rewritten in place: an `UPDATE` of a `leaf` moves
/// neither number. Nothing in this crate ever updates `log_entries` — the log is append-only by
/// construction, not by convention — and whoever can issue that `UPDATE` can also read
/// `log_key` from the same database and sign whatever head they like. Guarding against it here
/// would be theatre.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fingerprint {
    size: i64,
    last_seq: i64,
}

/// The tree as it stood in the table, with the proof it was that tree.
///
/// The leaves are kept alongside the root because `inclusion_proof` and `consistency_proof` need
/// them: caching only the root would move the full table read from `/v1/log/sth` onto the two
/// proof routes, which is not a saving.
pub struct Snapshot {
    pub leaves: Vec<Hash>,
    pub root: Hash,
    fingerprint: Fingerprint,
}

/// The last tree read, shared by every request this process serves.
///
/// Process-wide rather than held in the application state because [`backfill`] and the route
/// handlers reach the log through a bare `PgPool` and nothing else. The consequence to be aware
/// of is that a single process opening pools onto **two different logs** would have them share
/// one cache and serve each other's roots. That configuration does not exist — one server, one
/// database — but it is a real precondition and not a tautology.
static CACHED: std::sync::LazyLock<std::sync::Mutex<Option<std::sync::Arc<Snapshot>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

/// Reads the two numbers that say whether the cached tree is still the tree in the table.
///
/// One statement, so both numbers come from one snapshot of the table. Two statements would let
/// a commit land between them and produce a pair that never actually existed — which would be a
/// way to certify a stale cache as fresh.
async fn fingerprint(pool: &PgPool) -> Result<Fingerprint, sqlx::Error> {
    let (size, last_seq): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COALESCE(MAX(seq), 0) FROM log_entries")
            .fetch_one(pool)
            .await?;

    Ok(Fingerprint { size, last_seq })
}

/// Reads every leaf and rebuilds the tree.
///
/// The fingerprint is taken from the rows themselves rather than from a second query, so that
/// what is stored in the cache and what certifies it necessarily describe the same read.
async fn rebuild(pool: &PgPool) -> Result<std::sync::Arc<Snapshot>, sqlx::Error> {
    let rows: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT seq, leaf FROM log_entries ORDER BY seq").fetch_all(pool).await?;

    let fingerprint = Fingerprint {
        size: rows.len() as i64,
        last_seq: rows.last().map(|(seq, _)| *seq).unwrap_or(0),
    };

    let leaves: Vec<Hash> = rows
        .into_iter()
        .map(|(_, leaf)| leaf.try_into().expect("log_leaf_is_sha256 constraint"))
        .collect();

    Ok(std::sync::Arc::new(Snapshot { root: transparency::root(&leaves), leaves, fingerprint }))
}

/// The current tree, from the cache when the table has not moved.
///
/// # What this answers in the comment that used to sit on `leaves`
///
/// That comment said recomputation was chosen because it "guarantees no derived state can
/// diverge from the table". The reasoning was right and the conclusion was too expensive:
/// `/v1/log/sth`, `/v1/log/proof/{handle}` and `/v1/log/consistency` are signed routes carrying
/// no quota, and each one read the whole table and re-hashed the whole tree. At any realistic
/// account count that is the cheapest request on the server to saturate it with.
///
/// The cache keeps the guarantee rather than trading it away: **it never trusts itself**. Every
/// call re-derives the fingerprint from the table and only reuses what it holds if the table
/// says it is still current. Divergence is therefore not prevented by discipline at the write
/// sites — it is impossible to serve, because serving requires the table to agree first.
///
/// # Across instances
///
/// Nothing has to be invalidated, and no instance has to be told anything. An append made by
/// another process changes `size` and `last_seq`, every other instance sees the mismatch on its
/// very next request and rebuilds. The `LISTEN/NOTIFY` fanout the deployment already uses is
/// deliberately **not** wired in here: notification is best-effort by design — `crate::stream`
/// says as much and drops on a full queue — and a cache invalidated by a message that may be
/// dropped is a cache that can serve a wrong root. Paying one index-only aggregate per request
/// to make that impossible is the conservative choice, and it is the one taken.
///
/// # What this is not
///
/// It is not O(1). The probe still counts rows; it is an index-only scan of the primary key
/// instead of shipping every leaf over the wire and re-hashing the tree, which is a large
/// constant factor and not a change of complexity. A log that outgrows that would want cached
/// interior nodes and an incremental root — a different design, and premature here.
///
/// Two requests that miss at the same time both rebuild, and the slower one may overwrite the
/// newer entry with its own older tree. Neither is a correctness problem: each caller is handed a
/// tree that really was in the table when it read it, which is all a signed head has to be, and a
/// cache left holding the older of the two is rejected by the very next request's probe. Holding
/// the lock across the query to avoid the duplicated work would serialise every request behind
/// one database round trip, which is a worse trade than doing it twice.
pub async fn snapshot(pool: &PgPool) -> Result<std::sync::Arc<Snapshot>, sqlx::Error> {
    let current = fingerprint(pool).await?;

    {
        let cached = CACHED.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(snapshot) = cached.as_ref()
            && snapshot.fingerprint == current
        {
            return Ok(std::sync::Arc::clone(snapshot));
        }
    }

    let fresh = rebuild(pool).await?;
    *CACHED.lock().unwrap_or_else(|error| error.into_inner()) = Some(std::sync::Arc::clone(&fresh));

    Ok(fresh)
}

/// Position of an account's latest entry, and its key.
///
/// The **latest**: a rotation adds an entry without removing any, and the most recent one is
/// authoritative. The older ones stay in the tree — that is what lets a client observe that a key
/// changed, rather than watch it disappear.
pub async fn latest(
    pool: &PgPool,
    account: &str,
) -> Result<Option<(i64, Vec<u8>)>, sqlx::Error> {
    let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, identity_key FROM log_entries WHERE account = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(account)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// Index of an entry in the tree.
///
/// `seq` is a `BIGSERIAL`: it grows strictly but can skip (aborted transaction). It therefore
/// cannot be used directly as an index; the preceding entries have to be counted. Confusing the
/// two would produce inclusion proofs valid for the wrong position — the kind of bug that only
/// shows up once a rollback has happened.
pub async fn index_of(pool: &PgPool, seq: i64) -> Result<usize, sqlx::Error> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM log_entries WHERE seq < $1").bind(seq).fetch_one(pool).await?;

    Ok(count as usize)
}

/// The log's current head, signed.
///
/// Takes a [`Snapshot`] rather than a slice of leaves so the root cannot be recomputed here by
/// accident: the whole point of the snapshot is that the root was computed once, for that exact
/// state of the table.
pub fn head(snapshot: &Snapshot, key: &SigningKey) -> (TreeHead, [u8; 64]) {
    let head = TreeHead {
        size: snapshot.leaves.len() as u64,
        root: snapshot.root,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let signature = head.sign(key);
    (head, signature)
}
