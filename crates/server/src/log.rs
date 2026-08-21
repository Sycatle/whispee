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
    handle: &str,
    identity_key: &[u8],
) -> Result<(), sqlx::Error> {
    let leaf = transparency::leaf_hash(&transparency::entry(handle, identity_key));

    sqlx::query("INSERT INTO log_entries (handle, identity_key, leaf) VALUES ($1, $2, $3)")
        .bind(handle)
        .bind(identity_key)
        .bind(leaf.as_slice())
        .execute(tx)
        .await?;

    Ok(())
}

/// Brings accounts created before the log existed into it.
///
/// Without this catch-up their keys would have no inclusion proof and clients would reject them
/// all — the log would make the system less usable rather than safer.
///
/// The order is deterministic (`created_at, handle`): two runs must produce the same tree, or a
/// restart would look like a rewrite.
pub async fn backfill(pool: &PgPool) -> Result<usize, sqlx::Error> {
    let missing: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT a.handle, a.identity_key FROM accounts a
         WHERE NOT EXISTS (SELECT 1 FROM log_entries l WHERE l.handle = a.handle)
         ORDER BY a.created_at, a.handle",
    )
    .fetch_all(pool)
    .await?;

    let mut tx = pool.begin().await?;
    for (handle, identity_key) in &missing {
        append(&mut tx, handle, identity_key).await?;
    }
    tx.commit().await?;

    Ok(missing.len())
}

/// Every leaf, in tree order.
///
/// Re-read in full for each proof. Accepted for this project: a real log would cache the
/// intermediate nodes, but recomputing guarantees no derived state can diverge from the table —
/// and the table is what counts.
pub async fn leaves(pool: &PgPool) -> Result<Vec<Hash>, sqlx::Error> {
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT leaf FROM log_entries ORDER BY seq").fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(|(leaf,)| leaf.try_into().expect("log_leaf_is_sha256 constraint"))
        .collect())
}

/// Position of an account's latest entry, and its key.
///
/// The **latest**: a rotation adds an entry without removing any, and the most recent one is
/// authoritative. The older ones stay in the tree — that is what lets a client observe that a key
/// changed, rather than watch it disappear.
pub async fn latest(
    pool: &PgPool,
    handle: &str,
) -> Result<Option<(i64, Vec<u8>)>, sqlx::Error> {
    let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, identity_key FROM log_entries WHERE handle = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(handle)
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
pub fn head(leaves: &[Hash], key: &SigningKey) -> (TreeHead, [u8; 64]) {
    let head = TreeHead {
        size: leaves.len() as u64,
        root: transparency::root(leaves),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let signature = head.sign(key);
    (head, signature)
}
