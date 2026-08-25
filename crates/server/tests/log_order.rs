//! The one invariant an append-only log has: a leaf never moves.
//!
//! Everything the transparency log promises rests on it. An inclusion proof names a position; a
//! consistency proof asserts that the tree a client pinned is a *prefix* of the tree served now.
//! Move one leaf and both become false — and the client cannot tell that from a server keeping
//! two logs, which is the accusation the whole mechanism exists to make. A false one is therefore
//! as damaging as a missed true one.

mod common;

use common::{TestAccount, start, unique};

/// Reads the tree as the server would.
async fn leaves(pool: &sqlx::PgPool) -> Vec<transparency::Hash> {
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT leaf FROM log_entries ORDER BY seq").fetch_all(pool).await.unwrap();

    rows.into_iter().map(|(leaf,)| leaf.try_into().unwrap()).collect()
}

/// Two appends that overlap: the tree a client pinned stays a prefix of the tree that follows.
///
/// # The race this pins, and why `seq` alone could not answer it
///
/// `log_entries.seq` is a `BIGSERIAL`, so a number is drawn at `INSERT` and becomes **visible** at
/// `COMMIT`. Two overlapping appends can therefore commit in the reverse of their numbering: the
/// larger `seq` lands first and is read into a tree, and when the smaller one follows it takes a
/// position *before* it in `ORDER BY seq`. That is not an append — it is an insertion in the
/// middle of a log a client has already signed off on, and `verify_consistency` rightly refuses
/// it.
///
/// The fix is in `log::append`, which takes a transaction-scoped advisory lock before drawing its
/// number. What that buys is exactly the missing guarantee: numbering order **is** commit order,
/// because the number cannot be drawn while another appender holds the lock, and the lock is only
/// released by its holder's commit or rollback.
#[tokio::test]
async fn a_leaf_never_moves_when_two_appends_overlap() {
    let server = start().await;

    let a = TestAccount::create(&server, &unique("racera")).await;
    let b = TestAccount::create(&server, &unique("racerb")).await;

    // The first transaction appends and stays open.
    let mut slow = server.pool.begin().await.unwrap();
    server::log::append(&mut slow, &a.id, &[1u8; 32], None).await.unwrap();

    // The second appends while the first is still uncommitted, and commits first. Without the
    // lock in `append` it would draw the larger number and win the race to visibility; with it,
    // it blocks here until the first transaction releases — so this call is also the assertion
    // that the lock is taken at all.
    let pool = server.pool.clone();
    let account_b = b.id.clone();
    let racing = tokio::spawn(async move {
        let mut fast = pool.begin().await.unwrap();
        server::log::append(&mut fast, &account_b, &[2u8; 32], None).await.unwrap();
        fast.commit().await.unwrap();
    });

    // Long enough for the second transaction to have got there and blocked. If it did not block,
    // it has committed by now and the leaf order is already inverted.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // What a client sees and pins at this instant.
    let seen = leaves(&server.pool).await;
    let pinned_size = seen.len();
    let pinned_root = transparency::root(&seen);

    slow.commit().await.unwrap();
    racing.await.unwrap();

    let now = leaves(&server.pool).await;
    let root_now = transparency::root(&now);

    assert!(now.len() > pinned_size, "neither append landed");

    let proof = transparency::consistency_proof(&now, pinned_size).unwrap();
    transparency::verify_consistency(pinned_size, &pinned_root, now.len(), &root_now, &proof)
        .expect(
            "the tree the client pinned is no longer a prefix of the tree served now: a fork \
             this server produced by letting two appends commit out of their numbering order",
        );
}
