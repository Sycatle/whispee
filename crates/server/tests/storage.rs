//! The per-account stored-bytes ceiling.
//!
//! What is checked here is not that a number is enforced — that part is one `UPDATE` — but the
//! two things that make a maintained counter either trustworthy or worthless: that a refusal
//! stores nothing and charges nothing, and that every path which deletes gives the bytes back.
//! The last test reconciles rather than asserting a figure, so a deletion path added later is
//! covered by it without being named in it.

mod common;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use common::{TestAccount, account_with_group, now, start, start_with_storage_quota, unique};

/// Bytes stored by an account, recomputed from the tables rather than read off the counter.
async fn actually_stored(pool: &sqlx::PgPool, account: &str) -> i64 {
    let (bytes,): (i64,) = sqlx::query_as(
        "SELECT COALESCE((SELECT SUM(octet_length(payload)) FROM vault_entries WHERE account = $1), 0)
              + COALESCE((SELECT SUM(octet_length(payload)) FROM attachments WHERE account = $1), 0)",
    )
    .bind(account)
    .fetch_one(pool)
    .await
    .unwrap();

    bytes
}

/// What the counter says, which is what the ceiling is enforced against.
async fn counter(pool: &sqlx::PgPool, account: &str) -> i64 {
    let (bytes,): (i64,) = sqlx::query_as("SELECT bytes FROM account_storage WHERE account = $1")
        .bind(account)
        .fetch_one(pool)
        .await
        .expect("no counter row for a registered account");

    bytes
}

fn vault_body(seq: i64, size: usize) -> serde_json::Value {
    serde_json::json!({
        "entries": [{ "seq": seq, "payload": BASE64_STANDARD.encode(vec![7u8; size]) }]
    })
}

/// The counter exists the moment the account does, and starts empty.
///
/// A row created lazily on first write would make every charge an upsert, and an upsert cannot
/// express "refuse if this would cross the ceiling" in one statement: the insert has already
/// happened by the time the condition is looked at.
#[tokio::test]
async fn an_account_gets_an_empty_counter() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;

    assert_eq!(counter(&server.pool, &alice.id).await, 0);
}

/// Deleting the account takes its counter with it.
#[tokio::test]
async fn deleting_an_account_removes_its_counter() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;

    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(&alice.id)
        .execute(&server.pool)
        .await
        .unwrap();

    let row: Option<(i64,)> = sqlx::query_as("SELECT bytes FROM account_storage WHERE account = $1")
        .bind(&alice.id)
        .fetch_optional(&server.pool)
        .await
        .unwrap();

    assert!(row.is_none(), "the counter outlived the account it belongs to");
}

/// The backfill agrees with what is actually stored.
///
/// The harness applies the migrations when it opens the pool, so no test can populate a database
/// *before* `0019`. What is checked is the statement rather than its timing: no counter in the
/// database disagrees with the rows it counts. A backfill computing the wrong thing fails here;
/// one that ran at the wrong moment is out of this suite's reach, and the migration says so.
#[tokio::test]
async fn no_counter_disagrees_with_the_rows_it_counts() {
    let server = start().await;

    let (drift,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM account_storage s
          WHERE s.bytes <> COALESCE((SELECT SUM(octet_length(v.payload))
                                       FROM vault_entries v
                                      WHERE v.account = s.account), 0)
                         + COALESCE((SELECT SUM(octet_length(a.payload))
                                       FROM attachments a
                                      WHERE a.account = s.account), 0)",
    )
    .fetch_one(&server.pool)
    .await
    .unwrap();

    assert_eq!(drift, 0, "{drift} counters disagree with the rows they count");
}

/// A vault write moves the counter by the bytes stored, not by the size of the request.
///
/// Run against `start()`, whose ceiling is disabled — which is the point as much as the figure
/// is: `0` switches off enforcement, never the bookkeeping. A deployment that runs unlimited and
/// sets a ceiling later must not start from zero, or every account gets a full allowance on top
/// of what it already stores.
#[tokio::test]
async fn a_vault_write_is_charged_to_its_owner() {
    let server = start().await;
    let (alice, device, group) = account_with_group(&server, "alice").await;

    let response =
        device.post(&format!("/v1/vault/{}", hex::encode(&group)), vault_body(1, 1000)).await;
    assert!(response.status().is_success(), "vault write refused: {}", response.status());

    // 1000 and not 1336: base64 is a third larger, and charging for the encoding would make the
    // ceiling depend on the transport rather than on the disk.
    assert_eq!(counter(&server.pool, &alice.id).await, 1000);
}

/// Re-depositing an entry charges nothing the second time.
///
/// `ON CONFLICT DO NOTHING` skips the row, and two devices of one account archiving the same
/// conversation is the ordinary case rather than an edge one. Charging before the insert would
/// charge for a row that was not written, and nothing credits an overcharge — the counter would
/// climb above the tables for good. This is why the insert comes first and the charge follows it
/// inside the same transaction.
#[tokio::test]
async fn a_repeated_deposit_is_charged_once() {
    let server = start().await;
    let (alice, device, group) = account_with_group(&server, "alice").await;

    let path = format!("/v1/vault/{}", hex::encode(&group));
    device.post(&path, vault_body(1, 1000)).await;
    device.post(&path, vault_body(1, 1000)).await;

    assert_eq!(counter(&server.pool, &alice.id).await, 1000, "the same row was charged twice");
    assert_eq!(counter(&server.pool, &alice.id).await, actually_stored(&server.pool, &alice.id).await);
}

/// A write past the ceiling is refused with 507, stores nothing, and charges nothing.
#[tokio::test]
async fn a_write_past_the_ceiling_stores_nothing() {
    let server = start_with_storage_quota(500).await;
    let (alice, device, group) = account_with_group(&server, "alice").await;

    let response =
        device.post(&format!("/v1/vault/{}", hex::encode(&group)), vault_body(1, 1000)).await;
    assert_eq!(response.status(), 507);

    let (rows,): (i64,) = sqlx::query_as("SELECT count(*) FROM vault_entries WHERE account = $1")
        .bind(&alice.id)
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "a refused write left rows behind");
    assert_eq!(counter(&server.pool, &alice.id).await, 0, "a refused write charged the account");
}

/// Two writes that each fit and jointly do not: one passes, one is refused, the ceiling holds.
///
/// This is the test the single-statement charge exists for. Under a read-then-write both would
/// pass, and the ceiling would be a number an attacker steps over by opening a second connection.
#[tokio::test]
async fn concurrent_writes_cannot_both_cross_the_ceiling() {
    let server = start_with_storage_quota(1500).await;
    let (alice, device, group) = account_with_group(&server, "alice").await;

    let path = format!("/v1/vault/{}", hex::encode(&group));
    let (first, second) =
        tokio::join!(device.post(&path, vault_body(1, 1000)), device.post(&path, vault_body(2, 1000)));

    let statuses = [first.status().as_u16(), second.status().as_u16()];
    assert!(statuses.iter().any(|s| (200..300).contains(s)), "both refused: {statuses:?}");
    assert!(statuses.contains(&507), "both passed: {statuses:?}");
    assert!(counter(&server.pool, &alice.id).await <= 1500, "the counter passed the ceiling");
}

/// An upload is charged to the account that signed it, and the row records which one that was.
#[tokio::test]
async fn an_upload_is_charged_to_its_uploader() {
    let server = start().await;
    let (alice, device, group) = account_with_group(&server, "alice").await;

    let path = format!("/v1/groups/{}/attachments", hex::encode(&group));
    let blob = vec![3u8; 2048];
    let response =
        device.signed_at("POST", &path, blob.clone(), now(), &path).await;
    assert!(response.status().is_success(), "upload refused: {}", response.status());

    assert_eq!(counter(&server.pool, &alice.id).await, 2048);

    let (owner,): (Option<String>,) =
        sqlx::query_as("SELECT account FROM attachments WHERE group_id = $1")
            .bind(&group)
            .fetch_one(&server.pool)
            .await
            .unwrap();
    assert_eq!(owner.as_deref(), Some(alice.id.as_str()));
}

/// An upload past the ceiling is refused with 507 and stores nothing.
#[tokio::test]
async fn an_upload_past_the_ceiling_stores_nothing() {
    let server = start_with_storage_quota(1024).await;
    let (_alice, device, group) = account_with_group(&server, "alice").await;

    let path = format!("/v1/groups/{}/attachments", hex::encode(&group));
    let response = device.signed_at("POST", &path, vec![3u8; 2048], now(), &path).await;
    assert_eq!(response.status(), 507);

    let (rows,): (i64,) = sqlx::query_as("SELECT count(*) FROM attachments WHERE group_id = $1")
        .bind(&group)
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

/// A purge gives the bytes back to the uploader.
#[tokio::test]
async fn a_purge_credits_the_uploader() {
    let server = start().await;
    let (alice, device, group) = account_with_group(&server, "alice").await;

    let path = format!("/v1/groups/{}/attachments", hex::encode(&group));
    device.signed_at("POST", &path, vec![3u8; 4096], now(), &path).await;
    assert_eq!(counter(&server.pool, &alice.id).await, 4096);

    // Ages the row past the retention rule rather than waiting a year for it.
    sqlx::query("UPDATE attachments SET created_at = now() - interval '400 days' WHERE group_id = $1")
        .bind(&group)
        .execute(&server.pool)
        .await
        .unwrap();

    server::purge_once(&server.pool).await.unwrap();

    assert_eq!(
        counter(&server.pool, &alice.id).await,
        0,
        "the purge deleted the bytes without giving them back"
    );
}

/// The counter and the tables agree after writes, a purge and a deletion.
///
/// This is the test that catches the failure mode of a maintained counter: a deletion path that
/// forgets to credit. It reconciles rather than asserting a number, so a path added later is
/// covered by it without being named in it.
#[tokio::test]
async fn the_counter_reconciles_with_what_is_actually_stored() {
    let server = start().await;
    let (alice, device, group) = account_with_group(&server, "alice").await;

    let attachments = format!("/v1/groups/{}/attachments", hex::encode(&group));
    device.signed_at("POST", &attachments, vec![3u8; 4096], now(), &attachments).await;
    device.signed_at("POST", &attachments, vec![3u8; 8192], now(), &attachments).await;
    device.post(&format!("/v1/vault/{}", hex::encode(&group)), vault_body(1, 500)).await;

    sqlx::query(
        "UPDATE attachments SET created_at = now() - interval '400 days'
          WHERE group_id = $1 AND octet_length(payload) = 4096",
    )
    .bind(&group)
    .execute(&server.pool)
    .await
    .unwrap();

    server::purge_once(&server.pool).await.unwrap();

    assert_eq!(
        counter(&server.pool, &alice.id).await,
        actually_stored(&server.pool, &alice.id).await,
        "the counter drifted from what is stored"
    );
}
