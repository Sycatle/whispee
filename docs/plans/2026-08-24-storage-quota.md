# Stored-bytes quota — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every account a live ceiling on the bytes it stores durably — vault entries and attachments — enforced at write time and credited back when the bytes leave.

**Architecture:** One counter row per account in `account_storage`, debited and checked by a single `UPDATE … WHERE bytes + $1 <= ceiling` inside the transaction that inserts the payload, credited by `purge_once` and by group deletion. Refusal is 507, distinct from the 429 of `throttle.rs`. Attachments gain an `account` column so the uploader can be charged and credited.

**Tech Stack:** Rust 1.95 (edition 2024), Axum, sqlx + PostgreSQL 17, React 19 + TypeScript on the client, `node --test` for the web suite.

**Spec:** [`docs/specs/2026-08-24-storage-quota.md`](../specs/2026-08-24-storage-quota.md)

## Global Constraints

- Default ceiling: **256 MiB per account** (`268435456`), read from `ACCOUNT_STORAGE_BYTES`, falling back to the constant on an unparseable value — same rule as `throttle::quota`.
- `0` disables the ceiling. The integration harness relies on this exactly as it does for the rate limits (`Limits::off()`).
- Refusal status is **507**, never 429.
- Nothing is evicted to make room. A refusal stores nothing.
- Every check-and-debit is one SQL statement, inside the transaction that writes the payload.
- Envelopes are **out of scope**: their bound is `docs/specs/2026-08-24-posting-allowance.md`. Do not touch `post_envelope`.
- Documentation that says the quota is missing must stop saying it in the same commit that adds it. Prose is part of the deliverable in this repo, not a follow-up.
- Tests need PostgreSQL: `docker compose up -d` before `cargo test -p server`.

---

### Task 1: The counter table and the uploader column

**Files:**
- Create: `crates/server/migrations/0019_storage_quota.sql`
- Test: `crates/server/tests/storage.rs`

**Interfaces:**
- Produces: table `account_storage(account TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE, bytes BIGINT NOT NULL DEFAULT 0)`; column `attachments.account TEXT NULL REFERENCES accounts(id) ON DELETE SET NULL`.

- [ ] **Step 1: Write the failing test**

`crates/server/tests/storage.rs`:

```rust
mod common;

use common::{TestAccount, start};

/// The counter exists for an account the moment the account does, and starts empty.
///
/// A row created lazily on first write would mean every charge is an upsert, and an upsert
/// cannot express "refuse if this would cross the ceiling" in one statement.
#[tokio::test]
async fn an_account_gets_an_empty_counter() {
    let server = start().await;
    let alice = TestAccount::create(&server, &common::unique("alice")).await;

    let (bytes,): (i64,) = sqlx::query_as("SELECT bytes FROM account_storage WHERE account = $1")
        .bind(&alice.id)
        .fetch_one(&server.pool)
        .await
        .expect("no counter row for a registered account");

    assert_eq!(bytes, 0);
}

/// Deleting the account takes its counter with it. (Replaced during execution: see below.)
#[tokio::test]
async fn deleting_an_account_removes_its_counter() {
    let server = start().await;
    let alice = TestAccount::create(&server, &common::unique("alice")).await;

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
/// The harness runs the migrations when it opens the pool, so a database cannot be populated
/// *before* `0019` from inside a test. What is checked instead is the statement itself: the
/// backfill's `SELECT` is replayed against the live tables and compared to the counters it
/// produced. A backfill that computed the wrong thing fails here; one that ran at the wrong
/// moment is out of reach of this suite, and the migration says so in its own comment.
#[tokio::test]
async fn the_backfill_matches_what_is_stored() {
    let server = start().await;
    let alice = TestAccount::create(&server, &common::unique("alice")).await;

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
    let _ = alice;
}
```

**Corrected during execution.** The deletion test could not be written as an exercise: this
server has no way to delete an account. A raw `DELETE FROM accounts` sets `handles.account` to
null through that table's own cascade, and `tombstones_are_unowned` refuses it — a handle without
an owner must be a tombstone. `docs/ROADMAP.md` says the same from the other end. The cascade is
therefore asserted out of `information_schema` rather than exercised, and the test says why.

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose up -d && cargo test -p server --test storage`
Expected: FAIL — `relation "account_storage" does not exist`.

- [ ] **Step 3: Write the migration**

`crates/server/migrations/0019_storage_quota.sql`:

```sql
-- A stored-bytes quota per account: the bound `throttle.rs` has named since it was written.
--
-- # Why a counter and not a SUM
--
-- The check has to happen before the write, on every write, and `SUM(octet_length(payload))`
-- over an account's vault is an aggregation whose cost grows with exactly the quantity being
-- bounded. A maintained counter is O(1) to read and O(1) to move.
--
-- What that costs is drift: every path that deletes must credit, or an account is refused
-- writes for bytes that no longer exist. `crates/server/tests/storage.rs` reconciles the
-- counter against the recomputed SUM after writes, purges and deletions, so a forgotten
-- credit fails a test rather than becoming an incident nobody can reconstruct.
--
-- # Why the row is created with the account
--
-- So that charging is an UPDATE and never an upsert. `UPDATE … WHERE bytes + $1 <= ceiling`
-- says "refuse if this crosses the ceiling" in one statement, which is what makes the check
-- safe under concurrency. `INSERT … ON CONFLICT DO UPDATE` cannot express the refusal: the
-- conflicting insert has already happened by the time the condition is evaluated.

CREATE TABLE account_storage (
    account TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    bytes   BIGINT NOT NULL DEFAULT 0,

    CONSTRAINT bytes_not_negative CHECK (bytes >= 0)
);

-- Every account that already exists, with what it already stores.
INSERT INTO account_storage (account, bytes)
SELECT a.id,
       COALESCE((SELECT SUM(octet_length(v.payload))
                   FROM vault_entries v
                  WHERE v.account = a.id), 0)
  FROM accounts a;

-- ACCEPTED METADATA LEAK, and the only one this migration introduces: the server now records
-- **who** uploaded which attachment into which group. It already learned it — an upload is a
-- signed request — but it did not keep it. Charging the uploader means keeping it.
--
-- The alternative was charging the group, which leaves the heaviest write the server accepts
-- (`MAX_ATTACHMENT_BYTES`, twenty-five mebibytes) outside any personal bound and lets one
-- member exhaust a ceiling shared with people who wrote nothing. See
-- `docs/THREAT-MODEL.md` and `docs/specs/2026-08-24-storage-quota.md`.
--
-- Nullable, and null means *predates this migration*: rows uploaded before it have no owner to
-- retrofit, and inventing one would be worse than admitting the hole. They age out under
-- `ATTACHMENT_RETENTION_DAYS`, after which the hole closes by itself.
--
-- ON DELETE SET NULL rather than CASCADE: a deleted account must not silently delete
-- attachments other members are still fetching.
ALTER TABLE attachments
    ADD COLUMN account TEXT REFERENCES accounts(id) ON DELETE SET NULL;

-- The credit path reads attachments by owner when a purge deletes them.
CREATE INDEX attachments_account_idx ON attachments (account);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p server --test storage`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add crates/server/migrations/0019_storage_quota.sql crates/server/tests/storage.rs
git commit -m "feat(server): a counter per account, and an owner on every attachment"
```

---

### Task 2: The ceiling, and the two operations that move the counter

**Files:**
- Create: `crates/server/src/storage.rs`
- Modify: `crates/server/src/lib.rs` (add `pub mod storage;`, extend `AppState` and `FromRef`), `crates/server/src/throttle.rs` (extend `Limits`)
- Test: unit tests inside `crates/server/src/storage.rs`

**Interfaces:**
- Consumes: `account_storage` from Task 1.
- Produces:
  - `pub struct Quota { ceiling: i64 }`
  - `Quota::bytes(i64) -> Quota`, `Quota::from_environment() -> Quota`, `Quota::ceiling(&self) -> i64`
  - `pub const DEFAULT_ACCOUNT_BYTES: i64 = 256 * 1024 * 1024;`
  - `pub async fn charge(tx: &mut sqlx::PgTransaction<'_>, quota: &Quota, account: &str, bytes: i64) -> Result<bool, sqlx::Error>` — `false` means the ceiling refused it, and nothing was written.
  - `pub async fn credit(tx: &mut sqlx::PgTransaction<'_>, account: &str, bytes: i64) -> Result<(), sqlx::Error>`
  - `throttle::Limits` gains `pub storage: storage::Quota`, `Limits::off()` sets `Quota::bytes(0)`.

- [ ] **Step 1: Write the failing test**

At the bottom of `crates/server/src/storage.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ceiling_of_zero_is_no_ceiling() {
        assert!(Quota::bytes(0).unlimited());
        assert!(!Quota::bytes(1).unlimited());
    }

    #[test]
    fn an_unreadable_variable_falls_back_to_the_default() {
        // SAFETY: single-threaded test, and the variable is read only here.
        unsafe { std::env::set_var("ACCOUNT_STORAGE_BYTES", "two hundred megabytes") };
        assert_eq!(Quota::from_environment().ceiling(), DEFAULT_ACCOUNT_BYTES);
        unsafe { std::env::remove_var("ACCOUNT_STORAGE_BYTES") };
    }

    #[test]
    fn the_default_is_the_documented_number() {
        assert_eq!(DEFAULT_ACCOUNT_BYTES, 268_435_456);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p server --lib storage`
Expected: FAIL — `file not found for module storage` / unresolved `Quota`.

- [ ] **Step 3: Write the module**

`crates/server/src/storage.rs`:

```rust
//! What an account is allowed to keep on this server, and the two operations that move it.
//!
//! # Why this is not in `throttle`
//!
//! Because it bounds a different quantity, and conflating them is the mistake `throttle`'s own
//! header warns about: its quotas bound a **rate**, per device, keyed on time. Nothing keyed on
//! time stops a disk from filling — it turns "fill it this afternoon" into "fill it over a
//! fortnight". This bounds a **total**, per account, and it is the bound that actually closes
//! the question.
//!
//! # Why the account and not the device
//!
//! `throttle` counts devices because a device is what a signature proves, and ten devices are
//! ten people's worth of typing. Storage is the opposite case: ten devices of one account share
//! one vault, and giving each of them its own ceiling would multiply the disk by the number of
//! times somebody logged in.
//!
//! # What this does not close
//!
//! N accounts times the ceiling is still N times the ceiling. What bounds N is registration, a
//! different mechanism and not this one. And envelopes are not counted here at all: a sealed
//! post carries no device id, so charging the account behind it takes anonymous tokens — see
//! `docs/specs/2026-08-24-posting-allowance.md`.

use sqlx::{PgTransaction, Postgres};

/// Default ceiling on the bytes one account may keep, in bytes: 256 MiB.
///
/// Picked from the abuse it has to stop rather than from the use it has to allow. Ten vault
/// writes a minute, two hundred entries each, at the 256-byte minimum the padding imposes, is
/// about seven hundred megabytes a day and per device: this ceiling meets an attacker within
/// hours. Real use is tens of megabytes a year, so a legitimate account never sees the edge.
pub const DEFAULT_ACCOUNT_BYTES: i64 = 256 * 1024 * 1024;

/// The per-account ceiling in force.
pub struct Quota {
    ceiling: i64,
}

impl Quota {
    /// A ceiling in bytes. `0` disables it.
    ///
    /// Disabling exists for the integration harness, which writes far more in a few seconds
    /// than any realistic ceiling admits; the test that checks the ceiling bites sets its own.
    pub fn bytes(ceiling: i64) -> Self {
        Self { ceiling }
    }

    /// Ceiling read from `ACCOUNT_STORAGE_BYTES`, or [`DEFAULT_ACCOUNT_BYTES`].
    ///
    /// An unparseable value falls back to the default rather than failing the start-up, exactly
    /// as `throttle::quota` does: refusing to boot on a typo in a tuning variable turns a
    /// harmless mistake into an outage.
    pub fn from_environment() -> Self {
        Self::bytes(
            std::env::var("ACCOUNT_STORAGE_BYTES")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(DEFAULT_ACCOUNT_BYTES),
        )
    }

    pub fn ceiling(&self) -> i64 {
        self.ceiling
    }

    pub fn unlimited(&self) -> bool {
        self.ceiling == 0
    }
}

/// Charges an account for bytes about to be written.
///
/// Returns `false` when the ceiling refuses them, and the caller must abandon the transaction
/// without writing anything.
///
/// # Why the check and the debit are one statement
///
/// A read followed by a write is a race, and under that race two concurrent uploads that each
/// fit both pass. A quota that fails under concurrency is a quota an attacker meets by opening
/// a second connection, which is not a quota. The condition rides on the `UPDATE` itself, so
/// PostgreSQL's row lock serialises the two.
pub async fn charge(
    tx: &mut PgTransaction<'_>,
    quota: &Quota,
    account: &str,
    bytes: i64,
) -> Result<bool, sqlx::Error> {
    if quota.unlimited() {
        return Ok(true);
    }

    let affected = sqlx::query::<Postgres>(
        "UPDATE account_storage
            SET bytes = bytes + $1
          WHERE account = $2 AND bytes + $1 <= $3",
    )
    .bind(bytes)
    .bind(account)
    .bind(quota.ceiling)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    Ok(affected == 1)
}

/// Gives bytes back to an account whose payload has been deleted.
///
/// Clamped at zero by the table's own constraint rather than by a branch here: a credit larger
/// than what is charged is a bug in a deletion path, and it should fail loudly the first time
/// rather than round itself away every time afterwards.
pub async fn credit(
    tx: &mut PgTransaction<'_>,
    account: &str,
    bytes: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query::<Postgres>(
        "UPDATE account_storage SET bytes = bytes - $1 WHERE account = $2",
    )
    .bind(bytes)
    .bind(account)
    .execute(&mut **tx)
    .await?;

    Ok(())
}
```

- [ ] **Step 4: Wire it into the application state**

In `crates/server/src/lib.rs`, next to the other modules:

```rust
pub mod storage;
```

In `AppState`, after `writes`:

```rust
    /// Ceiling on what one account may keep on this server.
    ///
    /// Separate from `writes` because it bounds a total rather than a rate: see `storage` for
    /// why no quota keyed on time can stand in for it.
    pub storage: Arc<storage::Quota>,
```

Its `FromRef`, next to the others:

```rust
impl FromRef<AppState> for Arc<storage::Quota> {
    fn from_ref(state: &AppState) -> Self {
        state.storage.clone()
    }
}
```

In `app_with_waker`, inside the `AppState { … }` literal:

```rust
        storage: Arc::new(limits.storage),
```

In `crates/server/src/throttle.rs`, extend `Limits`:

```rust
pub struct Limits {
    pub throttle: Throttle,
    pub claims: Claims,
    pub writes: Writes,
    /// Ceiling on stored bytes per account. See `crate::storage`.
    pub storage: crate::storage::Quota,
}
```

`from_environment` gains `storage: crate::storage::Quota::from_environment(),` and `off()` gains `storage: crate::storage::Quota::bytes(0),`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p server --lib storage && cargo check -p server --all-targets`
Expected: PASS, and the workspace still compiles.

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/storage.rs crates/server/src/lib.rs crates/server/src/throttle.rs
git commit -m "feat(server): a per-account ceiling, charged and credited in one statement"
```

---

### Task 3: A refusal that does not say "retry later"

**Files:**
- Modify: `crates/server/src/error.rs`

**Interfaces:**
- Produces: `ApiError::InsufficientStorage`, mapping to `StatusCode::INSUFFICIENT_STORAGE` (507).

- [ ] **Step 1: Write the failing test**

At the bottom of `crates/server/src/error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    /// 507, and above all not 429.
    ///
    /// The distinction is the one `Gone` already draws against `NotFound`: 429 means *retry
    /// later*, which is true of a rate limit and false of a full vault. A client told to retry
    /// a ceiling retries forever.
    #[test]
    fn a_full_account_is_not_a_client_going_too_fast() {
        let full = ApiError::InsufficientStorage.into_response().status();
        let fast = ApiError::TooManyRequests.into_response().status();

        assert_eq!(full.as_u16(), 507);
        assert_ne!(full, fast);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p server --lib error`
Expected: FAIL — no variant `InsufficientStorage`.

- [ ] **Step 3: Add the variant**

In the `ApiError` enum, after `TooManyRequests`:

```rust
    /// The caller is within its rate, and out of room.
    ///
    /// Distinct from `TooManyRequests` on purpose, and the distinction is the whole point: a 429
    /// tells an honest client to come back later, which is true of a rate limit and never
    /// becomes true of a ceiling. A client told to retry a full vault retries forever, and its
    /// user believes their history is being archived while nothing is.
    #[error("storage quota reached")]
    InsufficientStorage,
```

In the `match` inside `into_response`:

```rust
            ApiError::InsufficientStorage => StatusCode::INSUFFICIENT_STORAGE,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p server --lib error`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/error.rs
git commit -m "feat(server): say \"full\" with a status that does not mean \"later\""
```

---

### Task 4: The vault charges what it stores

**Files:**
- Modify: `crates/server/src/routes.rs` (`store_vault`, around line 1810)
- Modify: `crates/server/tests/common/mod.rs` (add `start_with_storage_quota`)
- Test: `crates/server/tests/storage.rs`

**Interfaces:**
- Consumes: `storage::charge`, `storage::Quota`, `ApiError::InsufficientStorage`, `Limits.storage`.
- Produces: `common::start_with_storage_quota(bytes: i64) -> TestServer`.

- [ ] **Step 1: Write the failing test**

Add the harness helper to `crates/server/tests/common/mod.rs`:

```rust
/// Test server with an enforced storage ceiling, in bytes.
///
/// The rate limits stay off: setting up a test's account, device and group consumes several
/// writes, and the two bounds have nothing to do with each other.
pub async fn start_with_storage_quota(bytes: i64) -> TestServer {
    start_with(
        pool().await,
        Limits { storage: server::storage::Quota::bytes(bytes), ..Limits::off() },
    )
    .await
}
```

Add to `crates/server/tests/storage.rs` (reuse the group set-up already used by the vault tests in `crates/server/tests/api.rs` — a group of one is enough, since `store_vault` only requires membership):

```rust
/// A vault write moves the counter by exactly the bytes stored.
#[tokio::test]
async fn a_vault_write_is_charged_to_its_owner() {
    let server = start().await;
    let (alice, device, group) = common::account_with_group(&server, "alice").await;

    let payload = BASE64_STANDARD.encode(vec![7u8; 1000]);
    let response = device
        .signed_at(
            "POST",
            &format!("/v1/vault/{}", hex::encode(&group)),
            serde_json::json!({ "entries": [{ "seq": 1, "payload": payload }] }),
        )
        .await;
    assert_eq!(response.status(), 200);

    let (bytes,): (i64,) = sqlx::query_as("SELECT bytes FROM account_storage WHERE account = $1")
        .bind(&alice.id)
        .fetch_one(&server.pool)
        .await
        .unwrap();

    assert_eq!(bytes, 1000, "the counter must move by the stored bytes, not by the request size");
}

/// A write that would cross the ceiling is refused with 507, and stores nothing.
#[tokio::test]
async fn a_write_past_the_ceiling_stores_nothing() {
    let server = common::start_with_storage_quota(500).await;
    let (alice, device, group) = common::account_with_group(&server, "alice").await;

    let payload = BASE64_STANDARD.encode(vec![7u8; 1000]);
    let response = device
        .signed_at(
            "POST",
            &format!("/v1/vault/{}", hex::encode(&group)),
            serde_json::json!({ "entries": [{ "seq": 1, "payload": payload }] }),
        )
        .await;

    assert_eq!(response.status(), 507);

    let (rows,): (i64,) = sqlx::query_as("SELECT count(*) FROM vault_entries WHERE account = $1")
        .bind(&alice.id)
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "a refused write left rows behind");

    let (bytes,): (i64,) = sqlx::query_as("SELECT bytes FROM account_storage WHERE account = $1")
        .bind(&alice.id)
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(bytes, 0, "a refused write charged the account anyway");
}

/// Two writes that each fit and jointly do not: one passes, one is refused, the ceiling holds.
///
/// This is the test the single-statement charge exists for. Under a read-then-write both would
/// pass, and the ceiling would be a number an attacker steps over by opening a second
/// connection.
#[tokio::test]
async fn concurrent_writes_cannot_both_cross_the_ceiling() {
    let server = common::start_with_storage_quota(1500).await;
    let (alice, device, group) = common::account_with_group(&server, "alice").await;

    let path = format!("/v1/vault/{}", hex::encode(&group));
    let body = |seq: i64| {
        serde_json::json!({
            "entries": [{ "seq": seq, "payload": BASE64_STANDARD.encode(vec![7u8; 1000]) }]
        })
    };

    let (first, second) = tokio::join!(
        device.signed_at("POST", &path, body(1)),
        device.signed_at("POST", &path, body(2)),
    );

    let statuses = [first.status().as_u16(), second.status().as_u16()];
    assert!(statuses.contains(&200), "both concurrent writes were refused: {statuses:?}");
    assert!(statuses.contains(&507), "both concurrent writes passed: {statuses:?}");

    let (bytes,): (i64,) = sqlx::query_as("SELECT bytes FROM account_storage WHERE account = $1")
        .bind(&alice.id)
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert!(bytes <= 1500, "the counter passed the ceiling: {bytes}");
}
```

Add the helper the three tests share, in `crates/server/tests/common/mod.rs`, following the group set-up `api.rs` already performs:

```rust
/// An account, one device, and a group that device is a member of.
///
/// Three tests need exactly this and nothing more; copying the set-up into each of them would
/// make a change to registration a change to every test file.
pub async fn account_with_group(
    server: &TestServer,
    who: &str,
) -> (TestAccount, Device, Vec<u8>) {
    let account = TestAccount::create(server, &unique(who)).await;
    let device = account.device(server, &unique("device")).await;
    let group = create_group(server, &device).await;
    (account, device, group)
}
```

If `create_group` does not already exist in `common`, lift the group creation out of `crates/server/tests/api.rs` into it verbatim and have `api.rs` call the shared one — do not write a second implementation.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p server --test storage`
Expected: FAIL — the counter stays at 0 and the third test sees two 200s.

- [ ] **Step 3: Charge inside the insert's transaction**

In `crates/server/src/routes.rs`, `store_vault` gains the quota in its state and a transaction around the insert:

```rust
async fn store_vault(
    State(pool): State<PgPool>,
    State(writes): State<Arc<Writes>>,
    State(quota): State<Arc<crate::storage::Quota>>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
```

and, replacing the bare `sqlx::query(…).execute(&pool)`:

```rust
    // The bytes charged are the bytes stored, which is why this is computed from the decoded
    // blobs and not from the request: base64 is a third larger, and charging for the encoding
    // would make the ceiling depend on the transport.
    let charged: i64 = blobs.iter().map(|blob| blob.len() as i64).sum();

    let mut tx = pool.begin().await?;

    // Before the insert and inside its transaction: a refusal must cost the database nothing,
    // and an insert that fails afterwards must not leave the account charged for bytes it does
    // not hold.
    if !crate::storage::charge(&mut tx, &quota, &account, charged).await? {
        return Err(ApiError::InsufficientStorage);
    }

    sqlx::query(
        "INSERT INTO vault_entries (account, group_id, seq, payload)
         SELECT $1, $2, * FROM UNNEST($3::bigint[], $4::bytea[])
         ON CONFLICT DO NOTHING",
    )
    .bind(&account)
    .bind(&group_id)
    .bind(&seqs)
    .bind(&blobs)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
```

**Corrected during execution, and the plan was wrong here.** It first said to charge before the insert and to accept that `ON CONFLICT DO NOTHING` charges a re-uploaded entry without storing it. That overcharge is not bounded by anything that credits it, so the counter drifts above the tables permanently — and `api.rs` already deposits the same entry twice in `depositing_into_the_vault_is_idempotent`, so the reconciliation test of Task 6 catches it. The order is therefore insert-then-charge, with `RETURNING octet_length(payload)` naming the rows actually written. Nothing races: both statements are in one transaction, the charge is still the single conditional `UPDATE`, and a refusal returns before the commit so the insert goes with it. The cost is that a doomed write does its insert before being refused, which is work wasted on the rare refusal in exchange for an exact counter on every acceptance.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p server --test storage`
Expected: PASS, all five tests in the file.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/routes.rs crates/server/tests/common/mod.rs crates/server/tests/storage.rs
git commit -m "feat(server): charge the vault to the account that owns it"
```

---

### Task 5: The uploader pays for the attachment

**Files:**
- Modify: `crates/server/src/routes.rs` (`upload_attachment`, around line 2388)
- Test: `crates/server/tests/storage.rs`

**Interfaces:**
- Consumes: `storage::charge`, `caller_account` (already in `routes.rs`), `attachments.account` from Task 1.

- [ ] **Step 1: Write the failing test**

```rust
/// An upload is charged to the account that signed it, and the row records who that was.
#[tokio::test]
async fn an_upload_is_charged_to_its_uploader() {
    let server = start().await;
    let (alice, device, group) = common::account_with_group(&server, "alice").await;

    let response = device
        .signed_bytes("POST", &format!("/v1/attachments/{}", hex::encode(&group)), &[3u8; 2048])
        .await;
    assert_eq!(response.status(), 200);

    let (bytes,): (i64,) = sqlx::query_as("SELECT bytes FROM account_storage WHERE account = $1")
        .bind(&alice.id)
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(bytes, 2048);

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
    let server = common::start_with_storage_quota(1024).await;
    let (_alice, device, group) = common::account_with_group(&server, "alice").await;

    let response = device
        .signed_bytes("POST", &format!("/v1/attachments/{}", hex::encode(&group)), &[3u8; 2048])
        .await;
    assert_eq!(response.status(), 507);

    let (rows,): (i64,) = sqlx::query_as("SELECT count(*) FROM attachments WHERE group_id = $1")
        .bind(&group)
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}
```

If `common::Device` has no raw-body signed helper, add one next to `signed_at`, signing the same way the existing attachment tests in `api.rs` do — and if those tests already have such a helper locally, lift it into `common` rather than writing a second one.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p server --test storage`
Expected: FAIL — counter unchanged, `account` column null.

- [ ] **Step 3: Charge and record the uploader**

```rust
async fn upload_attachment(
    State(pool): State<PgPool>,
    State(writes): State<Arc<Writes>>,
    State(quota): State<Arc<crate::storage::Quota>>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<AttachmentUploaded>> {
```

after `require_membership` and the emptiness check:

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p server --test storage && cargo test -p server --test api`
Expected: PASS — including the existing attachment tests in `api.rs`, which must not have been broken by the new column.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/routes.rs crates/server/tests/storage.rs crates/server/tests/common/mod.rs
git commit -m "feat(server): charge an attachment to the account that uploaded it"
```

---

### Task 6: Bytes that leave come back

**Files:**
- Modify: `crates/server/src/lib.rs` (`purge_once`, around line 366-420)
- Test: `crates/server/tests/storage.rs`

**Interfaces:**
- Consumes: `storage::credit`.
- Produces: `purge_once` credits every account whose attachment it deleted, and deletes a
  doomed group's attachments explicitly before the group row.

- [ ] **Step 1: Write the failing test**

```rust
/// A purge gives the bytes back to the uploader, and to nobody else.
#[tokio::test]
async fn a_purge_credits_the_uploader() {
    let server = start().await;
    let (alice, device, group) = common::account_with_group(&server, "alice").await;

    device
        .signed_bytes("POST", &format!("/v1/attachments/{}", hex::encode(&group)), &[3u8; 4096])
        .await;

    // Ages the row past the retention rule rather than waiting for it.
    sqlx::query("UPDATE attachments SET created_at = now() - interval '400 days'")
        .execute(&server.pool)
        .await
        .unwrap();

    server::purge_once(&server.pool).await.unwrap();

    let (bytes,): (i64,) = sqlx::query_as("SELECT bytes FROM account_storage WHERE account = $1")
        .bind(&alice.id)
        .fetch_one(&server.pool)
        .await
        .unwrap();

    assert_eq!(bytes, 0, "the purge deleted the bytes without giving them back");
}

/// The counter and the tables agree after writes, purges and deletions.
///
/// This is the test that catches the failure mode of a maintained counter: a deletion path that
/// forgets to credit. It reconciles rather than asserting a number, so a path added later is
/// covered by it without being named in it.
#[tokio::test]
async fn the_counter_reconciles_with_what_is_actually_stored() {
    let server = start().await;
    let (alice, device, group) = common::account_with_group(&server, "alice").await;

    let hex_group = hex::encode(&group);
    device.signed_bytes("POST", &format!("/v1/attachments/{hex_group}"), &[3u8; 4096]).await;
    device.signed_bytes("POST", &format!("/v1/attachments/{hex_group}"), &[3u8; 8192]).await;
    device
        .signed_at(
            "POST",
            &format!("/v1/vault/{hex_group}"),
            serde_json::json!({
                "entries": [{ "seq": 1, "payload": BASE64_STANDARD.encode(vec![7u8; 500]) }]
            }),
        )
        .await;

    sqlx::query("UPDATE attachments SET created_at = now() - interval '400 days' WHERE octet_length(payload) = 4096")
        .execute(&server.pool)
        .await
        .unwrap();
    server::purge_once(&server.pool).await.unwrap();

    let (counter,): (i64,) = sqlx::query_as("SELECT bytes FROM account_storage WHERE account = $1")
        .bind(&alice.id)
        .fetch_one(&server.pool)
        .await
        .unwrap();

    let (actual,): (i64,) = sqlx::query_as(
        "SELECT COALESCE((SELECT SUM(octet_length(payload)) FROM vault_entries WHERE account = $1), 0)
              + COALESCE((SELECT SUM(octet_length(payload)) FROM attachments WHERE account = $1), 0)",
    )
    .bind(&alice.id)
    .fetch_one(&server.pool)
    .await
    .unwrap();

    assert_eq!(counter, actual, "the counter drifted from what is stored");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p server --test storage`
Expected: FAIL — the counter keeps the purged bytes.

- [ ] **Step 3: Credit on every deletion path**

In `purge_once`, the attachment deletion becomes a transaction that reports what it deleted and to whom:

```rust
    let mut tx = pool.begin().await?;

    // `RETURNING` rather than `rows_affected`: the credit needs to know *whose* bytes left, and
    // the only moment that is knowable is the deletion itself. Aggregated in SQL so a group of
    // ten thousand rows does not come back over the wire to be summed in Rust.
    let credited: Vec<(Option<String>, i64, i64)> = sqlx::query_as(&format!(
        "WITH gone AS (
             DELETE FROM attachments
              WHERE created_at < now() - interval '{ATTACHMENT_RETENTION_DAYS} days'
          RETURNING account, octet_length(payload) AS bytes
         )
         SELECT account, SUM(bytes)::bigint, count(*)::bigint FROM gone GROUP BY account"
    ))
    .fetch_all(&mut *tx)
    .await?;

    // `Purged.attachments` keeps meaning **rows deleted**, unchanged: the log line it feeds is
    // read for one thing only, which is noticing that a retention rule has started biting
    // harder than expected. Turning it into a byte count would silently change what an
    // operator's dashboard has been plotting.
    let attachments: u64 = credited.iter().map(|(_, _, rows)| *rows as u64).sum();

    for (account, bytes, _) in &credited {
        // `None` is an attachment uploaded before `0019`: it was never charged to anybody, so
        // there is nobody to credit. See the migration for why those rows are not retrofitted.
        if let Some(account) = account {
            crate::storage::credit(&mut tx, account, *bytes).await?;
        }
    }

    tx.commit().await?;
```

The group deletion needs the same treatment, and it needs it *first*: a `DELETE FROM groups` cascades to `attachments`, and a cascade cannot credit. Before the existing `DELETE FROM groups`, delete the attachments of the groups about to go, through the same `WITH gone AS (…) SELECT account, SUM(bytes)` shape, restricted to the groups the existing `WHERE` clause selects. Write into the comment that the cascade would otherwise silently strand those bytes on the counter — that is the exact drift this task exists to prevent.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p server --test storage && cargo test -p server`
Expected: PASS, the whole server suite.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/lib.rs crates/server/tests/storage.rs
git commit -m "feat(server): give the bytes back when they leave"
```

---

### Task 7: The client stops pretending it archived

**Files:**
- Modify: `apps/web/src/lib/api.ts` (`storeVault`, around line 376), `apps/web/src/lib/session-vault.ts:152`, `apps/web/src/components/Vault.tsx`
- Test: `apps/web/src/lib/session-vault.test.ts` (create if absent)

**Interfaces:**
- Consumes: the 507 from Tasks 4 and 5.
- Produces: `VaultSession.full: boolean` on the class in `session-vault.ts`, set when a store is refused for want of room and cleared by a store that succeeds. The session façade the components consume re-exports it as `vaultFull`, next to `archiving` — the two names are deliberate: `full` is the vault's own state, `vaultFull` is how a screen that also knows about devices, locks and signals refers to it.

- [ ] **Step 1: Write the failing test**

```ts
import assert from "node:assert/strict";
import { test } from "node:test";

test("a full vault is remembered, not swallowed", async () => {
  const session = new VaultSession(keyForTests());
  const api = {
    storeVault: () => Promise.reject(new ApiError(507, "storage quota reached")),
  };

  await session.store(api, groupId, [message]);

  assert.equal(session.full, true);
});

test("a transient failure is not a full vault", async () => {
  const session = new VaultSession(keyForTests());
  const api = { storeVault: () => Promise.reject(new ApiError(503, "unavailable")) };

  await session.store(api, groupId, [message]);

  assert.equal(session.full, false);
});

test("a successful store clears the flag", async () => {
  const session = new VaultSession(keyForTests());
  let refuse = true;
  const api = {
    storeVault: () =>
      refuse ? Promise.reject(new ApiError(507, "full")) : Promise.resolve(undefined),
  };

  await session.store(api, groupId, [message]);
  refuse = false;
  await session.store(api, groupId, [message]);

  assert.equal(session.full, false);
});
```

Use the existing helpers of the web suite for `keyForTests`, `groupId` and `message` — `apps/web/src/lib/vault.test.ts` already builds all three, and duplicating them would make a change to `Message` a change to two files.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd apps/web && pnpm test`
Expected: FAIL — `session.full` is undefined.

- [ ] **Step 3: Keep the refusal**

In `session-vault.ts`, the swallowed error learns to tell two things apart:

```ts
  /**
   * True when the server refused an archive for want of room.
   *
   * The other failures stay swallowed — a delivered message whose backup is late is not a
   * problem, and the next send retries it. A ceiling is different in kind: retrying never
   * clears it, and a user who is not told believes their history is being archived while
   * nothing is. That belief is the failure this flag exists to prevent.
   */
  full = false;

  async store(api: VaultApi, groupId: Uint8Array, messages: Message[]): Promise<void> {
    if (!this.key || messages.length === 0) return;

    try {
      await vault.store(api, this.key, groupId, messages);
      this.full = false;
    } catch (error) {
      if (error instanceof ApiError && error.status === 507) {
        this.full = true;
        return;
      }
      console.warn("archiving deferred", error);
    }
  }
```

- [ ] **Step 4: Say it on the screen**

In `VaultSettings`, above the existing controls, when `session.vaultFull` is true:

```tsx
{session.vaultFull && (
  <p role="status">
    This account has reached its storage limit on this server. Messages from now on are
    <strong> not </strong> being archived, and nothing already archived has been deleted.
    Turning the backup off frees nothing; ask the operator of this server for more room.
  </p>
)}
```

Expose `vaultFull` on the session object the component already consumes, alongside `archiving`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd apps/web && pnpm test && pnpm run typecheck && pnpm run lint`
Expected: PASS, all three.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/lib/session-vault.ts apps/web/src/lib/session-vault.test.ts apps/web/src/components/Vault.tsx apps/web/src/lib/api.ts
git commit -m "feat(ui): stop reporting an archive that the server refused"
```

---

### Task 8: The documentation stops saying the bound is missing

**Files:**
- Modify: `crates/server/src/throttle.rs` (module header, the three passages), `docs/THREAT-MODEL.md`, `docs/SECURITY-PROPERTIES.md`, `docs/ROADMAP.md`, `README.md`, `.env.example`

- [ ] **Step 1: Rewrite the three passages in `throttle.rs`**

Its header currently says the stored-bytes quota "this server does not have" three times (module header around lines 38-55, and the note on `DEFAULT_ATTACHMENTS_PER_MINUTE` around line 135). Two of them are now false and must say what is true instead: the bound exists, it lives in `crate::storage`, it is per account rather than per device, and what remains unbounded is envelopes — pending `docs/specs/2026-08-24-posting-allowance.md`. The third, the passage about `envelopes`, stays true and must be left alone with a pointer to that spec.

- [ ] **Step 2: Add the leak to the limitations table**

In `docs/THREAT-MODEL.md`, in the known-limitations table: the server records which account uploaded which attachment into which group, where it previously only learned it for the duration of the request. Say what it buys — the heaviest write the server accepts becomes personally bounded — and that the alternative was a shared ceiling one member can exhaust for everybody.

- [ ] **Step 3: Update the vault's unbounded-store entry**

`docs/ROADMAP.md` has, under the longer-standing gaps, "The history vault is the server's unbounded store, and must stay unpurged", ending on the stored-bytes quota `throttle.rs` names. The gap is closed for the vault and for attachments, and stays open for envelopes. `README.md`'s status table and `docs/SECURITY-PROPERTIES.md` get the same treatment: a bound that exists, a bound that does not yet, and the spec that will close the second.

- [ ] **Step 4: Document the variable**

`.env.example` gains `ACCOUNT_STORAGE_BYTES=` with a one-line comment giving the default and saying that `0` disables the ceiling.

- [ ] **Step 5: Verify nothing else still claims the quota is absent**

Run: `grep -rn "stored-bytes quota\|does not have\|unbounded store" --include='*.rs' --include='*.md' crates docs README.md`
Expected: every remaining hit is about envelopes and points at the posting-allowance spec.

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/throttle.rs docs README.md .env.example
git commit -m "docs(storage): the bound exists now, and the prose says which half"
```

---

### Task 9: The whole suite, and the pull request

- [ ] **Step 1: Run everything**

```bash
docker compose up -d
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cd apps/web && pnpm test && pnpm run typecheck && pnpm run lint
```

Expected: green throughout. `cargo test -p server` requires the database; a failure there is a missing container before it is a bug.

- [ ] **Step 2: Open the pull request against `dev`**

Explain the decision rather than the diff, as `CONTRIBUTING.md` requires: why the account is the subject, what the attachment column costs and why it was accepted, why 507 is not 429, and that envelopes stay unbounded until the posting allowance ships. Say what was run, and say plainly if any of it was not.
