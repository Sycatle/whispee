//! What an account is allowed to keep on this server, and the two operations that move it.
//!
//! # Why this is not in `throttle`
//!
//! Because it bounds a different quantity, and conflating them is the mistake that module's own
//! header warns about: its quotas bound a **rate**, per device, keyed on time. Nothing keyed on
//! time stops a disk from filling — it turns "fill it this afternoon" into "fill it over a
//! fortnight". This bounds a **total**, per account, and it is the bound that actually closes the
//! question.
//!
//! # Why the account and not the device
//!
//! `throttle` counts devices because a device is what a signature proves, and ten devices are ten
//! people's worth of typing. Storage is the opposite case: ten devices of one account share one
//! vault, and giving each of them its own ceiling would multiply the disk by the number of times
//! somebody logged in.
//!
//! # What this does not close
//!
//! N accounts times the ceiling is still N times the ceiling. What bounds N is registration, a
//! different mechanism and not this one. And envelopes are not counted here at all: a sealed post
//! carries no device id, so charging the account behind it takes anonymous tokens — see
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
    /// Disabling exists for the integration harness, which writes far more in a few seconds than
    /// any realistic ceiling admits; the test that checks the ceiling bites sets its own.
    pub fn bytes(ceiling: i64) -> Self {
        Self { ceiling }
    }

    /// Ceiling read from `ACCOUNT_STORAGE_BYTES`, or [`DEFAULT_ACCOUNT_BYTES`].
    ///
    /// An unparseable value falls back to the default rather than failing the start-up, exactly
    /// as `throttle::quota` does: refusing to boot on a typo in a tuning variable turns a harmless
    /// mistake into an outage.
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
/// A read followed by a write is a race, and under that race two concurrent uploads that each fit
/// both pass. A quota that fails under concurrency is a quota an attacker meets by opening a
/// second connection, which is not a quota. The condition rides on the `UPDATE` itself, so
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
/// Not clamped here: the table's own `CHECK (bytes >= 0)` refuses a credit larger than what was
/// charged. That is deliberate — an over-credit is a bug in a deletion path, and it should fail
/// loudly the first time rather than round itself away silently every time afterwards.
pub async fn credit(
    tx: &mut PgTransaction<'_>,
    account: &str,
    bytes: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query::<Postgres>("UPDATE account_storage SET bytes = bytes - $1 WHERE account = $2")
        .bind(bytes)
        .bind(account)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

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
