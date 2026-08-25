//! Rate limits: what one caller may do per minute.
//!
//! Three counters live here, and they count different subjects on purpose — an address for the
//! routes that have no caller yet, a caller-target pair for KeyPackage claims, a device for the
//! authenticated writes. Merging them into one would mean picking a single quota for "create an
//! account", "drain someone else's stock" and "send a message", which are three orders of
//! magnitude apart.
//!
//! # What this closes, on the open routes
//!
//! Four routes run **with no authentication at all**, because they come before an identity
//! exists: account creation, device registration, pairing post and pairing fetch. Nothing
//! bounded them.
//!
//! Account creation is the most expensive one to leave open. It writes an entry into
//! `log_entries` — the transparency log — and that write is designed never to be undone: an
//! append-only log you remove a leaf from can no longer prove its own consistency. A stranger
//! with no identity could therefore grow the one table in the schema we cannot clean up. The
//! `ON DELETE CASCADE` foreign key on `log_entries` does offer a way out — delete the accounts —
//! but it punches a hole in the log, choosing to break the proofs rather than keep the garbage.
//! Neither exit is good: the entry had to be prevented.
//!
//! # What this closes, on the authenticated writes
//!
//! Every route that appends a row on the caller's behalf — KeyPackages, vault entries,
//! attachments, envelopes — was unbounded. Authentication is not a bound: one registered device,
//! obtained through two open requests, could fill `key_packages`, `vault_entries`, `attachments`
//! and `envelopes` at whatever rate the network allowed. Revoking the device afterwards does not
//! give the disk back.
//!
//! The counting subject is the device rather than the account, because the device is what the
//! signature proves. An account with ten devices therefore gets ten times the quota, which is
//! correct — ten devices are ten people's worth of typing — and also the way a determined abuser
//! multiplies their allowance, at the cost of two open requests per device. Those two requests
//! are themselves counted by the address limit above; that is the only thing standing between
//! the two mechanisms, and it is thin.
//!
//! **What this does not do is stop a disk from filling.** Nothing keyed on time can: the quotas
//! turn "fill the disk this afternoon" into "fill the disk over a fortnight", which buys an
//! operator the chance to notice. The bound that actually closes it is a stored-bytes quota per
//! account, and it now exists — in [`crate::storage`], keyed on the account rather than on the
//! device, covering the vault and attachments. It is a different mechanism bounding a different
//! quantity, which is why it is a different module: saying a rate limit solves storage would be
//! the comfortable lie, and so would folding the two into one number.
//!
//! **And what it bounds in `envelopes` is a rate, not a total.** The table is no longer
//! unbounded — `crate::purge_once` deletes an envelope once it is both older than thirty days
//! and five hundred sequences behind the group's head — but that is not a ceiling either. It is
//! a steady state: a group settles at roughly the last thirty days of its own traffic, so growth
//! stops being proportional to all of history and becomes proportional to a month of it. A group
//! writing five hundred messages a day still holds fifteen thousand envelopes, forever, and the
//! quota is what stops that number being chosen by an attacker rather than by the conversation.
//!
//! **Envelopes are the half [`crate::storage`] does not cover**, and the reason is not an
//! oversight: a sealed post carries no device id, so the account behind it cannot be charged
//! without recording the sender of every post — which is the register sealed sender removed. The
//! answer is anonymous byte tokens, specified in
//! `docs/specs/2026-08-24-posting-allowance.md` and not implemented. Until then this rate limit
//! is what stands in front of `envelopes`, and the steady state above is what bounds it.
//!
//! The history vault, which is deliberately never purged and had inherited the role of this
//! server's unbounded store, is bounded now — by the ceiling in [`crate::storage`], not by the
//! ten writes a minute below, which never could.
//!
//! # What this does not close
//!
//! **The counter lives in memory, so per instance.** Two instances behind a load balancer offer
//! twice the quota, and a restart resets everything. Same caveat as the one already written in
//! `crate::presence` about its cache — except that here, unlike presence, there is no database
//! guard behind it to catch what slips through. A serious deployment would put this limit in
//! front of the server, in the load balancer, where it sees all the traffic.
//!
//! **An address is not an identity.** An attacker who changes it bypasses the limit; legitimate
//! users behind the same NAT share it. This is a speed bump, not a barrier, and presenting it
//! otherwise would be lying to ourselves.
//!
//! **Behind a proxy, the address seen is the proxy's.** The server reads the socket and nothing
//! else: it places no trust in `X-Forwarded-For`, which is freely forged and would turn the limit
//! into a formality. The trade-off is that a deployment behind a proxy limits the whole proxy;
//! carrying the limit is then the proxy's job.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default quota for the open routes, per address and per minute.
///
/// Generous for human use — create an account, attach a few devices, pair them — and narrow next
/// to the number of requests it takes to grow a table inconveniently.
pub const DEFAULT_PER_MINUTE: u32 = 60;

/// Default quota for KeyPackage claims, per caller-target pair and per minute.
///
/// **Two orders of magnitude below the previous one, and that is the point.** An honest caller
/// only needs one KeyPackage per targeted device; the margin covers retries after a network
/// failure. Reusing the open-route quota here would allow sixty claims a minute against a single
/// victim — an attack that still works: the limit would look set without preventing anything.
pub const DEFAULT_CLAIMS_PER_MINUTE: u32 = 5;

/// Default quota for recovery lookups, per address and per minute.
///
/// **The narrowest quota in this module, and the one carrying the most weight.** Every other
/// limit here bounds a table's growth; this one bounds guessing. A recovery lookup is a password
/// attempt, and it is the *only* bound on password attempts that exists — a failed lookup names
/// no account (see `migrations/0018_recovery_escrow.sql`), so there is nothing to lock out after
/// N tries and no per-account counter to keep.
///
/// Three a minute is generous for the human action, which is typing one password on the worst
/// day of your life and mistyping it twice.
///
/// What it does not do, stated because the number invites the opposite conclusion: it does not
/// make a weak password safe. An attacker who obtains the table skips this route entirely and
/// grinds the ciphertext offline, where the only cost is Argon2id's. This limit closes the
/// online door; the offline one is closed by the password and by nothing else.
pub const DEFAULT_RECOVERY_LOOKUPS_PER_MINUTE: u32 = 3;

/// Default quota for KeyPackage top-ups, per device and per minute.
///
/// A top-up is a background action, not an interactive one: the client replenishes when its
/// stock runs low, and one request already carries up to `MAX_KEY_PACKAGES_PER_REQUEST` — a
/// hundred packages, a hundred conversations someone can open with this device. Five requests a
/// minute is five hundred packages a minute, which no client legitimately needs and which is
/// still two orders of magnitude below what it takes to make the table a problem in an hour.
pub const DEFAULT_KEY_PACKAGES_PER_MINUTE: u32 = 5;

/// Default quota for vault writes, per device and per minute.
///
/// The vault is archival: a client uploads a batch when it decides to, not continuously, and one
/// request carries up to `MAX_VAULT_ENTRIES` — two hundred archived messages. Ten a minute lets
/// a device that has been offline for a long time push two thousand messages a minute, which
/// covers the worst honest catch-up, and no more.
pub const DEFAULT_VAULT_WRITES_PER_MINUTE: u32 = 10;

/// Default quota for vault deletions, per device and per minute.
///
/// **A counter of its own, and sharing the one above was a defect rather than a simplification.**
/// A deletion undoes deposits, so it is emitted by a device that has just been depositing: the
/// client archives on every send and on every polled batch. Counting both in one bucket meant that
/// a user who had sent ten messages in the last minute and then turned a lifetime on got a `429`
/// on the deletion — **after** the commit had already changed the room's memory for everybody. The
/// archive survived the feature that exists to remove it, and the only thing on screen was "too
/// many requests".
///
/// Thirty, above the ten deposits it undoes. That direction is the whole point: a session must
/// always be able to erase what that same session was allowed to write. It is still a bound — the
/// call is a `DELETE … RETURNING` plus a counter update in one transaction, which is real work a
/// signed device could otherwise ask for without end.
pub const DEFAULT_VAULT_DROPS_PER_MINUTE: u32 = 30;

/// A deletion is never rarer than the deposit it undoes.
///
/// Checked rather than trusted to review, because the failure it prevents is silent on this side:
/// the server answers `429` correctly, and what breaks is a client's ability to erase an archive
/// it has just been told to erase. An edit that inverts this ordering brings back exactly the
/// defect the constant above describes.
const _: () = assert!(DEFAULT_VAULT_DROPS_PER_MINUTE >= DEFAULT_VAULT_WRITES_PER_MINUTE);

/// Default quota for attachment uploads, per device and per minute.
///
/// Set from the human action, which is picking a batch of photographs and sending them at once:
/// thirty in a minute is a generous version of that and nothing a person exceeds by accident.
///
/// **This number was the uncomfortable one, and it is the ceiling behind it that fixed that.** An
/// attachment may be `MAX_ATTACHMENT_BYTES` — twenty-five mebibytes — so thirty a minute is three
/// quarters of a gibibyte a minute in the worst case. As a bound on storage that was a bad one,
/// and it existed because unbounded was worse rather than because it sufficed. What makes it
/// sufficient is [`crate::storage`]: the burst is still allowed, and it stops at the account's
/// ceiling. This limit now bounds what it is good at bounding, which is the rate.
pub const DEFAULT_ATTACHMENT_UPLOADS_PER_MINUTE: u32 = 30;

/// Default quota for envelope posts, per device and per minute.
///
/// Two a second, sustained. A person typing does not approach it, and the burst a client emits
/// when it commits a group change — one envelope per commit, not per member — stays far below.
/// The margin is deliberately wide here: refusing a message is the most visible failure this
/// server can produce, and an envelope is a kilobyte where an attachment is megabytes.
pub const DEFAULT_ENVELOPES_PER_MINUTE: u32 = 120;

/// The four write quotas are ordered by what the row costs to keep.
///
/// [`DEFAULT_VAULT_DROPS_PER_MINUTE`] is deliberately outside this ordering: it keeps no row, it
/// removes them, so "what the row costs to keep" says nothing about it. Its own bound is the one
/// asserted beside it — never below the deposits it undoes.
///
/// A message is a kilobyte, an attachment up to twenty-five mebibytes, a vault write up to two
/// hundred rows and a KeyPackage top-up up to a hundred — so the widest quota belongs to the
/// cheapest write and the narrowest to the most expensive. Every doc comment above argues from
/// that ordering; checked here so an edit that inverts it fails the build instead of quietly
/// making four paragraphs untrue.
const _: () = assert!(
    DEFAULT_ENVELOPES_PER_MINUTE > DEFAULT_ATTACHMENT_UPLOADS_PER_MINUTE
        && DEFAULT_ATTACHMENT_UPLOADS_PER_MINUTE > DEFAULT_VAULT_WRITES_PER_MINUTE
        && DEFAULT_VAULT_WRITES_PER_MINUTE > DEFAULT_KEY_PACKAGES_PER_MINUTE
);

/// The recovery quota is below every write quota, and that ordering is not aesthetic.
///
/// Those bound rows; this bounds guesses at a secret. Any edit that lets recovery lookups outrun
/// the cheapest write has stopped treating a password attempt as more expensive than a message,
/// and should fail the build rather than the review.
const _: () = assert!(DEFAULT_RECOVERY_LOOKUPS_PER_MINUTE < DEFAULT_KEY_PACKAGES_PER_MINUTE);

/// Past this many tracked addresses, stale entries are swept.
///
/// Without that cleanup, the table would grow by one entry per address seen and never shrink:
/// we would have traded a way to fill a disk for a way to fill memory, which is no progress.
const SWEEP_THRESHOLD: usize = 4096;

/// A quota from the environment, or the compiled-in default.
///
/// An unparseable value falls back to the default rather than failing the start-up. Refusing to
/// boot on a typo in an optional tuning variable would turn a harmless mistake into an outage;
/// the default is a safe number by construction.
fn quota(variable: &str, fallback: u32) -> u32 {
    std::env::var(variable).ok().and_then(|value| value.parse().ok()).unwrap_or(fallback)
}

pub struct Throttle {
    quota: u32,
    window: Duration,
    seen: Mutex<HashMap<String, Counter>>,
}

struct Counter {
    since: Instant,
    requests: u32,
}

impl Throttle {
    /// A limiter at the given quota, per minute.
    ///
    /// `0` disables the limit. The integration tests rely on that: they create dozens of accounts
    /// in a few seconds from the loopback, which no realistic quota would let through. The test
    /// that checks the limit actually bites builds its own limiter with a low quota.
    pub fn per_minute(quota: u32) -> Self {
        Self {
            quota,
            window: Duration::from_secs(60),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Quota read from `THROTTLE_PER_MINUTE`, or [`DEFAULT_PER_MINUTE`].
    pub fn from_environment() -> Self {
        Self::per_minute(quota("THROTTLE_PER_MINUTE", DEFAULT_PER_MINUTE))
    }

    /// Counts a request under a key, and says whether it may pass.
    ///
    /// The key is textual rather than an address: the subject to limit is not always the caller.
    /// KeyPackage claims are counted per caller-target pair, because what we want to bound is a
    /// caller's persistence **against one specific victim**, not their activity in general.
    ///
    /// A fixed window, not a sliding one: at the boundary, a caller can emit two quotas in a
    /// short time. That is known, and irrelevant here — the limit exists to prevent sustained
    /// pressure, not a burst.
    pub fn allows(&self, key: &str) -> bool {
        if self.quota == 0 {
            return true;
        }

        let now = Instant::now();
        let mut seen = self.seen.lock().unwrap_or_else(|error| error.into_inner());

        if seen.len() > SWEEP_THRESHOLD {
            seen.retain(|_, counter| now.duration_since(counter.since) < self.window);
        }

        let counter = seen
            .entry(key.to_owned())
            .or_insert(Counter { since: now, requests: 0 });

        if now.duration_since(counter.since) >= self.window {
            *counter = Counter { since: now, requests: 0 };
        }

        counter.requests += 1;
        counter.requests <= self.quota
    }
}

/// Limit on KeyPackage claims, per caller-target pair.
///
/// # Why a distinct type rather than a second [`Throttle`]
///
/// Because confusing the two is precisely the mistake to prevent. They count different things —
/// addresses on one side, pairs on the other — and their quotas differ by two orders of
/// magnitude. A type that cannot substitute for the other makes it impossible to wire the wrong
/// quota onto the wrong route, which would set a serious-looking limit with no effect.
pub struct Claims(Throttle);

impl Claims {
    pub fn per_minute(quota: u32) -> Self {
        Self(Throttle::per_minute(quota))
    }

    /// Quota read from `CLAIM_QUOTA_PER_MINUTE`, or [`DEFAULT_CLAIMS_PER_MINUTE`].
    pub fn from_environment() -> Self {
        Self::per_minute(quota("CLAIM_QUOTA_PER_MINUTE", DEFAULT_CLAIMS_PER_MINUTE))
    }

    /// `pair` identifies the caller **and** its target.
    pub fn allows(&self, pair: &str) -> bool {
        self.0.allows(pair)
    }
}

/// Limit on recovery lookups, per address.
///
/// # Why not simply reuse [`Throttle`], which already counts addresses
///
/// Because the open routes' quota is sixty a minute, set from what it takes to grow a table
/// inconveniently, and reusing it here would allow sixty password guesses a minute against an
/// escrow. The number would look set and would bound the wrong quantity — the same mistake
/// [`Claims`] exists to prevent, in the one place where the quantity being bounded is a secret
/// rather than a row count.
///
/// A distinct type rather than a second [`Throttle`] field, so wiring the wrong quota onto this
/// route does not compile.
pub struct Recovery(Throttle);

impl Recovery {
    pub fn per_minute(quota: u32) -> Self {
        Self(Throttle::per_minute(quota))
    }

    /// Quota read from `RECOVERY_QUOTA_PER_MINUTE`, or
    /// [`DEFAULT_RECOVERY_LOOKUPS_PER_MINUTE`].
    pub fn from_environment() -> Self {
        Self::per_minute(quota("RECOVERY_QUOTA_PER_MINUTE", DEFAULT_RECOVERY_LOOKUPS_PER_MINUTE))
    }

    pub fn allows(&self, address: &str) -> bool {
        self.0.allows(address)
    }
}


/// Which table a write lands in.
///
/// An enum rather than four methods so that adding a write route makes the compiler ask which
/// quota it belongs to. A route that quietly reuses a neighbour's counter is how a limit ends up
/// looking set while bounding the wrong thing.
#[derive(Clone, Copy, Debug)]
pub enum Written {
    KeyPackages,
    Vault,
    /// A vault deletion. Separate from [`Written::Vault`] on purpose — see
    /// [`DEFAULT_VAULT_DROPS_PER_MINUTE`] for the failure that sharing one counter produced.
    VaultDrops,
    Attachments,
    Envelopes,
}

/// Limits on the authenticated write routes, per device.
///
/// # Why four counters and not one
///
/// The same reason [`Claims`] is not a [`Throttle`]: a top-up of a hundred KeyPackages, a
/// twenty-five mebibyte attachment and a one kilobyte message are not the same event, and a
/// single quota would have to be set for the worst of them — which makes it useless for the
/// others. Each counter also keeps its own table, so a device that hits its attachment ceiling
/// can still send messages. Coupling them would let an abuser silence their own account's
/// conversations, which is not a security property anybody asked for.
pub struct Writes {
    key_packages: Throttle,
    vault: Throttle,
    vault_drops: Throttle,
    attachments: Throttle,
    envelopes: Throttle,
}

impl Writes {
    /// Every write quota at the same value.
    ///
    /// For the tests: `0` disables them all, which the harness needs — the suite publishes
    /// KeyPackages and posts envelopes in tight loops — and a low value makes each of them bite
    /// in turn.
    pub fn per_minute(quota: u32) -> Self {
        Self {
            key_packages: Throttle::per_minute(quota),
            vault: Throttle::per_minute(quota),
            vault_drops: Throttle::per_minute(quota),
            attachments: Throttle::per_minute(quota),
            envelopes: Throttle::per_minute(quota),
        }
    }

    /// Quotas from the environment, each falling back to its documented default.
    pub fn from_environment() -> Self {
        Self {
            key_packages: Throttle::per_minute(quota(
                "KEY_PACKAGE_QUOTA_PER_MINUTE",
                DEFAULT_KEY_PACKAGES_PER_MINUTE,
            )),
            vault: Throttle::per_minute(quota(
                "VAULT_QUOTA_PER_MINUTE",
                DEFAULT_VAULT_WRITES_PER_MINUTE,
            )),
            vault_drops: Throttle::per_minute(quota(
                "VAULT_DROP_QUOTA_PER_MINUTE",
                DEFAULT_VAULT_DROPS_PER_MINUTE,
            )),
            attachments: Throttle::per_minute(quota(
                "ATTACHMENT_QUOTA_PER_MINUTE",
                DEFAULT_ATTACHMENT_UPLOADS_PER_MINUTE,
            )),
            envelopes: Throttle::per_minute(quota(
                "ENVELOPE_QUOTA_PER_MINUTE",
                DEFAULT_ENVELOPES_PER_MINUTE,
            )),
        }
    }

    /// Counts one write by `device_id`, and says whether it may go through.
    ///
    /// The device, not the account: the signature proves a device and nothing more, and reading
    /// the account back would put a query on the path of every write to bound something the
    /// caller can multiply anyway by registering more devices.
    pub fn allows(&self, table: Written, device_id: &str) -> bool {
        match table {
            Written::KeyPackages => &self.key_packages,
            Written::Vault => &self.vault,
            Written::VaultDrops => &self.vault_drops,
            Written::Attachments => &self.attachments,
            Written::Envelopes => &self.envelopes,
        }
        .allows(device_id)
    }
}

/// Every limit the application enforces, in one place.
///
/// Grouped so that adding a limiter does not change the signature of `crate::app_with` again,
/// and so that a caller cannot construct an application having silently forgotten one.
pub struct Limits {
    pub throttle: Throttle,
    pub claims: Claims,
    pub recovery: Recovery,
    pub writes: Writes,
    /// Ceiling on stored bytes per account. See [`crate::storage`], which explains why a total
    /// and a rate cannot be the same mechanism.
    pub storage: crate::storage::Quota,
}

impl Limits {
    pub fn from_environment() -> Self {
        Self {
            throttle: Throttle::from_environment(),
            claims: Claims::from_environment(),
            recovery: Recovery::from_environment(),
            writes: Writes::from_environment(),
            storage: crate::storage::Quota::from_environment(),
        }
    }

    /// Every limit disabled.
    ///
    /// **For the tests only.** The suite runs dozens of accounts, top-ups and posts from the
    /// loopback within seconds, which no realistic quota lets through. Each test that checks a
    /// limit actually bites turns exactly that one back on.
    pub fn off() -> Self {
        Self {
            throttle: Throttle::per_minute(0),
            claims: Claims::per_minute(0),
            recovery: Recovery::per_minute(0),
            writes: Writes::per_minute(0),
            storage: crate::storage::Quota::bytes(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> String {
        format!("ip:127.0.0.{last}")
    }

    #[test]
    fn the_quota_lets_through_then_refuses() {
        let throttle = Throttle::per_minute(3);

        for round in 1..=3 {
            assert!(throttle.allows(&ip(1)), "request {round} should have passed");
        }

        assert!(!throttle.allows(&ip(1)), "the fourth exceeds the quota");
    }

    #[test]
    fn one_address_does_not_exhaust_the_quota_of_another() {
        let throttle = Throttle::per_minute(1);

        assert!(throttle.allows(&ip(1)));
        assert!(!throttle.allows(&ip(1)));

        assert!(throttle.allows(&ip(2)), "the counter is per address, not global");
    }


    /// Each written table keeps its own counter.
    ///
    /// Sharing one would let a device that has filled its attachment allowance be refused a
    /// message — the server silencing an account because it sent too many photographs.
    #[test]
    fn exhausting_one_write_quota_leaves_the_others_alone() {
        let writes = Writes::per_minute(1);

        assert!(writes.allows(Written::Attachments, "alice:laptop"));
        assert!(!writes.allows(Written::Attachments, "alice:laptop"));

        assert!(
            writes.allows(Written::Envelopes, "alice:laptop"),
            "a full attachment quota must not stop a message"
        );
    }

    /// **The regression that made [`Written::VaultDrops`] exist.**
    ///
    /// A deletion used to be counted in the deposit's bucket. The client archives on every send,
    /// so a user who had been talking and then turned a lifetime on got a `429` on the deletion —
    /// after the commit had already changed the room's memory for everybody. The archive outlived
    /// the feature that exists to remove it, and the screen said "too many requests".
    #[test]
    fn archiving_does_not_exhaust_the_quota_for_erasing_the_archive() {
        let writes = Writes::per_minute(1);

        assert!(writes.allows(Written::Vault, "alice:laptop"));
        assert!(!writes.allows(Written::Vault, "alice:laptop"));

        assert!(
            writes.allows(Written::VaultDrops, "alice:laptop"),
            "a device must always be able to erase what it was allowed to write"
        );
    }

    /// The write quotas count devices, not the server.
    #[test]
    fn one_device_does_not_exhaust_the_write_quota_of_another() {
        let writes = Writes::per_minute(1);

        assert!(writes.allows(Written::Envelopes, "alice:laptop"));
        assert!(!writes.allows(Written::Envelopes, "alice:laptop"));

        assert!(writes.allows(Written::Envelopes, "bob:phone"));
    }

    /// `Limits::off()` really turns everything off, including what is added later.
    #[test]
    fn the_disabled_limits_never_refuse_anything() {
        let limits = Limits::off();

        for _ in 0..1000 {
            assert!(limits.throttle.allows(&ip(1)));
            assert!(limits.claims.allows("alice:laptop:bob:phone"));
            assert!(limits.writes.allows(Written::Envelopes, "alice:laptop"));
        }
    }

    /// A zero quota makes the limiter transparent — which the test harness depends on.
    #[test]
    fn a_zero_quota_never_refuses() {
        let throttle = Throttle::per_minute(0);

        for _ in 0..1000 {
            assert!(throttle.allows(&ip(1)));
        }
    }
}
