//! Rate limit on the open routes.
//!
//! # What this closes
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

/// Past this many tracked addresses, stale entries are swept.
///
/// Without that cleanup, the table would grow by one entry per address seen and never shrink:
/// we would have traded a way to fill a disk for a way to fill memory, which is no progress.
const SWEEP_THRESHOLD: usize = 4096;

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
        let quota = std::env::var("THROTTLE_PER_MINUTE")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_PER_MINUTE);

        Self::per_minute(quota)
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
        let quota = std::env::var("CLAIM_QUOTA_PER_MINUTE")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_CLAIMS_PER_MINUTE);

        Self::per_minute(quota)
    }

    /// `pair` identifies the caller **and** its target.
    pub fn allows(&self, pair: &str) -> bool {
        self.0.allows(pair)
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

    /// A zero quota makes the limiter transparent — which the test harness depends on.
    #[test]
    fn a_zero_quota_never_refuses() {
        let throttle = Throttle::per_minute(0);

        for _ in 0..1000 {
            assert!(throttle.allows(&ip(1)));
        }
    }
}
