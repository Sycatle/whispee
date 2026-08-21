//! Real-time fanout to connected clients.
//!
//! # What this module changes for privacy
//!
//! It **removes** more than it adds, which is not the same as adding nothing. Until now the
//! client polled its mailbox every 1.5 seconds, with a signed request per conversation: the
//! server thus received a detailed log of who was awake, to the second, for each group. A long
//! connection replaces that stream with a single observation point, at open time.
//!
//! The balance has narrowed since: this stream is also the heartbeat that feeds the presence
//! registry (`crate::presence`). One observation per minute per device, instead of one per
//! second per group, remains a net gain — but the claim "it only removes" is no longer accurate,
//! and leaving it as is would be a writer's convenience.
//!
//! # What does not travel through here
//!
//! No content. An `envelope` event carries only the sequence number: the client then fetches the
//! envelope by the normal path, which rechecks its membership and applies pagination.
//! Duplicating that path in the fanout would have duplicated its access control — and it is the
//! forgotten copy that becomes the hole.
//!
//! # Nothing is stored
//!
//! Ephemeral signals (typing indicator) go through this hub **and never reach the disk**. That
//! is the property justifying its existence: `envelopes` is never purged, and it cannot be
//! purged after the fact without punching a hole in the application ratchet.
//!
//! One reservation since [`Hub::attach`]: inter-instance fanout makes signals travel through
//! `pg_notify`. They are not written to a table there — the notification queue lives in shared
//! memory — but a deployment set to `log_statement = all` would see them go by in its logs. The
//! "nothing reaches the disk" property therefore now depends on a database setting, which is not
//! the same as being true by construction.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::{broadcast, mpsc};

/// Depth of the per-group queue.
///
/// A client that is too slow is left behind rather than growing the server's memory. The lost
/// event is not a data loss: the periodic poll catches it up, and that is precisely why the
/// fanout can afford to be careless.
const CAPACITY: usize = 64;

/// What a subscriber receives.
#[derive(Clone, Debug)]
pub enum Notice {
    /// An envelope has been posted. Carries **only** the sequence number.
    Envelope { group_id: Vec<u8>, seq: i64 },
    /// An ephemeral, opaque signal, relayed as is and never written.
    Signal { group_id: Vec<u8>, payload: Vec<u8> },
}

/// Postgres channel through which the instances talk to each other.
///
/// One channel for the whole server, not one per group: `LISTEN` works per channel, and
/// dynamically listening to one channel per group on each instance would cancel the benefit — we
/// would have replaced an in-memory table by as many `LISTEN`s to keep in sync.
const CHANNEL: &str = "wac_notice";

/// Ceiling for a `NOTIFY` payload, minus a margin.
///
/// Postgres refuses anything beyond 8000 bytes. The margin absorbs the JSON encoding around the
/// content; the test `a_maximal_signal_fits_in_the_notify_payload` freezes the computation,
/// without which raising `MAX_SIGNAL_BYTES` would break inter-instance fanout **for large
/// signals only**, that is, perfectly silently.
const NOTIFY_MAX: usize = 7800;

/// Depth of the outbound queue towards the other instances.
///
/// Same philosophy as `CAPACITY`: if the relay falls behind, we drop rather than grow memory. A
/// lost event is caught up by the poll.
const RELAY_CAPACITY: usize = 1024;

/// Representation of a `Notice` on the Postgres wire.
///
/// Short fields: the 8000-byte ceiling is the constraint, and a verbose field name consumes it
/// for nothing.
#[derive(Serialize, Deserialize)]
#[serde(tag = "k")]
enum Wire {
    #[serde(rename = "e")]
    Envelope { g: String, s: i64 },
    #[serde(rename = "s")]
    Signal { g: String, p: String },
}

impl Wire {
    fn from(notice: &Notice) -> Self {
        match notice {
            Notice::Envelope { group_id, seq } => {
                Self::Envelope { g: hex::encode(group_id), s: *seq }
            }
            Notice::Signal { group_id, payload } => {
                Self::Signal { g: hex::encode(group_id), p: BASE64_STANDARD.encode(payload) }
            }
        }
    }

    fn into_notice(self) -> Option<Notice> {
        match self {
            Self::Envelope { g, s } => {
                Some(Notice::Envelope { group_id: hex::decode(g).ok()?, seq: s })
            }
            Self::Signal { g, p } => Some(Notice::Signal {
                group_id: hex::decode(g).ok()?,
                payload: BASE64_STANDARD.decode(p).ok()?,
            }),
        }
    }
}

/// Table of the groups that have at least one listener.
#[derive(Default)]
pub struct Hub {
    channels: Mutex<HashMap<Vec<u8>, broadcast::Sender<Notice>>>,
    /// Outbound path to the other instances, once [`Hub::attach`] has wired it up.
    ///
    /// `None` until it is: an unattached hub broadcasts locally and nothing more, which is
    /// exactly the previous behaviour and what the unit tests need.
    relay: Mutex<Option<mpsc::Sender<Notice>>>,
}

impl Hub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Wires the hub onto Postgres: what is published here goes to the other instances, and what
    /// they publish arrives here.
    ///
    /// # Why `LISTEN/NOTIFY` rather than a dedicated bus
    ///
    /// Because the in-memory `Hub` is this server's hard ceiling — two instances mean two
    /// populations of clients that cannot see each other — and lifting it does not justify
    /// adding a service to deploy, to monitor and to account for in the threat model. The
    /// database is already there, and the fanout is already best-effort.
    ///
    /// # What the server learns, and who does not
    ///
    /// The `group_id` travels in the clear inside the payload. The server already knows it from
    /// `group_members`: nothing new leaks to it. What is new is that it will appear in the
    /// Postgres logs of a deployment set to `log_statement = all`.
    ///
    /// **Must be called from a tokio runtime**, from which it detaches two tasks.
    pub fn attach(self: &Arc<Self>, pool: PgPool) {
        let (sender, mut receiver) = mpsc::channel::<Notice>(RELAY_CAPACITY);
        *self.relay.lock().expect("poisoned hub") = Some(sender);

        // Outbound: what this instance publishes goes to the others.
        let outbound = pool.clone();
        tokio::spawn(async move {
            while let Some(notice) = receiver.recv().await {
                let payload = serde_json::to_string(&Wire::from(&notice))
                    .expect("a Notice is always serialisable");

                // Beyond the ceiling we give up on inter-instance fanout rather than let
                // Postgres refuse the query. Only signals can reach that size, and a lost signal
                // is inconsequential — an envelope carries only a sequence number and cannot
                // come close to the limit.
                if payload.len() > NOTIFY_MAX {
                    tracing::debug!(size = payload.len(), "notice too large for NOTIFY");
                    continue;
                }

                if let Err(error) = sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(CHANNEL)
                    .bind(&payload)
                    .execute(&outbound)
                    .await
                {
                    tracing::debug!(%error, "inter-instance fanout failed");
                }
            }
        });

        // Inbound: what the other instances publish arrives here.
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
                    Ok(listener) => listener,
                    Err(error) => {
                        tracing::debug!(%error, "inter-instance listening unavailable");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                };

                if let Err(error) = listener.listen(CHANNEL).await {
                    tracing::debug!(%error, "LISTEN refused");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }

                // `recv` reconnects on its own after a cut, but returns on a definitive error:
                // the outer loop then reopens a listener. Without it, an instance would survive
                // a database restart having silently stopped hearing the others.
                while let Ok(notification) = listener.recv().await {
                    let Ok(wire) = serde_json::from_str::<Wire>(notification.payload()) else {
                        continue;
                    };

                    if let Some(notice) = wire.into_notice() {
                        hub.publish_local(notice);
                    }
                }
            }
        });
    }

    /// Opens a listener on a group, creating the channel if it did not exist.
    pub fn subscribe(&self, group_id: &[u8]) -> broadcast::Receiver<Notice> {
        let mut channels = self.channels.lock().expect("poisoned hub");
        channels
            .entry(group_id.to_vec())
            .or_insert_with(|| broadcast::channel(CAPACITY).0)
            .subscribe()
    }

    /// Broadcasts to the listeners of this instance **and** of the others.
    ///
    /// This is the handlers' entry point. The relay is best-effort: if its queue is full, the
    /// event stays local. Blocking here would make an envelope post pay for the delay of a
    /// fanout that `crate::stream` already documents as negligible.
    pub fn publish(&self, notice: Notice) {
        if let Some(relay) = self.relay.lock().expect("poisoned hub").as_ref()
            && relay.try_send(notice.clone()).is_err()
        {
            tracing::debug!("inter-instance relay saturated");
        }

        self.publish_local(notice);
    }

    /// Broadcasts to the listeners of this instance only.
    ///
    /// Called by the Postgres listener. Without this separate door, an event received from
    /// another instance would be re-notified by this one, and the instances would bounce it back
    /// and forth forever.
    ///
    /// The absence of a listener is not an error: it is the common case, and it drives the
    /// cleanup. Without this removal, a long-running server would keep one channel per group
    /// ever listened to — a slow, silent leak.
    fn publish_local(&self, notice: Notice) {
        let group_id = match &notice {
            Notice::Envelope { group_id, .. } | Notice::Signal { group_id, .. } => group_id.clone(),
        };

        let mut channels = self.channels.lock().expect("poisoned hub");
        if let Some(sender) = channels.get(&group_id)
            && sender.send(notice).is_err()
        {
            channels.remove(&group_id);
        }
    }

    /// Number of groups currently listened to. Serves the tests, not the runtime.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.channels.lock().expect("poisoned hub").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_subscriber_receives_what_is_published_in_its_group() {
        let hub = Hub::new();
        let mut alice = hub.subscribe(b"group-a");

        hub.publish(Notice::Envelope { group_id: b"group-a".to_vec(), seq: 7 });

        match alice.recv().await.expect("the channel stays open") {
            Notice::Envelope { seq, .. } => assert_eq!(seq, 7),
            other => panic!("expected an envelope, received {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_subscriber_receives_nothing_from_other_groups() {
        let hub = Hub::new();
        let mut alice = hub.subscribe(b"group-a");

        hub.publish(Notice::Envelope { group_id: b"group-b".to_vec(), seq: 1 });

        // `try_recv` rather than a delay: the absence must be observed, not waited for.
        assert!(alice.try_recv().is_err(), "per-group isolation is the only barrier");
    }

    #[test]
    fn a_group_without_a_listener_is_forgotten() {
        let hub = Hub::new();
        drop(hub.subscribe(b"group-a"));
        assert_eq!(hub.tracked(), 1);

        hub.publish(Notice::Envelope { group_id: b"group-a".to_vec(), seq: 1 });

        assert_eq!(hub.tracked(), 0, "otherwise a long-running server leaks one channel per group");
    }

    /// **The test that prevents a silent fanout regression.**
    ///
    /// Postgres refuses a `NOTIFY` larger than 8000 bytes. Raising `MAX_SIGNAL_BYTES` would
    /// therefore not break the fanout — it would break it for large signals only, that is, in a
    /// way no functional test would catch.
    #[test]
    fn a_maximal_signal_fits_in_the_notify_payload() {
        // The worst case of both fields at once: a group with the longest identifier
        // `decode_group_id` accepts, and a signal at the ceiling.
        let notice = Notice::Signal {
            group_id: vec![0xab; 64],
            payload: vec![0u8; crate::routes::MAX_SIGNAL_BYTES],
        };

        let encoded = serde_json::to_string(&Wire::from(&notice)).expect("serialisable");

        assert!(
            encoded.len() <= NOTIFY_MAX,
            "a signal at the ceiling is {} bytes, beyond the {NOTIFY_MAX} that fit",
            encoded.len(),
        );
    }

    /// The wire format round-trips faithfully.
    ///
    /// An asymmetry here would make what one instance's clients see diverge from what another's
    /// see — the kind of bug that only shows up in production, where there is more than one
    /// instance.
    #[test]
    fn the_wire_format_makes_the_round_trip() {
        for original in [
            Notice::Envelope { group_id: b"group-a".to_vec(), seq: 42 },
            Notice::Signal { group_id: b"group-a".to_vec(), payload: vec![1, 2, 3] },
        ] {
            let encoded = serde_json::to_string(&Wire::from(&original)).expect("serialisable");
            let decoded: Wire = serde_json::from_str(&encoded).expect("readable back");

            match (original, decoded.into_notice().expect("convertible")) {
                (
                    Notice::Envelope { group_id: a, seq: x },
                    Notice::Envelope { group_id: b, seq: y },
                ) => {
                    assert_eq!((a, x), (b, y));
                }
                (
                    Notice::Signal { group_id: a, payload: x },
                    Notice::Signal { group_id: b, payload: y },
                ) => {
                    assert_eq!((a, x), (b, y));
                }
                (before, after) => panic!("the type changed: {before:?} became {after:?}"),
            }
        }
    }

    /// An unattached hub only does local fanout, and does not panic for lack of a relay.
    ///
    /// This is what lets the unit tests above exist without a database, and `publish` stay a
    /// synchronous function callable from any handler.
    #[tokio::test]
    async fn an_unattached_hub_still_broadcasts_locally() {
        let hub = Hub::new();
        let mut alice = hub.subscribe(b"group-a");

        hub.publish(Notice::Envelope { group_id: b"group-a".to_vec(), seq: 1 });

        assert!(alice.recv().await.is_ok());
    }
}
