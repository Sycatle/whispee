//! A gateway session that reopens itself, and beats its own heart.
//!
//! Two chores every long-running client would otherwise write, and get subtly wrong.
//!
//! **The heartbeat.** The server closes a session that says nothing for eighty seconds, and
//! revalidates the device on every beat — which is how a revoked device loses an open socket
//! within a couple of beats rather than keeping it until it next speaks.
//!
//! **Reconnection.** Networks drop. What matters is that the new session resumes from the
//! cursors as they are *now*, not as they were when the first session opened, or the client is
//! handed messages it has already processed. Cursors are therefore read from the
//! [`StateStore`](crate::store::StateStore) at each connection rather than held here: a client
//! that persists a cursor after processing an envelope gets correct resumption for free, and one
//! that does not gets its own Welcome replayed at it.

use crate::error::Result;
use crate::gateway::{Event, Gateway, Poll};
use crate::store::StateStore;
use crate::transport::Transport;

/// Where reconnection delay starts.
const BACKOFF_FLOOR: std::time::Duration = std::time::Duration::from_secs(1);

/// And where it stops growing. A minute is long enough not to hammer a server that is down, and
/// short enough that a client notices it came back.
const BACKOFF_CEILING: std::time::Duration = std::time::Duration::from_secs(60);

/// How often to beat, well inside the server's eighty-second silence limit.
const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// A gateway that keeps itself open.
pub struct Reconnecting<'a> {
    transport: &'a Transport,
    store: &'a dyn StateStore,
    session: Option<Gateway>,
    backoff: std::time::Duration,
    last_heartbeat: std::time::Instant,
}

impl<'a> Reconnecting<'a> {
    /// Wraps a transport and the store its cursors live in. Nothing connects until the first
    /// [`Reconnecting::next_event`].
    #[must_use]
    pub fn new(transport: &'a Transport, store: &'a dyn StateStore) -> Self {
        Self {
            transport,
            store,
            session: None,
            backoff: BACKOFF_FLOOR,
            last_heartbeat: std::time::Instant::now(),
        }
    }

    /// The next event, reconnecting and heartbeating as needed.
    ///
    /// Only returns when there is something to report, so a caller's loop is simply
    /// `while let Ok(event) = gateway.next_event().await`. Connection failures are retried with a
    /// growing delay rather than surfaced: a client that has to distinguish "the server is
    /// restarting" from "the server is gone" cannot, and neither can this.
    pub async fn next_event(&mut self) -> Result<Event> {
        loop {
            if self.session.is_none() {
                self.reconnect().await;
                continue;
            }

            let session = self.session.as_mut().expect("just ensured");
            match session.poll().await {
                Ok(Poll::Event(event)) => {
                    // A session that produced an event is a working session, so the next failure
                    // starts its backoff from the floor again rather than from whatever the last
                    // outage had grown it to.
                    self.backoff = BACKOFF_FLOOR;
                    return Ok(event);
                }
                Ok(Poll::Idle) => {
                    if self.last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
                        if session.heartbeat().await.is_err() {
                            self.session = None;
                            continue;
                        }
                        self.last_heartbeat = std::time::Instant::now();
                    }
                }
                Ok(Poll::Closed) | Err(_) => self.session = None,
            }
        }
    }

    async fn reconnect(&mut self) {
        // Read now, not at construction: an hour-old cursor set would replay everything since.
        let cursors = self.store.load_cursors().unwrap_or_default();

        match Gateway::connect(self.transport, &cursors).await {
            Ok(session) => {
                self.session = Some(session);
                self.last_heartbeat = std::time::Instant::now();
            }
            Err(_) => {
                tokio::time::sleep(self.backoff).await;
                self.backoff = (self.backoff * 2).min(BACKOFF_CEILING);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The read window has to be under the heartbeat interval, which has to be well under the
    /// server's silence limit. Getting this ordering wrong disconnects an idle client, and the
    /// symptom — a session that dies every eighty seconds while nothing is happening — points at
    /// the network rather than at these three constants.
    #[test]
    fn the_timing_constants_are_ordered() {
        const SERVER_SILENCE_LIMIT: std::time::Duration = std::time::Duration::from_secs(80);

        assert!(crate::gateway::READ_TIMEOUT < HEARTBEAT_INTERVAL);
        assert!(HEARTBEAT_INTERVAL * 2 < SERVER_SILENCE_LIMIT, "two beats must fit in the limit");
    }

    #[test]
    fn the_backoff_grows_and_stops() {
        let mut delay = BACKOFF_FLOOR;
        for _ in 0..20 {
            delay = (delay * 2).min(BACKOFF_CEILING);
        }
        assert_eq!(delay, BACKOFF_CEILING, "the delay must stop growing, not overflow");
        assert!(BACKOFF_FLOOR < BACKOFF_CEILING);
    }
}
