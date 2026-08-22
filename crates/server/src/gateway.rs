//! Session gateway: one connection, all groups.
//!
//! # What this module replaces
//!
//! The SSE stream of `routes::stream`, which stays in place while clients migrate. Three things
//! that stream could not do, each with a real cost:
//!
//! * **subscribing to a group joined after opening.** SSE freezes its list at connection time;
//!   discovering a group forced the client to reopen everything.
//! * **catching up at open time.** The client polled every conversation with a signed request
//!   only to find out it had missed nothing. Here it announces its cursors and the server only
//!   speaks if it has something to say.
//! * **knowing the client is gone.** The SSE keep-alive goes from server to client: a vanished
//!   client stays indistinguishable from a silent one, and its presence keeps being written.
//!
//! # What does not travel through here
//!
//! No content, exactly as with the SSE stream. An `envelope` frame carries only the sequence
//! number; the client fetches the envelope by the normal HTTP path, which rechecks its
//! membership and applies pagination. Duplicating that path here would have duplicated its
//! access control, and it is the forgotten copy that becomes the hole.
//!
//! # What this module changes in the threat model
//!
//! **Authentication moves from a signature per request to a signature per session.** That is the
//! change to weigh, and it cuts both ways.
//!
//! What we gain: the challenge is issued by the server and consumed on first use, so the
//! sixty-second replay window [`crate::auth`] documents does not exist on this path.
//!
//! What we lose: an open session survives the revocation of the device that opened it, and its
//! removal from a group. A signature per request made that check on every call, for free. That
//! is why [`Session::revalidate`] exists and runs on every heartbeat — without it, revoking a
//! device would cut it off from nothing as long as it keeps its socket open.
//!
//! # What this module deliberately does not authenticate
//!
//! The `signal` frame. It is authenticated by the group MAC, as on the HTTP path: the server
//! checks that the sender holds the posting key, hence that it is a member, without learning
//! which one. Tying the signal to the session's identity — known here, as it happens — would
//! undo sealed sender for the sole convenience of not rechecking a MAC.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::sink::SinkExt;
use futures_util::stream::{SplitSink, StreamExt};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio_stream::StreamMap;
use tokio_stream::wrappers::BroadcastStream;

use crate::AppState;
use crate::error::{ApiError, ApiResult};
use crate::stream::{Hub, Notice};

/// Heartbeat pace imposed on the client, announced in `hello`.
///
/// It also sets the granularity of [`Session::revalidate`]: a revocation takes effect on open
/// sessions within at most two heartbeats. Shortening it would make the cut-off sharper at the
/// cost of one query per session per heartbeat — and that is not where the protection lies,
/// since a revoked device still holds the group's secrets.
const HEARTBEAT: Duration = Duration::from_secs(30);

/// What a device is told when its session is cut off because it was revoked.
///
/// A constant rather than two literals, because the two paths that end a revoked session — the
/// server's tick and the client's own heartbeat — have to say the same thing. They did not: one
/// of them said nothing at all, and a literal repeated in two places is how that stays true.
const REASON_REVOKED: &str = "session revoked";

/// Silence beyond which the session is closed.
///
/// Two heartbeats plus a margin: a client that loses a heartbeat on a network switch must not be
/// disconnected for it, since reconnecting would cost it a challenge, a signature and a full
/// catch-up.
const SILENCE_MAX: Duration = Duration::from_secs(80);

/// Time allowed the client to answer the challenge.
///
/// Short, and that is the point: an unauthenticated socket consumes no request and appears
/// nowhere, which makes it the cheapest way to tie up a server.
const IDENTIFY_MAX: Duration = Duration::from_secs(10);

/// Ceiling on simultaneous subscriptions for one session.
///
/// Each subscription is a `broadcast::Receiver` with its queue. Without a ceiling, an
/// authenticated client grows the server's memory by subscribing in a loop — including to groups
/// it really is a member of, hence without violating anything.
const MAX_SUBSCRIPTIONS: usize = 512;

/// Size ceiling for a frame, in both directions.
///
/// Applies before authentication: that is where it counts, since the peer has proved nothing yet.
const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Ceiling on cursors accepted in an `identify`.
///
/// **Without this bound, a single frame buys as many SQL queries as it contains entries.** The
/// membership filter is not enough: it rules out foreign groups, but nothing stops repeating a
/// thousand times a group one really belongs to. Amplification is the problem, not access.
///
/// Aligned on [`MAX_SUBSCRIPTIONS`]: a client has no reason to announce a cursor for a group it
/// cannot subscribe to.
///
/// Since the gap check, an entry buys **two** queries rather than one. The ceiling did not move
/// for it: doubling a bounded cost leaves it bounded, and halving the ceiling would penalise
/// every honest multi-group client to shave a constant off the abusive case.
const MAX_CURSORS: usize = MAX_SUBSCRIPTIONS;

/// Ceiling on envelopes announced per group during catch-up.
///
/// Aligned on the HTTP path's pagination. A client far behind receives the first ones and
/// discovers the rest by paginating: that is already what the normal poll does, and announcing
/// ten thousand sequences at once would not help it read them any faster.
const MAX_RESUME_PER_GROUP: i64 = 200;

/// Frames emitted by the client.
///
/// `deny_unknown_fields` is **not** set: a client newer than a server must be able to add a
/// field without the session being refused. An unknown field is ignored, never interpreted.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ClientFrame {
    Identify {
        device_id: String,
        /// The challenge received in `hello`, echoed back as is.
        nonce: String,
        signature: String,
        /// Last known sequence per group. Absent means "I know nothing".
        #[serde(default)]
        cursors: Vec<Cursor>,
    },
    Subscribe {
        group_id: String,
    },
    Unsubscribe {
        group_id: String,
    },
    Heartbeat,
    Signal {
        group_id: String,
        nonce: String,
        mac: String,
        payload: String,
    },
}

#[derive(Deserialize)]
struct Cursor {
    group_id: String,
    seq: i64,
}

/// Frames emitted by the server.
#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ServerFrame<'a> {
    Hello { heartbeat_ms: u64, nonce: String },
    Ready { groups: Vec<String> },
    Envelope { group_id: String, seq: i64 },
    /// The cursor announced in `identify` points below what the group still holds.
    ///
    /// Emitted during catch-up only, before that group's `envelope` frames. Without it the
    /// session would stay silent about a purged group — indistinguishable, from the client's
    /// side, from a group where nothing happened — and silence is what turns a purge into a
    /// corruption. Same field and same meaning as `oldest` on the HTTP fetch, deliberately: a
    /// client must not have to learn the gap rule twice.
    Gap { group_id: String, oldest: i64 },
    Signal { group_id: String, payload: String },
    HeartbeatAck,
    /// Deliberately coarse reason: see [`reason`].
    Error { reason: &'a str },
}

/// Translates an internal error into a reason served to the client.
///
/// The reasons are deliberately coarse, for the same reason `ApiError` refuses to distinguish
/// "unknown device" from "invalid signature": the distinction would turn the gateway into an
/// enumeration oracle. The detail goes to the server traces, not onto the wire.
fn reason(error: &ApiError) -> &'static str {
    match error {
        ApiError::BadRequest(_) => "invalid frame",
        ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound | ApiError::Gone => {
            "denied"
        }
        ApiError::Conflict(_) => "conflict",
        ApiError::TooManyRequests => "too many requests",
        ApiError::Database(err) => {
            tracing::error!(error = %err, "database error in the gateway");
            "internal error"
        }
    }
}

type Sender = SplitSink<WebSocket, Message>;

/// HTTP entry point: switches the connection over to WebSocket.
///
/// No authenticating extractor here, and that is deliberate. The browser's `WebSocket` API
/// accepts no custom header — the same limit as `EventSource`, which `routes::stream` already
/// had to give in to. Putting the signature in a URL parameter would land it in the access logs
/// of every proxy crossed; the socket is therefore opened without an identity and nothing is
/// served before the challenge.
pub async fn handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    // **Size ceiling, before any authentication.**
    //
    // Without it, tungstenite's default applies: 64 MiB per message. A peer that has proved
    // nothing yet can therefore cause 64 MiB to be allocated, as many times as it opens sockets.
    // The HTTP path has always protected itself with `RequestBodyLimitLayer` at 1 MiB; this
    // route arrived without its equivalent.
    //
    // The bound is wide compared with what the protocol carries — the largest frame is a
    // `signal`, capped at 4 KiB by `MAX_SIGNAL_BYTES`, plus its base64 encoding — and narrow
    // compared with what a machine can take.
    ws.max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            if let Err(error) = session(state, socket).await {
                tracing::debug!(%error, "gateway session ended");
            }
        })
}

/// State of an authenticated session.
struct Session {
    pool: PgPool,
    hub: Arc<Hub>,
    device_id: String,
    /// One `BroadcastStream` per listened group. `StreamMap` rather than `select_all`:
    /// subscriptions change during the life of the connection, and a `select_all` over a `Vec`
    /// freezes its contents at construction.
    subscriptions: StreamMap<Vec<u8>, BroadcastStream<Notice>>,
}

async fn session(state: AppState, socket: WebSocket) -> Result<(), axum::Error> {
    let (mut sender, mut receiver) = socket.split();

    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);

    send(
        &mut sender,
        &ServerFrame::Hello {
            heartbeat_ms: HEARTBEAT.as_millis() as u64,
            nonce: BASE64_STANDARD.encode(challenge),
        },
    )
    .await?;

    // Nothing is subscribed, nothing is read, until the challenge has been answered.
    let identified = tokio::time::timeout(IDENTIFY_MAX, async {
        while let Some(message) = receiver.next().await {
            let Ok(Message::Text(text)) = message else { continue };
            return serde_json::from_str::<ClientFrame>(&text).ok();
        }
        None
    })
    .await;

    let Ok(Some(ClientFrame::Identify { device_id, nonce, signature, cursors })) = identified
    else {
        // No reason given: at this stage the peer has proved nothing, and telling it what was
        // missing would help it probe.
        return sender.close().await;
    };

    let mut session = match authenticate(&state, &device_id, &challenge, &nonce, &signature).await {
        Ok(session) => session,
        Err(error) => {
            let _ = send(&mut sender, &ServerFrame::Error { reason: reason(&error) }).await;
            return sender.close().await;
        }
    };

    let groups = match session.membership().await {
        Ok(groups) => groups,
        Err(error) => {
            let _ = send(&mut sender, &ServerFrame::Error { reason: reason(&error) }).await;
            return sender.close().await;
        }
    };

    for group_id in &groups {
        session.subscribe(group_id.clone());
    }

    send(
        &mut sender,
        &ServerFrame::Ready { groups: groups.iter().map(hex::encode).collect() },
    )
    .await?;

    // Catch-up. It comes after `ready` so that the client already has its group list when the
    // missed sequences arrive.
    if let Err(error) = session.resume(&mut sender, &cursors, &groups).await {
        let _ = send(&mut sender, &ServerFrame::Error { reason: reason(&error) }).await;
        return sender.close().await;
    }

    session.pump(sender, receiver).await
}

/// Checks the challenge and opens the session.
async fn authenticate(
    state: &AppState,
    device_id: &str,
    challenge: &[u8],
    nonce: &str,
    signature: &str,
) -> ApiResult<Session> {
    // The echoed nonce must be **the one that was served**. Comparing it rather than blindly
    // signing what the client proposes is what prevents replaying a signature obtained on a
    // previous session.
    let echoed = BASE64_STANDARD.decode(nonce).map_err(|_| ApiError::Unauthorized)?;
    if echoed != challenge {
        return Err(ApiError::Unauthorized);
    }

    // Revoked device: refused at open time, and cut off mid-session by `revalidate`.
    let auth_key: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT auth_key FROM devices WHERE id = $1 AND revoked_at IS NULL")
            .bind(device_id)
            .fetch_optional(&state.pool)
            .await?;

    let (auth_key,) = auth_key.ok_or(ApiError::Unauthorized)?;

    let auth_key: [u8; 32] = auth_key.try_into().map_err(|_| ApiError::Unauthorized)?;
    let auth_key = VerifyingKey::from_bytes(&auth_key).map_err(|_| ApiError::Unauthorized)?;

    let signature = BASE64_STANDARD
        .decode(signature)
        .ok()
        .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
        .map(|bytes| Signature::from_bytes(&bytes))
        .ok_or(ApiError::Unauthorized)?;

    let message =
        attest::gateway_message(device_id, challenge).map_err(|_| ApiError::Unauthorized)?;

    auth_key.verify_strict(&message, &signature).map_err(|_| ApiError::Unauthorized)?;

    Ok(Session {
        pool: state.pool.clone(),
        hub: state.hub.clone(),
        device_id: device_id.to_owned(),
        subscriptions: StreamMap::new(),
    })
}

impl Session {
    /// Groups the device is currently a member of.
    ///
    /// Re-read on every heartbeat rather than memorised: it is the only way for a removal from a
    /// group to take effect on an already open session.
    async fn membership(&self) -> ApiResult<Vec<Vec<u8>>> {
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT m.group_id FROM group_members m
             JOIN devices d ON d.id = m.device_id
             WHERE m.device_id = $1 AND d.revoked_at IS NULL",
        )
        .bind(&self.device_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(group_id,)| group_id).collect())
    }

    fn subscribe(&mut self, group_id: Vec<u8>) {
        if self.subscriptions.contains_key(&group_id) || self.subscriptions.len() >= MAX_SUBSCRIPTIONS
        {
            return;
        }

        let receiver = BroadcastStream::new(self.hub.subscribe(&group_id));
        self.subscriptions.insert(group_id, receiver);
    }

    /// Announces the sequences posted since the client's cursor, and the gaps beneath it.
    ///
    /// Serves numbers only: the client will go and read by the HTTP path, which rechecks its
    /// membership. A cursor on a group the device is not a member of is **silently ignored** —
    /// answering "unknown" rather than "not a member" would make this catch-up an oracle for
    /// group existence.
    ///
    /// A cursor pointing below what the group still holds gets a [`ServerFrame::Gap`] first.
    /// Staying silent there was defensible while nothing was ever deleted; it stopped being so
    /// the day `crate::purge_once` learned to delete envelopes, because the client's reading of
    /// silence — "I have missed nothing" — became false without anything on the wire saying so.
    ///
    /// The gap is not an oracle: it is served only for a group the caller is already a member
    /// of, and it says how far that group's own history reaches, which every member may know.
    async fn resume(
        &self,
        sender: &mut Sender,
        cursors: &[Cursor],
        groups: &[Vec<u8>],
    ) -> ApiResult<()> {
        let members: HashSet<&[u8]> = groups.iter().map(Vec::as_slice).collect();

        // Excess cursors are silently ignored rather than the session refused: an honest client
        // never produces that many, and refusing would turn a security bound into an outage for
        // a case that does not arise.
        let mut seen: HashSet<&str> = HashSet::new();

        for cursor in cursors.iter().take(MAX_CURSORS) {
            // A repeated group buys only one query. This is the second half of the bound:
            // without it, `MAX_CURSORS` identical entries would all go through.
            if !seen.insert(cursor.group_id.as_str()) {
                continue;
            }

            let Ok(group_id) = hex::decode(&cursor.group_id) else { continue };
            if !members.contains(group_id.as_slice()) {
                continue;
            }

            // Announced before the sequences, not after: a client that reads frames in order must
            // learn the history is broken before it is handed numbers to go and fetch. The other
            // order would have it decrypt a run of envelopes against a ratchet it has already
            // lost, which in a release build is one error per envelope and in a debug build is
            // the OpenMLS `debug_assert!` — see CONTRIBUTING.
            let oldest = crate::routes::oldest_surviving(&self.pool, &group_id).await?;
            if cursor.seq < oldest - 1 {
                let frame =
                    ServerFrame::Gap { group_id: cursor.group_id.clone(), oldest };
                if send(sender, &frame).await.is_err() {
                    return Ok(());
                }
            }

            let rows: Vec<(i64,)> = sqlx::query_as(
                "SELECT seq FROM envelopes
                 WHERE group_id = $1 AND seq > $2
                 ORDER BY seq
                 LIMIT $3",
            )
            .bind(&group_id)
            .bind(cursor.seq)
            .bind(MAX_RESUME_PER_GROUP)
            .fetch_all(&self.pool)
            .await?;

            for (seq,) in rows {
                let frame =
                    ServerFrame::Envelope { group_id: cursor.group_id.clone(), seq };
                if send(sender, &frame).await.is_err() {
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// Realigns the subscriptions on actual membership, and says whether the session should
    /// survive.
    ///
    /// This is the counterpart of moving to per-session authentication: without it, a revoked or
    /// evicted device would keep being served as long as it holds its socket open.
    async fn revalidate(&mut self) -> ApiResult<bool> {
        let groups = self.membership().await?;

        // No group **and** device gone or revoked: the session has no purpose left. The two
        // cases are distinguished, because a perfectly valid device may legitimately belong to
        // no group — that is the state of a freshly registered device.
        let alive: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM devices WHERE id = $1 AND revoked_at IS NULL")
                .bind(&self.device_id)
                .fetch_optional(&self.pool)
                .await?;

        if alive.is_none() {
            return Ok(false);
        }

        let current: HashSet<Vec<u8>> = groups.into_iter().collect();

        let lost: Vec<Vec<u8>> = self
            .subscriptions
            .keys()
            .filter(|group_id| !current.contains(*group_id))
            .cloned()
            .collect();

        for group_id in lost {
            self.subscriptions.remove(&group_id);
        }

        Ok(true)
    }

    /// Main loop: client frames on one side, hub fanout on the other.
    async fn pump(
        mut self,
        mut sender: Sender,
        mut receiver: futures_util::stream::SplitStream<WebSocket>,
    ) -> Result<(), axum::Error> {
        let mut heartbeat = tokio::time::interval(HEARTBEAT);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut last_sign_of_life = tokio::time::Instant::now();

        loop {
            tokio::select! {
                // `biased` so the hub cannot starve the client's frames: without it, a very
                // chatty group would delay an `unsubscribe` indefinitely.
                biased;

                message = receiver.next() => {
                    let Some(message) = message else { return Ok(()) };
                    let message = message?;

                    last_sign_of_life = tokio::time::Instant::now();

                    match message {
                        Message::Text(text) => {
                            // An unreadable frame is not fatal: a newer client may emit an
                            // operation this server does not know yet.
                            let Ok(frame) = serde_json::from_str::<ClientFrame>(&text) else {
                                continue;
                            };

                            match self.handle(frame).await {
                                Reaction::Silence => {}
                                Reaction::Reply(frame) => send(&mut sender, &frame).await?,
                                Reaction::Terminate(frame) => {
                                    let _ = send(&mut sender, &frame).await;
                                    return sender.close().await;
                                }
                            }
                        }
                        Message::Close(_) => return sender.close().await,
                        // Ping and Pong are handled by the axum layer; binary frames make no
                        // sense in this protocol and are ignored rather than fatal.
                        _ => {}
                    }
                }

                Some((group_id, notice)) = self.subscriptions.next() => {
                    // A subscriber left behind loses events rather than growing the server's
                    // memory. This is not a data loss: the client catches up by polling, as
                    // `crate::stream` documents.
                    let Ok(notice) = notice else { continue };

                    let frame = match notice {
                        Notice::Envelope { seq, .. } => {
                            ServerFrame::Envelope { group_id: hex::encode(&group_id), seq }
                        }
                        Notice::Signal { payload, .. } => ServerFrame::Signal {
                            group_id: hex::encode(&group_id),
                            payload: BASE64_STANDARD.encode(&payload),
                        },
                    };

                    send(&mut sender, &frame).await?;
                }

                _ = heartbeat.tick() => {
                    if last_sign_of_life.elapsed() > SILENCE_MAX {
                        // Closed without a word, and that is the one case where silence is right:
                        // a client that has said nothing for this long is not reading, so a frame
                        // explaining itself would be written to a socket nobody is holding.
                        return sender.close().await;
                    }

                    match self.revalidate().await {
                        Ok(true) => {}
                        // The same frame the client's own heartbeat would have earned, because it
                        // is the same event.
                        //
                        // This closed without a word, and which of the two paths ends a revoked
                        // session is not something the client chooses: whichever of the tick and
                        // its own heartbeat notices first decides whether it is told anything at
                        // all. A device cut off here could not tell a revocation from a dropped
                        // network, which is the one distinction this frame exists to make.
                        //
                        // Not a race worth fearing in practice — `HEARTBEAT` is thirty seconds,
                        // so an active client almost always asks first — and that is exactly why
                        // it was worth fixing rather than leaving: the silent path is the rare
                        // one, so nobody meets it until they are the one it happens to.
                        Ok(false) => {
                            let _ = send(
                                &mut sender,
                                &ServerFrame::Error { reason: REASON_REVOKED },
                            )
                            .await;
                            return sender.close().await;
                        }
                        // A momentarily unavailable database must not disconnect everyone: we
                        // retry on the next heartbeat. The session keeps its subscriptions,
                        // which is the behaviour from before this check.
                        Err(error) => tracing::debug!(%error, "revalidation deferred"),
                    }

                    // Presence is **not** written here: see the `heartbeat` frame. This tick
                    // observes nothing about the client, it only counts the server's time.
                }
            }
        }
    }

    /// Handles a frame from the client.
    async fn handle(&mut self, frame: ClientFrame) -> Reaction {
        match frame {
            // A second open on an already open session: ignored. Accepting it would allow
            // changing identity mid-flight without the subscriptions in place being recomputed.
            ClientFrame::Identify { .. } => Reaction::Silence,

            // The client's heartbeat is what triggers revalidation, rather than the server tick
            // alone: it makes it prompt — a revoked device is cut off on the next heartbeat, not
            // on the next tick — without costing an idle session anything.
            //
            // One query per heartbeat, then, and unamortised. That is the same order of
            // magnitude as a `subscribe` or `signal` frame, which already query the database on
            // every call; a client hammering its heartbeats would limit itself by its own
            // bandwidth long before troubling the database.
            ClientFrame::Heartbeat => match self.revalidate().await {
                Ok(true) => {
                    // **Presence is written here, on heartbeat receipt, and not on the server
                    // tick.**
                    //
                    // Writing it on the tick made it lie: a phone suspended by its system leaves
                    // a socket nothing closes before `SILENCE_MAX`, and the server kept
                    // declaring awake, for all that time, someone who no longer was. Counting
                    // the client's display window on top, that meant several minutes of "online"
                    // for a device at the bottom of a pocket.
                    //
                    // A received heartbeat is the only proof that someone is still at the other
                    // end. It is the same requirement that took presence out of the request
                    // path: declare present only what is observed.
                    crate::presence::touch_detached(self.pool.clone(), self.device_id.clone());
                    Reaction::Reply(ServerFrame::HeartbeatAck)
                }
                Ok(false) => {
                    Reaction::Terminate(ServerFrame::Error { reason: REASON_REVOKED })
                }
                Err(error) => Reaction::Reply(ServerFrame::Error { reason: reason(&error) }),
            },

            ClientFrame::Subscribe { group_id } => {
                let Ok(group_id) = crate::routes::decode_group_id(&group_id) else {
                    return Reaction::Reply(ServerFrame::Error { reason: "invalid frame" });
                };

                // Rechecked in the database, every time. Trusting the list computed at open time
                // would let a device subscribe to a group it has just been removed from.
                match crate::routes::is_member(&self.pool, &group_id, &self.device_id).await {
                    Ok(true) => {
                        self.subscribe(group_id);
                        Reaction::Silence
                    }
                    Ok(false) => Reaction::Reply(ServerFrame::Error { reason: "denied" }),
                    Err(error) => {
                        Reaction::Reply(ServerFrame::Error { reason: reason(&error) })
                    }
                }
            }

            ClientFrame::Unsubscribe { group_id } => {
                if let Ok(group_id) = crate::routes::decode_group_id(&group_id) {
                    self.subscriptions.remove(&group_id);
                }
                Reaction::Silence
            }

            ClientFrame::Signal { group_id, nonce, mac, payload } => {
                let decode = |value: &str| BASE64_STANDARD.decode(value).ok();
                let (Ok(group_id), Some(nonce), Some(mac), Some(payload)) = (
                    crate::routes::decode_group_id(&group_id),
                    decode(&nonce),
                    decode(&mac),
                    decode(&payload),
                ) else {
                    return Reaction::Reply(ServerFrame::Error { reason: "invalid frame" });
                };

                // Same check as the HTTP path, by the same function: the group MAC proves
                // membership without revealing who posts. The session does know its owner's
                // identity — using it here would undo sealed sender.
                match crate::routes::verify_signal(&self.pool, &group_id, &nonce, &mac, &payload)
                    .await
                {
                    Ok(()) => {
                        self.hub.publish(Notice::Signal { group_id, payload });
                        Reaction::Silence
                    }
                    Err(error) => {
                        Reaction::Reply(ServerFrame::Error { reason: reason(&error) })
                    }
                }
            }
        }
    }
}

/// What the server does with a received frame.
///
/// The third case is what justifies the enum: a session whose device has just been revoked must
/// be **closed**, not merely warned. Returning an error and carrying on would leave the socket
/// serving the groups already subscribed.
enum Reaction {
    Silence,
    Reply(ServerFrame<'static>),
    Terminate(ServerFrame<'static>),
}

async fn send(sender: &mut Sender, frame: &ServerFrame<'_>) -> Result<(), axum::Error> {
    // `expect` rather than a propagated error: these structures have no field that can fail to
    // serialise, and a failure would signal a bug in this module, not a runtime condition.
    let text = serde_json::to_string(frame).expect("server frames are serialisable");
    sender.send(Message::Text(text.into())).await
}
