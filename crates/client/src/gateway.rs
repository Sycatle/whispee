//! The gateway: how a client learns something happened without polling.
//!
//! One WebSocket, one signature for the whole session rather than one per request, and frames
//! that name a group and a sequence number and **never carry content**. That is not an
//! oversight: the wake-up says only that there is something to fetch, and the fetch goes back
//! over signed HTTP. A client's event loop therefore has two halves, and conflating them is the
//! first mistake to avoid.
//!
//! The session is revalidated on every heartbeat, so a revoked device loses an open socket
//! within a couple of beats rather than keeping it until it next speaks.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::Signer as _;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::error::{ClientError, Result};
use crate::transport::Transport;

/// How long to wait for a frame before deciding the server has nothing to say **right now**.
///
/// Below the thirty-second heartbeat interval on purpose: a quiet read is what prompts the
/// heartbeat, and a client that waited longer than the server's eighty-second silence limit
/// would be disconnected while believing itself idle.
pub(crate) const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// Where a client had got to in one group's mailbox.
///
/// **Persist these.** A client that reconnects at zero is woken by its own Welcome and takes it
/// for a new message; that is the first bug anyone writing this loop will hit, and it is silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// Group id, raw bytes.
    pub group_id: Vec<u8>,
    /// The last sequence this client has processed.
    pub seq: i64,
}

/// Something the server has to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The session is established; these are the groups the server will talk about.
    Ready {
        /// Group ids, hex-encoded.
        groups: Vec<String>,
    },
    /// There is an envelope to fetch. No content: go and get it.
    Envelope {
        /// Group id, hex-encoded.
        group: String,
        /// Its sequence number.
        seq: i64,
    },
    /// Envelopes below `oldest` are gone.
    ///
    /// Surfaced rather than swallowed: the MLS state for this group cannot be advanced any more.
    Gap {
        /// Group id, hex-encoded.
        group: String,
        /// The oldest sequence still held.
        oldest: i64,
    },
    /// Ephemeral traffic — typing, presence, receipts — carried but not stored.
    Signal {
        /// Group id, hex-encoded.
        group: String,
        /// The opaque signal body, base64 as it arrived.
        payload: String,
    },
    /// A frame this version does not model. Skipped, never fatal.
    Unknown {
        /// The `op` that was not recognised.
        op: String,
    },
}

/// What one read of the socket produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    /// The server said something.
    Event(Event),
    /// Nothing arrived in the read window. The session is fine; beat the heart and read again.
    Idle,
    /// The session is over. Open a new one.
    Closed,
}

/// An authenticated gateway session.
pub struct Gateway {
    socket: Socket,
}

impl Gateway {
    /// Opens a session and identifies, resuming from the given cursors.
    ///
    /// The challenge is signed under `wac-gateway-v1`, a different domain from HTTP requests:
    /// a signature captured on the HTTP path opens no session, and that separation is the point.
    pub async fn connect(transport: &Transport, cursors: &[Cursor]) -> Result<Self> {
        let url = format!(
            "{}/v1/gateway",
            transport.base_url().replacen("http://", "ws://", 1).replacen("https://", "wss://", 1)
        );

        let (mut socket, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|error| ClientError::Gateway(format!("cannot open {url}: {error}")))?;

        let Frame::Text(hello) = read_frame(&mut socket).await? else {
            return Err(ClientError::Gateway(
                "the server closed or said nothing instead of sending a hello".to_owned(),
            ));
        };

        if hello["op"] != "hello" {
            return Err(ClientError::Gateway(format!("expected hello, got {}", hello["op"])));
        }

        let challenge = hello["nonce"]
            .as_str()
            .and_then(|nonce| B64.decode(nonce).ok())
            .ok_or_else(|| ClientError::Gateway("hello without a usable nonce".to_owned()))?;

        let message = attest::gateway_message(transport.device_id(), &challenge)
            .map_err(|_| ClientError::Attest)?;

        // A list of `{group_id, seq}`, not a map. Getting this wrong costs a session that opens
        // and then never says `ready`, with no error to explain it.
        let cursors: Vec<serde_json::Value> = cursors
            .iter()
            .map(|cursor| {
                serde_json::json!({ "group_id": hex::encode(&cursor.group_id), "seq": cursor.seq })
            })
            .collect();

        let identify = serde_json::json!({
            "op": "identify",
            "device_id": transport.device_id(),
            "nonce": B64.encode(&challenge),
            "signature": B64.encode(transport.signing_key().sign(&message).to_bytes()),
            "cursors": cursors,
        });

        socket
            .send(Message::Text(identify.to_string().into()))
            .await
            .map_err(|error| ClientError::Gateway(format!("cannot identify: {error}")))?;

        Ok(Self { socket })
    }

    /// The next thing the server has to say.
    ///
    /// Three outcomes, and conflating the last two is a bug worth naming: `Idle` means nothing
    /// arrived in the read window, which is a statement about the machine, while `Closed` means
    /// the session is over and a new one has to be opened. A client that treats a quiet moment
    /// as a disconnection reconnects in a loop; one that treats a disconnection as quiet waits
    /// forever.
    ///
    /// Ping and pong are answered by the library and never surface here.
    pub async fn poll(&mut self) -> Result<Poll> {
        let frame = match read_frame(&mut self.socket).await? {
            Frame::Text(frame) => frame,
            Frame::Idle => return Ok(Poll::Idle),
            Frame::Closed => return Ok(Poll::Closed),
        };

        let op = frame["op"].as_str().unwrap_or_default().to_owned();
        let group = || frame["group_id"].as_str().unwrap_or_default().to_owned();

        Ok(Poll::Event(match op.as_str() {
            "ready" => Event::Ready {
                groups: frame["groups"]
                    .as_array()
                    .map(|groups| {
                        groups
                            .iter()
                            .filter_map(|group| group.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
            },
            "envelope" => Event::Envelope {
                group: group(),
                seq: frame["seq"].as_i64().unwrap_or_default(),
            },
            "gap" => Event::Gap {
                group: group(),
                oldest: frame["oldest"].as_i64().unwrap_or_default(),
            },
            "signal" => Event::Signal {
                group: group(),
                payload: frame["payload"].as_str().unwrap_or_default().to_owned(),
            },
            // A newer server saying something this version does not model. Skipping one frame is
            // right; closing the session over it would turn a forward-compatible addition into
            // an outage.
            _ => Event::Unknown { op },
        }))
    }

    /// Sends a heartbeat. The server closes a session that goes silent for eighty seconds.
    pub async fn heartbeat(&mut self) -> Result<()> {
        self.socket
            .send(Message::Text(serde_json::json!({ "op": "heartbeat" }).to_string().into()))
            .await
            .map_err(|error| ClientError::Gateway(format!("cannot send heartbeat: {error}")))
    }
}

/// What came back, or what did not.
enum Frame {
    Text(serde_json::Value),
    /// The server closed the session, or the stream ended.
    Closed,
    /// Nothing arrived in the read window. A statement about the machine, not the protocol.
    Idle,
}

async fn read_frame(socket: &mut Socket) -> Result<Frame> {
    let outcome = tokio::time::timeout(READ_TIMEOUT, async {
        while let Some(message) = socket.next().await {
            match message {
                Ok(Message::Text(text)) => {
                    return serde_json::from_str(&text).map_or(Frame::Closed, Frame::Text);
                }
                Ok(Message::Close(_)) | Err(_) => return Frame::Closed,
                _ => continue,
            }
        }
        Frame::Closed
    })
    .await;

    Ok(outcome.unwrap_or(Frame::Idle))
}
