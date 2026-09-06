//! The format of the content carried *inside* an MLS message.
//!
//! The MLS plaintext is just a byte string: it is up to the application to say whether it holds
//! text, an attachment descriptor, or protocol traffic. A single type byte does that, and leaves
//! room for forms added later.
//!
//! Everything here is end-to-end encrypted — including a file's name, its type and its key. That
//! is deliberate: they are facts about the content, and the server has no reason to know them.
//!
//! # Decoding is allowed to fail
//!
//! These bytes were authenticated by MLS, so they really do come from a group member. That does
//! not make them well-formed: a member can send anything at all, by mistake or on purpose. Every
//! layout is length-checked, and an unknown type byte is an error rather than a guess — a caller
//! skips the one message and carries on with the conversation.

use crate::{Result, WireError};

const TYPE_TEXT: u8 = 0;
const TYPE_ATTACHMENT: u8 = 1;
const TYPE_GOSSIP: u8 = 2;
const TYPE_POSTING_KEY: u8 = 3;
const TYPE_RECEIPT: u8 = 4;
const TYPE_REACTION: u8 = 5;
const TYPE_REPLY: u8 = 6;
const TYPE_STAMPED: u8 = 7;
const TYPE_PROFILE: u8 = 8;
const TYPE_MEMBERSHIP: u8 = 10;
const TYPE_HANDLE: u8 = 11;
const TYPE_SIGNALS: u8 = 12;
const TYPE_CALL: u8 = 13;
const TYPE_EXPIRY: u8 = 14;

const RECEIPT_DELIVERED: u8 = 0;
const RECEIPT_READ: u8 = 1;

/// The wire ceiling on a display name, in bytes.
pub const PROFILE_NAME_MAX_BYTES: usize = 64;

/// The wire ceiling on a handle, in bytes — the handle format's own, `^[a-z0-9_]{3,32}$`.
pub const HANDLE_MAX_BYTES: usize = 32;

/// A twelve-byte AES-GCM nonce and a sixteen-byte tag: nothing shorter can be a sealed blob.
pub const SEALED_SIGNALS_MIN_BYTES: usize = 12 + 16;

/// A ceiling, because a decoder without one lets a hostile member decide how much memory this
/// costs.
pub const SEALED_SIGNALS_MAX_BYTES: usize = 12 + 16 + 128;

/// How far ahead of us a peer's clock may be before a declared time is treated as a pin.
pub const CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

/// What happened to a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEvent {
    /// An invitation to join.
    Invite,
    /// The call finished.
    Ended,
    /// Nobody picked up.
    Missed,
}

/// What happened to somebody's membership. The subject is the handle; the actor is the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipEvent {
    /// They were added.
    Joined,
    /// They were removed by somebody else.
    Removed,
    /// They left on their own.
    Left,
}

/// How far a message got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptState {
    /// It reached the device.
    Delivered,
    /// It was displayed.
    Read,
}

/// A signed head of the transparency log, gossiped between members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipHead {
    /// Number of entries the head covers.
    pub size: u32,
    /// Merkle root.
    pub root: [u8; 32],
}

/// Everything needed to fetch and open an attachment. Travels inside the encrypted channel.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttachmentRef {
    /// Server-side identifier of the encrypted blob.
    pub id: String,
    /// AES-256-GCM key, base64. Must never reach the server other than encrypted.
    pub key: String,
    /// Nonce, base64.
    pub iv: String,
    /// Original file name. This is content: it is not handed to the server.
    pub name: String,
    /// Type declared by the sender. A hint, never proof.
    pub mime: String,
    /// Plaintext size, so a recipient can decide before downloading.
    pub size: u64,
    /// Is the blob padded? Absent on descriptors written before padding landed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padded: Option<bool>,
}

/// One decoded message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Written text.
    Text(String),
    /// A file, described well enough to fetch and open it.
    Attachment(Box<AttachmentRef>),
    /// A transparency log head, for cross-checking between members.
    Gossip(GossipHead),
    /// The group's posting key, handed to members so they can post without naming themselves.
    PostingKey([u8; 32]),
    /// Delivery or read acknowledgement for one sequence number.
    Receipt {
        /// How far it got.
        state: ReceiptState,
        /// The envelope being acknowledged.
        seq: u64,
    },
    /// An emoji pinned to an earlier message.
    Reaction {
        /// Sequence number of the message reacted to.
        target: u64,
        /// The emoji itself.
        emoji: String,
    },
    /// A reply quoting an earlier message.
    Reply {
        /// Sequence number of the message replied to.
        target: u64,
        /// The reply text.
        text: String,
    },
    /// A self-declared display name.
    Profile {
        /// The name. Not sanitised here: this module decodes bytes and knows nothing of screens.
        name: String,
        /// When the sender says they set it. See [`clamp_declared`].
        declared_at: u64,
    },
    /// A self-declared handle claim.
    Handle {
        /// The claimed handle. Not validated against the handle format here.
        handle: String,
        /// When the sender says they took it. See [`clamp_declared`].
        declared_at: u64,
    },
    /// Somebody's membership changed.
    Membership {
        /// What happened.
        event: MembershipEvent,
        /// Who it happened to.
        handle: String,
    },
    /// A sealed settings blob, for the sender's own other devices.
    Signals(Vec<u8>),
    /// A call happened.
    Call {
        /// What happened.
        event: CallEvent,
        /// Duration; zero on an invitation and on a missed call.
        seconds: u32,
        /// Identifier of the call.
        call: String,
    },
    /// The conversation's message lifetime changed. Zero announces it was turned off.
    Expiry {
        /// The new lifetime, in seconds.
        seconds: u32,
    },
}

impl Content {
    /// Is this **protocol traffic** rather than a message?
    ///
    /// Gossip, the posting key and sealed settings travel through the same encrypted channel as
    /// messages, because that is exactly what is wanted: a channel the server carries without
    /// being able to read it. But they are not messages — displaying them drowns the conversation
    /// in empty bubbles, and archiving them fills a store with things nobody will read again.
    ///
    /// A bridge archiving a conversation must skip these, and they carry no timestamp, so they
    /// have no expiry either.
    #[must_use]
    pub const fn is_control(&self) -> bool {
        matches!(
            self,
            Self::Gossip(_)
                | Self::PostingKey(_)
                | Self::Receipt { .. }
                | Self::Signals(_)
                | Self::Profile { .. }
                | Self::Handle { .. }
        )
    }
}

/// A body, and when its sender claims to have sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamped {
    /// What was said.
    pub body: Content,
    /// Milliseconds since the epoch, **declared by the sender**.
    ///
    /// An annotation, not evidence: a group member can put anything here. Thread order stays the
    /// sequence number, which the server assigns and no member controls.
    pub sent_at: Option<u64>,
}

/// Applies the declared time, unless it is far enough ahead to be a pin.
///
/// Clamped, never rejected. A skewed clock is common and dropping the message would lose a
/// legitimate rename; a date far in the future is a pinning move, and taking the receipt time
/// defeats it without having to tell the two cases apart.
///
/// The clock is a parameter rather than a call to the system: a decoder that reads the time is a
/// decoder that cannot be tested, and this crate holds no ambient state.
#[must_use]
pub const fn clamp_declared(declared: u64, now: u64) -> u64 {
    if declared > now + CLOCK_SKEW_MS { now } else { declared }
}

// ---------------------------------------------------------------- encoding

/// Encodes any content, stamped when a time is given.
///
/// Control traffic is never stamped even if a time is passed: it is not displayed, so the eight
/// bytes would buy nothing, and a receipt that looked like a dated message would be one more
/// thing for [`Content::is_control`] to have to un-say.
pub fn encode(body: &Content, sent_at: Option<u64>) -> Result<Vec<u8>> {
    let inner = encode_body(body)?;

    match sent_at {
        Some(stamp) if !body.is_control() => {
            let mut out = Vec::with_capacity(9 + inner.len());
            out.push(TYPE_STAMPED);
            out.extend_from_slice(&stamp.to_be_bytes());
            out.extend_from_slice(&inner);
            Ok(out)
        }
        _ => Ok(inner),
    }
}

/// One entry point, so adding a type forces the case to be handled everywhere.
fn encode_body(body: &Content) -> Result<Vec<u8>> {
    let out = match body {
        Content::Text(text) => prefixed(TYPE_TEXT, text.as_bytes()),

        Content::Attachment(reference) => {
            let json = serde_json::to_vec(reference).map_err(|_| WireError::BadLength {
                format: "attachment descriptor",
                expected: 0,
                actual: 0,
            })?;
            prefixed(TYPE_ATTACHMENT, &json)
        }

        Content::Gossip(head) => {
            let mut out = Vec::with_capacity(1 + 4 + 32);
            out.push(TYPE_GOSSIP);
            out.extend_from_slice(&head.size.to_be_bytes());
            out.extend_from_slice(&head.root);
            out
        }

        Content::PostingKey(key) => prefixed(TYPE_POSTING_KEY, key),

        Content::Receipt { state, seq } => {
            let mut out = Vec::with_capacity(1 + 1 + 8);
            out.push(TYPE_RECEIPT);
            out.push(match state {
                ReceiptState::Read => RECEIPT_READ,
                ReceiptState::Delivered => RECEIPT_DELIVERED,
            });
            out.extend_from_slice(&seq.to_be_bytes());
            out
        }

        Content::Reaction { target, emoji } => targeted(TYPE_REACTION, *target, emoji),
        Content::Reply { target, text } => targeted(TYPE_REPLY, *target, text),

        Content::Profile { name, declared_at } => {
            // Checked here and not only on the way in, because this is the last place that sees
            // the bytes: a name that got past the input field by some other route would
            // otherwise go out in a shape every recipient is required to reject. Failing on our
            // own side is the one failure the sender can actually see.
            if name.len() > PROFILE_NAME_MAX_BYTES {
                return Err(WireError::BadLength {
                    format: "display name",
                    expected: PROFILE_NAME_MAX_BYTES,
                    actual: name.len(),
                });
            }
            stamped_text(TYPE_PROFILE, *declared_at, name)
        }

        Content::Handle { handle, declared_at } => {
            if handle.len() > HANDLE_MAX_BYTES {
                return Err(WireError::BadLength {
                    format: "handle",
                    expected: HANDLE_MAX_BYTES,
                    actual: handle.len(),
                });
            }
            stamped_text(TYPE_HANDLE, *declared_at, handle)
        }

        Content::Membership { event, handle } => {
            let mut out = Vec::with_capacity(2 + handle.len());
            out.push(TYPE_MEMBERSHIP);
            out.push(match event {
                MembershipEvent::Joined => 0,
                MembershipEvent::Removed => 1,
                MembershipEvent::Left => 2,
            });
            out.extend_from_slice(handle.as_bytes());
            out
        }

        Content::Signals(sealed) => {
            if sealed.len() < SEALED_SIGNALS_MIN_BYTES || sealed.len() > SEALED_SIGNALS_MAX_BYTES {
                return Err(WireError::BadLength {
                    format: "sealed settings blob",
                    expected: SEALED_SIGNALS_MIN_BYTES,
                    actual: sealed.len(),
                });
            }
            prefixed(TYPE_SIGNALS, sealed)
        }

        Content::Call { event, seconds, call } => {
            let mut out = Vec::with_capacity(6 + call.len());
            out.push(TYPE_CALL);
            out.push(match event {
                CallEvent::Invite => 0,
                CallEvent::Ended => 1,
                CallEvent::Missed => 2,
            });
            out.extend_from_slice(&seconds.to_be_bytes());
            out.extend_from_slice(call.as_bytes());
            out
        }

        Content::Expiry { seconds } => {
            let mut out = Vec::with_capacity(1 + 4);
            out.push(TYPE_EXPIRY);
            out.extend_from_slice(&seconds.to_be_bytes());
            out
        }
    };

    Ok(out)
}

fn prefixed(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// The two forms pointing at an earlier message: `u8 type ‖ u64 BE target ‖ UTF-8`.
///
/// Reaction and reply share a layout and differ only by their type byte. Writing them twice
/// would invite one of them to get a fix the other never did.
fn targeted(kind: u8, target: u64, text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + text.len());
    out.push(kind);
    out.extend_from_slice(&target.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out
}

/// `u8 type ‖ u64 BE milliseconds ‖ UTF-8` — the shape profile and handle claims share.
fn stamped_text(kind: u8, at: u64, text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + text.len());
    out.push(kind);
    out.extend_from_slice(&at.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out
}

// ---------------------------------------------------------------- decoding

/// Reads a message body, unwrapping the timestamp if there is one.
pub fn decode(bytes: &[u8]) -> Result<Stamped> {
    let (&kind, body) = bytes.split_first().ok_or(WireError::Empty("content"))?;

    if kind == TYPE_STAMPED {
        if body.len() < 8 {
            return Err(WireError::Truncated {
                format: "stamped content",
                claimed: 8,
                available: body.len(),
            });
        }
        let (stamp, inner) = body.split_at(8);
        let sent_at = u64::from_be_bytes(stamp.try_into().expect("split_at(8) yields 8 bytes"));

        // One level, never two. A wrapper around a wrapper is not something a correct sender
        // produces, and unwrapping recursively would let a hostile member nest a few thousand
        // of them and spend our stack on it.
        return Ok(Stamped { body: decode_body(inner)?, sent_at: Some(sent_at) });
    }

    Ok(Stamped { body: decode_body(bytes)?, sent_at: None })
}

fn decode_body(bytes: &[u8]) -> Result<Content> {
    let (&kind, body) = bytes.split_first().ok_or(WireError::Empty("content"))?;

    match kind {
        TYPE_TEXT => Ok(Content::Text(utf8(body, "text")?)),

        TYPE_ATTACHMENT => serde_json::from_slice(body)
            .map(|reference| Content::Attachment(Box::new(reference)))
            .map_err(|_| WireError::BadLength {
                format: "attachment descriptor",
                expected: 0,
                actual: body.len(),
            }),

        TYPE_GOSSIP => {
            let body = exact(body, 4 + 32, "log head")?;
            let (size, root) = body.split_at(4);
            Ok(Content::Gossip(GossipHead {
                size: u32::from_be_bytes(size.try_into().expect("4 bytes")),
                root: root.try_into().expect("32 bytes"),
            }))
        }

        TYPE_POSTING_KEY => Ok(Content::PostingKey(
            exact(body, 32, "posting key")?.try_into().expect("32 bytes"),
        )),

        TYPE_RECEIPT => {
            let body = exact(body, 1 + 8, "receipt")?;
            Ok(Content::Receipt {
                state: if body[0] == RECEIPT_READ {
                    ReceiptState::Read
                } else {
                    ReceiptState::Delivered
                },
                seq: u64::from_be_bytes(body[1..9].try_into().expect("8 bytes")),
            })
        }

        TYPE_REACTION | TYPE_REPLY => {
            if body.len() < 8 {
                return Err(WireError::Truncated {
                    format: "message reference",
                    claimed: 8,
                    available: body.len(),
                });
            }
            let (target, text) = body.split_at(8);
            let target = u64::from_be_bytes(target.try_into().expect("8 bytes"));
            let text = utf8(text, "targeted content")?;

            Ok(if kind == TYPE_REACTION {
                Content::Reaction { target, emoji: text }
            } else {
                Content::Reply { target, text }
            })
        }

        TYPE_PROFILE => {
            let (declared_at, name) = declared(body, "profile")?;
            if name.len() > PROFILE_NAME_MAX_BYTES {
                return Err(WireError::BadLength {
                    format: "display name",
                    expected: PROFILE_NAME_MAX_BYTES,
                    actual: name.len(),
                });
            }
            Ok(Content::Profile { name: utf8(name, "display name")?, declared_at })
        }

        TYPE_HANDLE => {
            let (declared_at, handle) = declared(body, "handle")?;
            if handle.len() > HANDLE_MAX_BYTES {
                return Err(WireError::BadLength {
                    format: "handle",
                    expected: HANDLE_MAX_BYTES,
                    actual: handle.len(),
                });
            }
            Ok(Content::Handle { handle: utf8(handle, "handle")?, declared_at })
        }

        TYPE_MEMBERSHIP => {
            let (&event, handle) = body.split_first().ok_or(WireError::Truncated {
                format: "membership event",
                claimed: 1,
                available: 0,
            })?;
            // An event byte we do not know is a newer client saying something this one cannot
            // render. Refusing it is right: the alternative is drawing a line with a blank verb.
            let event = match event {
                0 => MembershipEvent::Joined,
                1 => MembershipEvent::Removed,
                2 => MembershipEvent::Left,
                byte => return Err(WireError::UnknownType { format: "membership event", byte }),
            };
            Ok(Content::Membership { event, handle: utf8(handle, "membership handle")? })
        }

        TYPE_SIGNALS => {
            if body.len() < SEALED_SIGNALS_MIN_BYTES || body.len() > SEALED_SIGNALS_MAX_BYTES {
                return Err(WireError::BadLength {
                    format: "sealed settings blob",
                    expected: SEALED_SIGNALS_MIN_BYTES,
                    actual: body.len(),
                });
            }
            // Not opened here: this module has no key, and only the receiving end knows whether
            // the author is one of our own devices — the sole case where opening can succeed.
            Ok(Content::Signals(body.to_vec()))
        }

        TYPE_CALL => {
            if body.len() < 5 {
                return Err(WireError::Truncated {
                    format: "call event",
                    claimed: 5,
                    available: body.len(),
                });
            }
            let event = match body[0] {
                0 => CallEvent::Invite,
                1 => CallEvent::Ended,
                2 => CallEvent::Missed,
                byte => return Err(WireError::UnknownType { format: "call event", byte }),
            };
            Ok(Content::Call {
                event,
                seconds: u32::from_be_bytes(body[1..5].try_into().expect("4 bytes")),
                call: utf8(&body[5..], "call id")?,
            })
        }

        // Four bytes and nothing else. A length nobody checks is how a garbled body becomes a
        // lifetime somebody did not choose — and the delay drawn from it would be one no member
        // of the room ever agreed to.
        TYPE_EXPIRY => Ok(Content::Expiry {
            seconds: u32::from_be_bytes(
                exact(body, 4, "expiry notice")?.try_into().expect("4 bytes"),
            ),
        }),

        byte => Err(WireError::UnknownType { format: "content", byte }),
    }
}

fn exact<'a>(body: &'a [u8], expected: usize, format: &'static str) -> Result<&'a [u8]> {
    if body.len() == expected {
        Ok(body)
    } else {
        Err(WireError::BadLength { format, expected, actual: body.len() })
    }
}

fn declared<'a>(body: &'a [u8], format: &'static str) -> Result<(u64, &'a [u8])> {
    if body.len() < 8 {
        return Err(WireError::Truncated { format, claimed: 8, available: body.len() });
    }
    let (stamp, rest) = body.split_at(8);
    Ok((u64::from_be_bytes(stamp.try_into().expect("8 bytes")), rest))
}

fn utf8(body: &[u8], format: &'static str) -> Result<String> {
    String::from_utf8(body.to_vec()).map_err(|_| WireError::NotUtf8(format))
}
