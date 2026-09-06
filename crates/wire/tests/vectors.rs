//! The shared wire vectors, run against the Rust implementation.
//!
//! `vectors.json` sits next to this file and is executed by **both** implementations — here,
//! and by `apps/web/src/lib/wire-vectors.test.ts`. That is the whole point: two encoders that
//! only round-trip against themselves agree on nothing, and the disagreement surfaces the day a
//! real client from the other side sends a real message.
//!
//! The vectors were written from the format description rather than dumped from either
//! implementation, so neither is being marked against its own homework.

use serde_json::Value;
use wire::content::{
    AttachmentRef, CallEvent, Content, GossipHead, MembershipEvent, ReceiptState,
};
use wire::{content, envelope, padding};

const VECTORS: &str = include_str!("../vectors.json");

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn array32(hex: &str) -> [u8; 32] {
    hex_to_bytes(hex).try_into().expect("32 bytes")
}

fn text(value: &Value, field: &str) -> String {
    value[field].as_str().expect("string field").to_owned()
}

fn number(value: &Value, field: &str) -> u64 {
    value[field].as_u64().expect("numeric field")
}

/// Builds a [`Content`] from the vector's description of it.
fn body_from(value: &Value) -> Content {
    match value["kind"].as_str().expect("every body names its kind") {
        "text" => Content::Text(text(value, "text")),
        "gossip" => Content::Gossip(GossipHead {
            size: number(&value["head"], "size") as u32,
            root: array32(value["head"]["root"].as_str().expect("root")),
        }),
        "posting-key" => Content::PostingKey(array32(value["key"].as_str().expect("key"))),
        "receipt" => Content::Receipt {
            state: match value["state"].as_str().expect("state") {
                "read" => ReceiptState::Read,
                other => {
                    assert_eq!(other, "delivered", "unknown receipt state");
                    ReceiptState::Delivered
                }
            },
            seq: number(value, "seq"),
        },
        "reaction" => Content::Reaction {
            target: number(value, "target"),
            emoji: text(value, "emoji"),
        },
        "reply" => Content::Reply { target: number(value, "target"), text: text(value, "text") },
        "profile" => Content::Profile { name: text(value, "name"), declared_at: number(value, "at") },
        "handle" => {
            Content::Handle { handle: text(value, "handle"), declared_at: number(value, "at") }
        }
        "membership" => Content::Membership {
            event: match value["event"].as_str().expect("event") {
                "joined" => MembershipEvent::Joined,
                "removed" => MembershipEvent::Removed,
                other => {
                    assert_eq!(other, "left", "unknown membership event");
                    MembershipEvent::Left
                }
            },
            handle: text(value, "handle"),
        },
        "signals" => Content::Signals(hex_to_bytes(value["sealed"].as_str().expect("sealed"))),
        "call" => Content::Call {
            event: match value["event"].as_str().expect("event") {
                "invite" => CallEvent::Invite,
                "ended" => CallEvent::Ended,
                other => {
                    assert_eq!(other, "missed", "unknown call event");
                    CallEvent::Missed
                }
            },
            seconds: number(value, "seconds") as u32,
            call: text(value, "call"),
        },
        "expiry" => Content::Expiry { seconds: number(value, "seconds") as u32 },
        "attachment" => {
            let reference = &value["ref"];
            Content::Attachment(Box::new(AttachmentRef {
                id: text(reference, "id"),
                key: text(reference, "key"),
                iv: text(reference, "iv"),
                name: text(reference, "name"),
                mime: text(reference, "mime"),
                size: number(reference, "size"),
                padded: reference["padded"].as_bool(),
            }))
        }
        other => panic!("the vectors describe a content kind this crate does not know: {other}"),
    }
}

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors.json is valid JSON")
}

#[test]
fn every_content_vector_encodes_to_its_bytes() {
    let vectors = vectors();
    let cases = vectors["content"].as_array().expect("content vectors");
    assert!(!cases.is_empty(), "an empty vector file would pass silently");

    for case in cases {
        let name = case["name"].as_str().expect("name");
        let body = body_from(&case["body"]);
        let sent_at = case["sentAt"].as_u64();

        let encoded = content::encode(&body, sent_at).expect("vector bodies are all encodable");
        assert_eq!(
            hex::encode(&encoded),
            case["hex"].as_str().expect("hex"),
            "encoding disagrees with the shared vector: {name}"
        );
    }
}

#[test]
fn every_content_vector_decodes_back() {
    let vectors = vectors();

    for case in vectors["content"].as_array().expect("content vectors") {
        let name = case["name"].as_str().expect("name");
        let bytes = hex_to_bytes(case["hex"].as_str().expect("hex"));
        let decoded = content::decode(&bytes).unwrap_or_else(|error| {
            panic!("shared vector {name} does not decode: {error}");
        });

        assert_eq!(decoded.body, body_from(&case["body"]), "wrong body for {name}");

        // Control traffic drops its stamp on encode, so the vector's `sentAt` is what was
        // *offered*, not what survives. What comes back must match the bytes.
        let expected_stamp =
            if decoded.body.is_control() { None } else { case["sentAt"].as_u64() };
        assert_eq!(decoded.sent_at, expected_stamp, "wrong stamp for {name}");
    }
}

#[test]
fn every_envelope_vector_matches() {
    let vectors = vectors();
    let cases = vectors["envelope"].as_array().expect("envelope vectors");
    assert!(!cases.is_empty());

    for case in cases {
        let name = case["name"].as_str().expect("name");
        let expected = case["hex"].as_str().expect("hex");

        let encoded = match case["kind"].as_str().expect("kind") {
            "mls" => envelope::encode_mls(&hex_to_bytes(case["payload"].as_str().expect("payload"))),
            "welcome" => envelope::encode_welcome(
                &hex_to_bytes(case["welcome"].as_str().expect("welcome")),
                &hex_to_bytes(case["ratchetTree"].as_str().expect("ratchetTree")),
            ),
            other => panic!("unknown envelope kind in vectors: {other}"),
        };
        assert_eq!(hex::encode(&encoded), expected, "envelope vector {name}");

        let bytes = hex_to_bytes(expected);
        let decoded = envelope::decode(&bytes).unwrap_or_else(|error| {
            panic!("envelope vector {name} does not decode: {error}");
        });
        match decoded {
            envelope::Envelope::Mls(payload) => {
                assert_eq!(hex::encode(payload), case["payload"].as_str().expect("payload"));
            }
            envelope::Envelope::Welcome { welcome, ratchet_tree } => {
                assert_eq!(hex::encode(welcome), case["welcome"].as_str().expect("welcome"));
                assert_eq!(
                    hex::encode(ratchet_tree),
                    case["ratchetTree"].as_str().expect("ratchetTree")
                );
            }
        }
    }
}

#[test]
fn every_padding_vector_matches() {
    let vectors = vectors();
    let cases = vectors["padding"].as_array().expect("padding vectors");
    assert!(!cases.is_empty());

    for case in cases {
        let length = number(case, "length") as usize;
        let body = vec![0x41u8; length];
        let padded = padding::pad(&body);

        assert_eq!(
            padded.len(),
            number(case, "paddedLength") as usize,
            "padded length for a body of {length} bytes"
        );
        assert_eq!(
            u64::from(padded[length]),
            number(case, "marker"),
            "marker position for a body of {length} bytes"
        );
        assert_eq!(padding::unpad(&padded).expect("round trip"), &body[..]);
    }
}
