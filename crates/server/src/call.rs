//! Admission to a call: the access token, and where to reach the relay.
//!
//! # What this module gives up, before anything else
//!
//! The rest of this server routes opaque blobs and can decrypt none of them. Audio cannot work
//! that way. A media server has to read the transport in order to route one stream to five
//! listeners without holding five conversations, so it terminates the transport encryption —
//! and a participant's stream carries a stable identity for the length of a call, where a posted
//! envelope carries none at all.
//!
//! **So a call leaks more than a message does**, and the two places it leaks are here:
//!
//! * this server signs the token, so it sees that somebody is joining a call, when, and towards
//!   which group;
//! * the media server sees who is connected to the same room as whom, and for how long.
//!
//! What neither of them sees is the audio. It is encrypted frame by frame under a key derived
//! from the MLS epoch — `Conversation::call_key`, in `crypto-core` — which is never sent
//! anywhere: every member computes it locally. There is no point at which this server or the
//! media server could be asked for it, because neither is ever in possession of one.
//!
//! `docs/THREAT-MODEL.md` carries the same statement where a reader will find it. This one is
//! here for whoever changes this file.
//!
//! # Two things are deliberately withheld from the media server
//!
//! **The group id.** The room is named by a digest over the group id and the call id, so the
//! relay learns that some room exists, never which conversation it belongs to. Two calls in the
//! same conversation are two unrelated rooms as far as it can tell.
//!
//! **The device id.** The identity in the token is chosen by the caller and this server does not
//! check it — it cannot, the route being authenticated by the group MAC rather than by a
//! signature, which is what keeps a call from revealing who placed it. Clients derive that
//! identity from the call key, so members recognise each other and the relay sees an opaque
//! string that changes every call. A member could take another member's identity inside a room,
//! which is the same forgery the ephemeral channel already allows and documents: a group key
//! authenticates the group, not the member.
//!
//! # Inert without configuration
//!
//! [`Media::from_environment`] returns a configuration with nothing in it when the variables are
//! absent, and the route then answers 503. A deployment that runs no media server keeps a fully
//! working messenger, exactly as one that talks to neither Apple nor Google keeps one — see
//! [`crate::push`], which this follows deliberately.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// How long an access token stays valid.
///
/// It is admission to a room, not the length of a call: once joined, the media server keeps the
/// connection. Long enough that a slow client still gets in, short enough that a token captured
/// from a log is worthless by the time anyone reads it.
const TOKEN_TTL_SECONDS: u64 = 300;

/// How long a relay credential stays valid.
///
/// Longer than the token, because it is needed again at every network change — a phone moving
/// from Wi-Fi to cellular re-runs candidate gathering, and a credential that expired mid-call
/// would drop the audio precisely when the connection was already struggling.
const RELAY_TTL_SECONDS: u64 = 12 * 3600;

/// The identity a client may ask for, in bytes.
///
/// The server cannot verify it — see the module header — so all it can do is refuse one large
/// enough to be used as storage.
const MAX_IDENTITY_BYTES: usize = 64;

/// The call id, in bytes. Clients send a hex digest; this only stops it being used as a field.
const MAX_CALL_ID_BYTES: usize = 64;

/// Where the media lives, if anywhere.
///
/// Both halves are optional and independent: a deployment may run a media server reachable
/// without a relay, and one behind a relay it does not own.
#[derive(Clone, Default)]
pub struct Media {
    pub sfu: Option<Sfu>,
    pub relay: Option<Relay>,
}

/// The media server, and the credentials to mint tokens for it.
#[derive(Clone)]
pub struct Sfu {
    /// The address clients connect to. Handed out as-is: this server never contacts it.
    pub url: String,
    pub api_key: String,
    pub api_secret: String,
}

/// The relay that carries the media when a direct path cannot be found.
#[derive(Clone)]
pub struct Relay {
    pub urls: Vec<String>,
    /// Shared with the relay, and with nothing else. It mints credentials, it is never sent.
    pub secret: String,
}

impl Media {
    /// Reads the configuration, and is content to find none.
    ///
    /// A partial configuration is treated as no configuration for that half, and says so in the
    /// log. The alternative — starting with a key and no secret — fails at the first call, on a
    /// path nobody is watching.
    pub fn from_environment() -> Self {
        let read = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());

        let sfu = match (read("MEDIA_URL"), read("MEDIA_API_KEY"), read("MEDIA_API_SECRET")) {
            (Some(url), Some(api_key), Some(api_secret)) => Some(Sfu { url, api_key, api_secret }),
            (None, None, None) => None,
            _ => {
                tracing::warn!("media server half-configured: calls stay off");
                None
            }
        };

        let relay = match (read("RELAY_URLS"), read("RELAY_SECRET")) {
            (Some(urls), Some(secret)) => Some(Relay {
                urls: urls.split(',').map(|url| url.trim().to_owned()).collect(),
                secret,
            }),
            (None, None) => None,
            _ => {
                tracing::warn!("relay half-configured: calls will only work on a direct path");
                None
            }
        };

        Self { sfu, relay }
    }
}

/// The room a call happens in.
///
/// A digest rather than the group id: the media server has no use for the identifier this whole
/// server is organised around, and handing it over would let it group a deployment's calls into
/// conversations. The call id is in the digest too, so two calls in one conversation do not look
/// related either.
pub fn room_name(group_id: &[u8], call_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"wac-call-room-v1");
    digest.update(group_id);
    digest.update(call_id.as_bytes());
    hex::encode(digest.finalize())
}

impl Sfu {
    /// Mints an access token for one room.
    ///
    /// The permissions are the narrowest that let a call happen: join, publish, subscribe. Not
    /// data — the conversation already has an encrypted channel of its own, and a second one
    /// through the relay would be a second one to secure.
    pub fn token(&self, room: &str, identity: &str) -> String {
        let now = seconds_now();

        let header = serde_json::json!({ "alg": "HS256", "typ": "JWT" });
        let claims = serde_json::json!({
            "iss": self.api_key,
            "sub": identity,
            "nbf": now,
            "exp": now + TOKEN_TTL_SECONDS,
            "video": {
                "room": room,
                "roomJoin": true,
                "canPublish": true,
                "canSubscribe": true,
                "canPublishData": false,
            },
        });

        let signing = format!("{}.{}", encode_part(&header), encode_part(&claims));
        let mut mac = Hmac::<Sha256>::new_from_slice(self.api_secret.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(signing.as_bytes());

        format!("{signing}.{}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
}

impl Relay {
    /// Mints a short-lived relay credential.
    ///
    /// The scheme is the relay's own: the user name is the expiry, and the password is a MAC
    /// over it under the shared secret. It means no account exists anywhere — nothing to
    /// provision, nothing to revoke, and a captured credential dies on its own.
    ///
    /// **The MAC is SHA-1 because the relay only speaks SHA-1 here.** It authenticates a name
    /// that expires in hours and protects nothing at rest; the alternative is no credential at
    /// all, since the other end would reject anything else.
    pub fn credential(&self) -> (String, String) {
        let username = (seconds_now() + RELAY_TTL_SECONDS).to_string();

        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(self.secret.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(username.as_bytes());

        (username, BASE64_STANDARD.encode(mac.finalize().into_bytes()))
    }
}

/// Refuses an identity or a call id that could be used as a field rather than as a name.
pub fn acceptable(call_id: &str, identity: &str) -> bool {
    !call_id.is_empty()
        && call_id.len() <= MAX_CALL_ID_BYTES
        && !identity.is_empty()
        && identity.len() <= MAX_IDENTITY_BYTES
        && call_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && identity.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn encode_part(value: &serde_json::Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("a JSON object always serialises"))
}

fn seconds_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_room_hides_the_group_it_belongs_to() {
        let room = room_name(b"group-1", "abc");

        assert_eq!(room.len(), 64, "a SHA-256 digest, hex");
        assert!(!room.contains(&hex::encode(b"group-1")), "the group id must not survive");
    }

    /// Two calls in one conversation must not look related to the relay, or the digest would
    /// only be hiding the identifier while keeping the grouping it enables.
    #[test]
    fn two_calls_in_one_group_are_two_unrelated_rooms() {
        assert_ne!(room_name(b"group-1", "abc"), room_name(b"group-1", "def"));
    }

    #[test]
    fn a_token_carries_the_room_and_expires() {
        let sfu = Sfu {
            url: "wss://media.example".into(),
            api_key: "key".into(),
            api_secret: "secret".into(),
        };

        let token = sfu.token("room-1", "peer-1");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "header, claims, signature");

        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();

        assert_eq!(claims["video"]["room"], "room-1");
        assert_eq!(claims["sub"], "peer-1");
        assert_eq!(claims["iss"], "key");
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["nbf"].as_u64().unwrap(),
            TOKEN_TTL_SECONDS
        );
    }

    /// The data channel is refused on purpose: the conversation already has an encrypted channel,
    /// and a second one through the relay would be a second one to secure.
    #[test]
    fn a_token_grants_no_data_channel() {
        let sfu = Sfu { url: "u".into(), api_key: "k".into(), api_secret: "s".into() };
        let token = sfu.token("room-1", "peer-1");
        let claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap(),
        )
        .unwrap();

        assert_eq!(claims["video"]["canPublishData"], false);
    }

    /// A different secret has to produce a different signature, or the token would be a claim
    /// anybody could make.
    #[test]
    fn the_signature_depends_on_the_secret() {
        let one = Sfu { url: "u".into(), api_key: "k".into(), api_secret: "one".into() };
        let two = Sfu { url: "u".into(), api_key: "k".into(), api_secret: "two".into() };

        let signature = |token: String| token.split('.').nth(2).unwrap().to_owned();

        assert_ne!(signature(one.token("room", "peer")), signature(two.token("room", "peer")));
    }

    #[test]
    fn a_relay_credential_is_a_mac_over_its_own_expiry() {
        let relay = Relay { urls: vec!["turn:relay.example".into()], secret: "shared".into() };
        let (username, password) = relay.credential();

        let expiry: u64 = username.parse().expect("the user name is the expiry");
        assert!(expiry > seconds_now(), "an already expired credential opens nothing");

        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(b"shared").unwrap();
        mac.update(username.as_bytes());
        assert_eq!(password, BASE64_STANDARD.encode(mac.finalize().into_bytes()));
    }

    #[test]
    fn an_identifier_that_is_not_a_name_is_refused() {
        assert!(acceptable("9f2c41ab", "peer1"));
        assert!(!acceptable("", "peer1"));
        assert!(!acceptable("9f2c41ab", ""));
        assert!(!acceptable("../etc", "peer1"), "a path is not a call id");
        assert!(!acceptable("9f2c41ab", &"a".repeat(MAX_IDENTITY_BYTES + 1)));
    }
}
