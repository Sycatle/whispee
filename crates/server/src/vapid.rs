//! VAPID: how this server proves to a push service that it is the one the browser subscribed to.
//!
//! # What this is, in one paragraph
//!
//! A browser subscribes and gets back an endpoint URL belonging to its own vendor — Google for
//! Chrome, Mozilla for Firefox. Anybody who learns that URL could push to it, so RFC 8292 has the
//! application server sign a short-lived JWT with a P-256 key and send the matching public key
//! alongside. The subscription was minted against that same public key, so the service can check
//! that the sender is the party the browser agreed to hear from. That is the whole mechanism.
//!
//! # Why there is no payload encryption in this file
//!
//! Because there is no payload. RFC 8291 — `aes128gcm`, the `p256dh` and `auth` secrets, the
//! whole content-encryption half of Web Push — exists to carry a body past a service that must
//! not read it. This server has no body to carry: the wake-up says "wake up" and nothing else,
//! which is the third of the three limits in `migrations/0011_push.sql` and the property
//! `push::the_wake_up_only_carries_addresses` freezes.
//!
//! So a subscription here is one string, the endpoint, and it fits `push::Address` unchanged. It
//! is worth noticing how much of the specification that removes, and worth not quietly adding it
//! back: a payload would need the two subscription secrets, a migration to hold them, and an
//! encryption path — to send a preview to a lock screen, which is what this project exists not to
//! do.
//!
//! # What a push service still learns
//!
//! When this deployment wakes a device, and how often. That is irreducible and is stated in
//! `crate::push`; nothing in this file improves it.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use sqlx::PgPool;

/// How long a signed token stays valid.
///
/// RFC 8292 caps this at twenty-four hours and services enforce it. Well below that on purpose:
/// the token is a bearer credential for pushing to every subscription of one service, and it
/// travels to a third party on every wake-up. Twelve hours would halve the signatures and double
/// the window a captured token is useful for, which is the wrong side of that trade for something
/// this cheap to mint.
const TOKEN_TTL_SECONDS: u64 = 3600;

/// Re-sign once a token is this close to expiring.
///
/// Without the margin, a token minted at the edge of validity is refused by a service whose clock
/// runs slightly ahead — and the failure appears as a `401` on a wake-up nobody is watching.
const REFRESH_MARGIN_SECONDS: u64 = 300;

/// The deployment's key pair.
#[derive(Clone)]
pub struct Key {
    signing: SigningKey,
}

impl Key {
    /// Loads the key, creating it on first start.
    ///
    /// `ON CONFLICT DO NOTHING` rather than a read-then-write, for the reason `log::
    /// ensure_signing_key` gives: two processes starting together would otherwise mint two keys,
    /// and a subscription is bound to the key it was created under — half of them would start
    /// being refused by the push service, with nothing in the logs to connect the two facts.
    pub async fn ensure(pool: &PgPool) -> sqlx::Result<Self> {
        let fresh = SigningKey::random(&mut rand_core::OsRng);

        sqlx::query("INSERT INTO vapid_key (id, signing_key) VALUES (TRUE, $1) ON CONFLICT DO NOTHING")
            .bind(fresh.to_bytes().as_slice())
            .execute(pool)
            .await?;

        let (stored,): (Vec<u8>,) =
            sqlx::query_as("SELECT signing_key FROM vapid_key WHERE id = TRUE")
                .fetch_one(pool)
                .await?;

        let signing = SigningKey::from_slice(&stored).expect("vapid_signing_key_is_p256 constraint");

        Ok(Self { signing })
    }

    /// The public half, as a push service expects it: uncompressed SEC1, base64url, unpadded.
    ///
    /// This is also exactly what a browser wants for `applicationServerKey`, which is why the
    /// client reads it from this server rather than carrying a build-time copy: a key baked into
    /// a bundle is a key that needs a rebuild to change, and one of those has already caught this
    /// project out.
    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.verifying_key().to_encoded_point(false).as_bytes())
    }

    /// Signs a token for one push service.
    ///
    /// The audience is the service's origin and not the endpoint: RFC 8292 says so, and it is what
    /// makes one signature serve every subscription of one vendor instead of one per device.
    pub fn token(&self, audience: &str, subject: &str) -> String {
        let header = serde_json::json!({ "typ": "JWT", "alg": "ES256" });
        let claims = serde_json::json!({
            "aud": audience,
            "exp": seconds_now() + TOKEN_TTL_SECONDS,
            "sub": subject,
        });

        let signing_input = format!("{}.{}", encode_part(&header), encode_part(&claims));

        // `Signature` is the fixed-width r‖s form, sixty-four bytes, which is what JWS ES256 is
        // defined over. The DER encoding the same crate can produce is what X.509 uses and what a
        // push service rejects — the two are easy to confuse and only one of them is ever right
        // here.
        let signature: Signature = self.signing.sign(signing_input.as_bytes());

        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

/// A token, and when it stops being worth reusing.
#[derive(Clone)]
pub struct Cached {
    pub token: String,
    expires_at: u64,
}

impl Cached {
    pub fn mint(key: &Key, audience: &str, subject: &str) -> Self {
        Self {
            token: key.token(audience, subject),
            expires_at: seconds_now() + TOKEN_TTL_SECONDS,
        }
    }

    /// Whether this token can still be sent.
    ///
    /// Cached per service rather than per wake-up: a group of twenty devices on one vendor is one
    /// signature, not twenty. An ECDSA signature is cheap, but doing it per address turns a
    /// constant cost into one that grows with the size of the room.
    pub fn usable(&self) -> bool {
        self.expires_at > seconds_now() + REFRESH_MARGIN_SECONDS
    }
}

/// The scheme and authority of an endpoint — the `aud` a token is signed for.
///
/// Returns `None` for anything that is not an absolute http(s) URL. That is a refusal rather than
/// a fallback: the audience ends up inside a signed credential, and guessing it wrong produces a
/// token that authenticates this deployment to a service it did not mean to talk to.
pub fn audience_of(endpoint: &str) -> Option<String> {
    let (scheme, rest) = endpoint.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }

    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }

    Some(format!("{scheme}://{authority}"))
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
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    fn key() -> Key {
        Key { signing: SigningKey::random(&mut rand_core::OsRng) }
    }

    /// A push service verifies the token the way this test does, and it is the whole contract.
    #[test]
    fn the_token_verifies_under_the_advertised_public_key() {
        let key = key();
        let token = key.token("https://fcm.googleapis.com", "mailto:ops@example.test");

        let mut parts = token.rsplitn(2, '.');
        let signature = parts.next().expect("a signature");
        let signing_input = parts.next().expect("a header and a payload");

        // The public key is taken from the advertised form rather than from the key object: what
        // the service checks against is the string in the `k=` parameter, so that is what has to
        // work. Verifying against `key.signing.verifying_key()` would pass even if `public_key`
        // encoded it wrongly.
        let advertised = URL_SAFE_NO_PAD.decode(key.public_key()).expect("base64url");
        let verifying = VerifyingKey::from_sec1_bytes(&advertised).expect("an uncompressed point");
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).expect("base64url"))
            .expect("sixty-four bytes");

        verifying.verify(signing_input.as_bytes(), &signature).expect("the service would refuse it");
    }

    /// The claims are the three RFC 8292 requires, and the expiry is inside the cap services
    /// enforce.
    #[test]
    fn the_claims_say_who_this_is_for_and_for_how_long() {
        let token = key().token("https://updates.push.services.mozilla.com", "mailto:ops@example.test");

        let payload = token.split('.').nth(1).expect("a payload");
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
                .expect("json");

        assert_eq!(claims["aud"], "https://updates.push.services.mozilla.com");
        assert_eq!(claims["sub"], "mailto:ops@example.test");

        let exp = claims["exp"].as_u64().expect("a number");
        assert!(exp > seconds_now(), "already expired when minted");
        assert!(exp <= seconds_now() + 86_400, "past the twenty-four hours RFC 8292 allows");
    }

    /// **The one that matters for cost.** The audience is the origin, so every subscription of one
    /// vendor shares a token; keying it on the endpoint would sign once per device.
    #[test]
    fn every_endpoint_of_one_service_shares_an_audience() {
        let one = audience_of("https://fcm.googleapis.com/fcm/send/abc?x=1");
        let other = audience_of("https://fcm.googleapis.com/fcm/send/zzz");

        assert_eq!(one.as_deref(), Some("https://fcm.googleapis.com"));
        assert_eq!(one, other);
    }

    /// Anything that is not an absolute http(s) URL has no audience, and gets no token.
    #[test]
    fn a_thing_that_is_not_a_url_is_refused_rather_than_guessed() {
        assert_eq!(audience_of("fcm.googleapis.com/send/abc"), None);
        assert_eq!(audience_of("javascript://evil/#"), None);
        assert_eq!(audience_of("https://"), None);
        assert_eq!(audience_of(""), None);
    }

    /// A fresh token is usable, and one about to expire is not.
    #[test]
    fn a_token_is_reused_until_it_nears_its_expiry() {
        let fresh = Cached::mint(&key(), "https://example.test", "mailto:ops@example.test");
        assert!(fresh.usable());

        let stale = Cached { token: String::new(), expires_at: seconds_now() + 1 };
        assert!(!stale.usable(), "a token this close to expiry would be refused by a fast clock");
    }
}
