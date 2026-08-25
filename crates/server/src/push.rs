//! Waking sleeping devices.
//!
//! # What this module degrades
//!
//! The rest of the server tries to know as little as possible; this module goes the other way,
//! and that has to be said before anything else: for a sleeping phone to learn that a message is
//! waiting, the server must ask Google or Apple to wake it. That third party then learns the
//! **rhythm** of the conversations of a device it can tie to an account.
//!
//! The content stays encrypted. What leaks is activity metadata, and it is irreducible: that is
//! how push works, not an implementation defect. See `migrations/0011_push.sql` for the three
//! limits that follow from it.
//!
//! # The wake-up carries nothing
//!
//! No text, no sender, no group id: "wake up", and nothing more. The app then fetches through the
//! normal path, decrypts, and composes the notification locally. Putting the message in the
//! notification would show it to the provider **and** to the lock screen — exactly what this
//! project exists to avoid.
//!
//! That explains the shape of [`Waker`]: it takes only tokens. There is nothing else to give it,
//! and the interface makes that impossible rather than merely discouraged.
//!
//! # Inert without configuration
//!
//! [`Silent`] is the default waker. A self-hosted deployment that talks to neither Apple nor
//! Google records tokens and sends nothing: the feature is missing, the app is not. That is the
//! behaviour to preserve first if anyone ever wires a real provider in here.

use std::sync::Arc;

use sqlx::PgPool;

/// Where to reach a device, and through which provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub provider: String,
    pub token: String,
}

/// Whatever knows how to wake devices.
///
/// Deliberately bounded to addresses: this trait cannot carry content because there is none to
/// carry. A signature accepting a text would invite someone, on a hurried day, to put the message
/// preview in it.
pub trait Waker: Send + Sync {
    fn wake(&self, addresses: Vec<Address>);
}

/// The default waker: it wakes nobody.
///
/// Not a stub pending something better — this is the behaviour of a deployment with no configured
/// provider, and that deployment must stay fully functional.
pub struct Silent;

impl Waker for Silent {
    fn wake(&self, addresses: Vec<Address>) {
        // Counted rather than ignored: with no trace, a deployment whose configuration went
        // missing looks exactly like one that never had any.
        if !addresses.is_empty() {
            tracing::debug!(devices = addresses.len(), "wake-up skipped: no provider");
        }
    }
}

/// What a deployment ended up with: something to wake devices, and the key to advertise.
///
/// The two travel together because they must agree. A client subscribes against the public key it
/// is given and the push service binds the subscription to it; a deployment advertising one key
/// and signing with another produces subscriptions that are refused later, on a path nobody
/// watches. Handing both out of one function makes disagreeing impossible.
pub struct Configured {
    pub waker: Arc<dyn Waker>,
    /// `None` when push is off. The route that serves it answers 503 in that case — the same
    /// distinction calls make, and for the same reason: a client reads it and hides the control
    /// instead of offering a subscription that would never be woken.
    pub public_key: Option<String>,
}

/// Reads the configuration, and is content to find none.
///
/// # What turns push on
///
/// `VAPID_SUBJECT`, and nothing else. It is the contact a push service is told to reach if this
/// deployment misbehaves — RFC 8292 wants a `mailto:` or an `https:` URL — and it doubles as the
/// switch because there is nothing else a deployment must supply: the key pair is the server's
/// own, created on first start (`migrations/0020_vapid.sql`). One variable, one meaning.
///
/// Unset, this returns [`Silent`] and no public key. That is the second of the three limits in
/// `migrations/0011_push.sql`: a deployment that talks to nobody records tokens, sends nothing,
/// and stays fully functional. `without_a_provider_nothing_is_sent` pins the behaviour.
pub async fn from_environment(pool: &PgPool) -> Configured {
    let subject = std::env::var("VAPID_SUBJECT").ok().filter(|value| !value.is_empty());

    let Some(subject) = subject else {
        return Configured { waker: Arc::new(Silent), public_key: None };
    };

    // A subject that is neither of the two forms RFC 8292 allows is refused here rather than at
    // the first wake-up: services reject the token, and the symptom would be a feature that
    // registers subscriptions and silently never delivers.
    if !subject.starts_with("mailto:") && !subject.starts_with("https://") {
        tracing::warn!("VAPID_SUBJECT must be a mailto: or https: URL; push stays off");
        return Configured { waker: Arc::new(Silent), public_key: None };
    }

    match crate::vapid::Key::ensure(pool).await {
        Ok(key) => {
            let public_key = key.public_key();
            tracing::info!(%subject, "web push enabled");
            Configured {
                waker: Arc::new(Vapid::new(pool.clone(), key, subject)),
                public_key: Some(public_key),
            }
        }
        Err(error) => {
            // Refusing to start would take a working messenger down over a feature that is
            // optional by design. Off, loudly, is the honest answer.
            tracing::warn!(?error, "cannot load the VAPID key; push stays off");
            Configured { waker: Arc::new(Silent), public_key: None }
        }
    }
}

/// How long a push service may hold a wake-up for a device that is offline.
///
/// Four hours. A wake-up is worth delivering late — somebody opening their phone at lunch should
/// learn that a message arrived at breakfast — but not indefinitely: past a point the application
/// will have polled and the notification would announce something already read. The header is
/// mandatory in RFC 8030; omitting it means the service picks, and the services do not agree.
const WAKE_TTL_SECONDS: u32 = 4 * 3600;

/// The provider name a Web Push subscription is stored under.
///
/// A string rather than an enum, because that is what the column holds and what the client sends.
/// The match in [`Vapid::wake`] is what gives it meaning, and an unknown value is skipped rather
/// than guessed at — a token whose provider this build does not know is a token for a provider
/// somebody is in the middle of adding.
pub const WEB_PUSH: &str = "webpush";

/// Wakes browsers, over Web Push.
///
/// # Why this holds a pool
///
/// Because a subscription dies without telling anybody. A browser drops it when the user clears
/// site data or the profile moves, and the only signal is the push service answering `404` or
/// `410` on the next attempt. Nothing else in this server would ever remove that row, so the
/// table would grow with every browser that ever subscribed and every wake-up would carry a
/// growing tail of requests that cannot succeed. Cleaning up needs the database, so the waker
/// holds it. [`Silent`] holds nothing and stays what it was.
///
/// # Why the trait did not change
///
/// [`Waker::wake`] is synchronous and this work is not. It could have become async — and then
/// every implementation, including the one that does nothing, would carry a boxed future for the
/// benefit of one of them. It is already called from inside a `tokio::spawn` (see
/// [`wake_detached`]), so spawning again here is a task inside a task and costs nothing anybody
/// can measure. The signature that cannot carry content stays exactly as it was, which is the
/// property worth protecting.
pub struct Vapid {
    pool: PgPool,
    key: crate::vapid::Key,
    /// The contact a push service is told to reach if this deployment misbehaves. RFC 8292 asks
    /// for a `mailto:` or an `https:` URL, and it is what turns push on: with no subject
    /// configured, `Silent` is used instead and this type is never built.
    subject: String,
    http: reqwest::Client,
    /// One signed token per push service, reused until it nears expiry.
    ///
    /// A `Mutex` over a small map rather than anything cleverer: it is held for the length of a
    /// clone, contended by at most a handful of wake-ups, and the alternative — signing per
    /// address — turns a constant cost into one that grows with the size of the room.
    tokens: std::sync::Mutex<std::collections::HashMap<String, crate::vapid::Cached>>,
}

impl Vapid {
    pub fn new(pool: PgPool, key: crate::vapid::Key, subject: String) -> Self {
        Self {
            pool,
            key,
            subject,
            // No cookie store and no redirect following. A push endpoint that answers with a
            // redirect is not one to follow carrying a bearer token: the token is signed for the
            // origin that was asked, and following would present it to another.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("a client with no TLS backend would fail here, at start-up"),
            tokens: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The token for one push service, minting a new one only when the held one is running out.
    fn token_for(&self, audience: &str) -> String {
        let mut tokens = self.tokens.lock().unwrap_or_else(|error| error.into_inner());

        if let Some(held) = tokens.get(audience)
            && held.usable()
        {
            return held.token.clone();
        }

        let fresh = crate::vapid::Cached::mint(&self.key, audience, &self.subject);
        let token = fresh.token.clone();
        tokens.insert(audience.to_owned(), fresh);
        token
    }

    /// Pushes to one endpoint, and reports whether the subscription is gone for good.
    async fn push_one(&self, endpoint: &str) -> Outcome {
        let Some(audience) = crate::vapid::audience_of(endpoint) else {
            // Not a URL this server will sign a credential for. Stored rather than sent, which
            // means it came from a client that sent something odd — dropping it is the only
            // action that ends the situation.
            tracing::warn!("a stored subscription is not an http(s) endpoint; dropping it");
            return Outcome::Gone;
        };

        let request = self
            .http
            .post(endpoint)
            .header(
                "Authorization",
                format!("vapid t={}, k={}", self.token_for(&audience), self.key.public_key()),
            )
            .header("TTL", WAKE_TTL_SECONDS.to_string())
            // **No body, and this is the line to read twice.** Everything else in Web Push — the
            // `Content-Encoding: aes128gcm`, the two subscription secrets, the whole of RFC 8291 —
            // exists to carry one past a service that must not read it. There is nothing to carry:
            // the wake-up says "wake up". `Content-Length: 0` is explicit so that a proxy inserting
            // a body would be the one lying, not this.
            .header("Content-Length", "0");

        match request.send().await {
            // 404 and 410 both mean the browser threw this subscription away. Every other status
            // is this deployment's problem or the service's, and the row stays.
            Ok(response) if response.status() == 404 || response.status() == 410 => Outcome::Gone,
            Ok(response) if response.status().is_success() => Outcome::Delivered,
            Ok(response) => {
                tracing::warn!(status = %response.status(), "push service refused a wake-up");
                Outcome::Failed
            }
            Err(error) => {
                tracing::warn!(?error, "cannot reach a push service");
                Outcome::Failed
            }
        }
    }
}

/// What one attempt settled.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Delivered,
    /// The subscription no longer exists. The row goes.
    Gone,
    /// Something else. The row stays: a service that is down comes back, and dropping a live
    /// subscription over a bad afternoon would silence a device for good.
    Failed,
}

impl Waker for Vapid {
    fn wake(&self, addresses: Vec<Address>) {
        // The pool, the key and the client are all cheap to clone or already behind an `Arc`;
        // what cannot be cloned is `self`, so the work moves into a task that owns what it needs.
        // See the type's own note on why the trait stayed synchronous.
        let waker = Vapid {
            pool: self.pool.clone(),
            key: self.key.clone(),
            subject: self.subject.clone(),
            http: self.http.clone(),
            // Deliberately not shared with the parent. The task lives for one wake-up, so at most
            // one signature per service is minted and thrown away — measurably nothing, against a
            // `Mutex` shared across tasks for the lifetime of the process.
            tokens: std::sync::Mutex::new(std::collections::HashMap::new()),
        };

        tokio::spawn(async move {
            for address in addresses {
                if address.provider != WEB_PUSH {
                    // Neither an error nor a silence: a row for a provider this build cannot speak
                    // to is what an FCM or APNs token looks like before its provider lands.
                    tracing::debug!(provider = %address.provider, "no provider for this token");
                    continue;
                }

                if waker.push_one(&address.token).await == Outcome::Gone
                    && let Err(error) = forget_token(&waker.pool, &address.token).await
                {
                    tracing::warn!(?error, "cannot drop a dead subscription");
                }
            }
        });
    }
}

/// Drops a subscription the push service says no longer exists.
///
/// By token and not by device: that is all a wake-up carries. A device that re-subscribes writes a
/// new row through [`register`] anyway, so there is nothing to preserve here.
async fn forget_token(pool: &PgPool, token: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM push_tokens WHERE token = $1")
        .bind(token)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Records or replaces a device's token.
///
/// Replacement is the rule: providers rotate their tokens without warning, and keeping the old
/// ones would only pile up dead addresses.
pub async fn register(
    pool: &PgPool,
    device_id: &str,
    provider: &str,
    token: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO push_tokens (device_id, provider, token, updated_at)
         VALUES ($1, $2, $3, now())
         ON CONFLICT (device_id) DO UPDATE
         SET provider = EXCLUDED.provider, token = EXCLUDED.token, updated_at = now()",
    )
    .bind(device_id)
    .bind(provider)
    .bind(token)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Drops a device's token. Silence becomes the normal state again.
pub async fn forget(pool: &PgPool, device_id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM push_tokens WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await
        .map(|_| ())
}

/// The addresses of a group's members, minus the one being excluded.
///
/// # Why the exclusion is optional
///
/// The sender of an **anonymous** post is unknown to the server: sealed sender took that power
/// away, and there is no question of handing it back to save one notification. That device will
/// therefore wake up for a message it just wrote — an inelegance, to be fixed on the client,
/// which does know what it sent.
pub async fn group_addresses(
    pool: &PgPool,
    group_id: &[u8],
    except: Option<&str>,
) -> sqlx::Result<Vec<Address>> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT p.provider, p.token
         FROM push_tokens p
         JOIN group_members m ON m.device_id = p.device_id
         WHERE m.group_id = $1 AND ($2::text IS NULL OR p.device_id <> $2)",
    )
    .bind(group_id)
    .bind(except)
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter().map(|(provider, token)| Address { provider, token }).collect()
    })
}

/// Wakes a group's members after a post.
///
/// Detached, like presence: a slow or broken provider must not delay the response to whoever just
/// sent their message. The message itself is already written and already announced to connected
/// clients — the wake-up only serves those who are not.
pub fn wake_detached(
    pool: PgPool,
    waker: Arc<dyn Waker>,
    group_id: Vec<u8>,
    except: Option<String>,
) {
    tokio::spawn(async move {
        match group_addresses(&pool, &group_id, except.as_deref()).await {
            Ok(addresses) if !addresses.is_empty() => waker.wake(addresses),
            Ok(_) => {}
            Err(error) => tracing::warn!(?error, "cannot wake devices"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A waker that records what it is asked for, to check what reaches it.
    #[derive(Default)]
    struct Spy(Mutex<Vec<Address>>);

    impl Waker for Spy {
        fn wake(&self, addresses: Vec<Address>) {
            self.0.lock().expect("poisoned spy").extend(addresses);
        }
    }

    /// **The test that carries the module's property.**
    ///
    /// The trait must not be able to carry content. This test does not state that through an
    /// assertion — the compiler handles it — but it freezes the usage: what crosses the boundary
    /// is a list of addresses, and nothing else. If anyone ever adds a message parameter, this
    /// file stops compiling and the discussion happens.
    #[test]
    fn the_wake_up_only_carries_addresses() {
        let spy = Spy::default();
        let address = Address { provider: "fcm".into(), token: "abc".into() };

        spy.wake(vec![address.clone()]);

        assert_eq!(spy.0.lock().unwrap().as_slice(), &[address]);
    }

    /// The default waker sends nothing and does not panic.
    ///
    /// That is the behaviour of a deployment with no provider, not a degraded case: it must stay
    /// the best-kept path in the module.
    #[test]
    fn without_a_provider_nothing_is_sent() {
        Silent.wake(vec![Address { provider: "fcm".into(), token: "abc".into() }]);
        Silent.wake(Vec::new());
    }
}
