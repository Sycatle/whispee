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
