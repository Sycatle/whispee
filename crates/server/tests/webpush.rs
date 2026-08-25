//! What this server actually puts on the wire when it wakes a browser.
//!
//! # Why a fake push service and not a mock
//!
//! Because the property worth checking is not "a function was called" but "the bytes leaving this
//! process are ones a push service would accept, and they carry nothing". A mock of our own
//! `Waker` would assert the first and be blind to the second — and the second is the whole
//! feature. So the double is a real HTTP server, on a real socket, reached by a real client,
//! built from the recipe `common::start_with` already uses.
//!
//! It is also what makes the endpoint override unnecessary: a Web Push subscription **is** a URL,
//! stored as the token, so pointing the server at this double is just registering it as a
//! subscription. Nothing in production code exists for the benefit of these tests.
//!
//! # What no test here can establish
//!
//! That Google and Mozilla accept these tokens. This checks the token against the specification
//! and against the public key advertised beside it; the remaining risk is a service disagreeing
//! with our reading of RFC 8292, and only a real subscription settles that. `docs/ROADMAP.md`
//! says so rather than leaving it implied.

mod common;

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use common::{Device, unique};
use server::push::{Configured, Vapid, WEB_PUSH};

/// One request as the push service saw it.
#[derive(Clone)]
struct Received {
    authorization: String,
    ttl: String,
    body: Vec<u8>,
    path: String,
}

/// A push service that records what it is sent and answers with the status it was told to.
struct FakeService {
    origin: String,
    seen: Arc<Mutex<Vec<Received>>>,
}

impl FakeService {
    async fn start(status: u16) -> Self {
        use axum::extract::{Path, State};
        use axum::http::HeaderMap;
        use axum::routing::post;

        let seen: Arc<Mutex<Vec<Received>>> = Arc::new(Mutex::new(Vec::new()));

        let app = axum::Router::new()
            .route(
                "/push/{id}",
                post(
                    |State((seen, status)): State<(Arc<Mutex<Vec<Received>>>, u16)>,
                     Path(id): Path<String>,
                     headers: HeaderMap,
                     body: axum::body::Bytes| async move {
                        let header = |name: &str| {
                            headers
                                .get(name)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_owned()
                        };

                        seen.lock().unwrap().push(Received {
                            authorization: header("authorization"),
                            ttl: header("ttl"),
                            body: body.to_vec(),
                            path: format!("/push/{id}"),
                        });

                        axum::http::StatusCode::from_u16(status).unwrap()
                    },
                ),
            )
            .with_state((seen.clone(), status));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self { origin: format!("http://{addr}"), seen }
    }

    fn endpoint(&self, id: &str) -> String {
        format!("{}/push/{id}", self.origin)
    }

    /// Waits for a request, because the wake-up is detached and nothing on the HTTP response
    /// depends on it. Same shape as `WakerSpy::wait_for`, and for the same reason.
    async fn wait_for_one(&self) -> Option<Received> {
        for _ in 0..100 {
            if let Some(first) = self.seen.lock().unwrap().first() {
                return Some(first.clone());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        None
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

const SUBJECT: &str = "mailto:ops@example.test";

/// Stands up a server that really emits Web Push, and hands back the advertised key.
async fn server_with_web_push(pool: sqlx::PgPool) -> (common::TestServer, String) {
    let key = server::vapid::Key::ensure(&pool).await.unwrap();
    let public_key = key.public_key();

    let push = Configured {
        waker: Arc::new(Vapid::new(pool.clone(), key, SUBJECT.into())),
        public_key: Some(public_key.clone()),
    };

    (common::start_with_push(push).await, public_key)
}

/// Registers a device, puts it in a group with a sender, and subscribes it to `endpoint`.
async fn subscribed_pair(server: &common::TestServer, endpoint: &str) -> (Device, Vec<u8>) {
    let alice = Device::register(server, &unique("alice")).await;
    let bob = Device::register(server, &unique("bob")).await;

    let group_id = unique("group").into_bytes();
    alice
        .post(
            &format!("/v1/groups/{}/members", hex::encode(&group_id)),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    let registered = bob
        .post(
            "/v1/push/token",
            serde_json::json!({ "provider": WEB_PUSH, "token": endpoint }),
        )
        .await;
    assert_eq!(registered.status(), 200);

    (alice, group_id)
}

async fn post_a_message(sender: &Device, group_id: &[u8]) {
    sender
        .post(
            &format!("/v1/groups/{}/envelopes", hex::encode(group_id)),
            serde_json::json!({ "payload": BASE64_STANDARD.encode([7u8]) }),
        )
        .await;
}

/// **The test the whole feature rests on.**
///
/// Three things at once, because they are one claim: the request is authenticated the way RFC
/// 8292 defines, the token verifies under the key this deployment advertises, and the body is
/// empty. The third is checked at the wire rather than inferred from `Waker`'s signature — the
/// signature stops a *parameter* being added, not a body being written here.
#[tokio::test]
async fn the_wake_up_is_signed_for_the_service_and_carries_nothing() {
    let pool = common::test_pool().await;
    let service = FakeService::start(201).await;
    let (server, advertised) = server_with_web_push(pool).await;

    let (alice, group_id) = subscribed_pair(&server, &service.endpoint("abc")).await;
    post_a_message(&alice, &group_id).await;

    let seen = service.wait_for_one().await.expect("the service was never called");

    assert!(seen.body.is_empty(), "a wake-up must carry nothing, got {} bytes", seen.body.len());
    assert_eq!(seen.path, "/push/abc", "the endpoint's own path must be preserved");
    assert_eq!(seen.ttl, "14400");

    // `vapid t=<jwt>, k=<public key>` — the two parameters RFC 8292 defines.
    let rest = seen.authorization.strip_prefix("vapid t=").expect("a vapid authorization");
    let (jwt, key_part) = rest.split_once(", k=").expect("both parameters");

    assert_eq!(
        key_part, advertised,
        "the key sent to the service is not the one clients are told to subscribe against"
    );

    // Verified exactly as the service would: against the advertised key, not against anything
    // this process kept a handle on.
    use p256::ecdsa::signature::Verifier;
    let (signing_input, signature) = jwt.rsplit_once('.').expect("a signature");
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(
        &URL_SAFE_NO_PAD.decode(key_part).expect("base64url"),
    )
    .expect("an uncompressed point");
    let signature = p256::ecdsa::Signature::from_slice(
        &URL_SAFE_NO_PAD.decode(signature).expect("base64url"),
    )
    .expect("sixty-four bytes");
    verifying
        .verify(signing_input.as_bytes(), &signature)
        .expect("the push service would refuse this token");

    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(signing_input.split('.').nth(1).expect("a payload"))
            .expect("base64url"),
    )
    .expect("json");

    assert_eq!(claims["aud"], service.origin, "signed for a different service than the one called");
    assert_eq!(claims["sub"], SUBJECT);
}

/// A subscription the service says is gone is removed, rather than retried forever.
///
/// Nothing else in this server would ever delete that row: a browser drops a subscription without
/// telling anybody, and `410` is the only notice there is. Left in place, every future wake-up
/// would carry a growing tail of requests that cannot succeed.
#[tokio::test]
async fn a_subscription_the_service_has_dropped_is_forgotten() {
    let pool = common::test_pool().await;
    let service = FakeService::start(410).await;
    let (server, _) = server_with_web_push(pool).await;

    let endpoint = service.endpoint("gone");
    let (alice, group_id) = subscribed_pair(&server, &endpoint).await;
    post_a_message(&alice, &group_id).await;

    service.wait_for_one().await.expect("the service was never called");

    // The delete happens after the response, so it is worth a few attempts rather than one read.
    for _ in 0..100 {
        let (rows,): (i64,) =
            sqlx::query_as("SELECT count(*)::bigint FROM push_tokens WHERE token = $1")
                .bind(&endpoint)
                .fetch_one(&server.pool)
                .await
                .unwrap();

        if rows == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    panic!("a subscription the service reported gone is still stored");
}

/// A service having a bad day keeps its subscriptions.
///
/// The opposite policy is tempting and wrong: dropping a live subscription over one `500` would
/// silence a device permanently, and the device has no way to know it should re-subscribe.
#[tokio::test]
async fn a_failing_service_does_not_cost_the_subscription() {
    let pool = common::test_pool().await;
    let service = FakeService::start(500).await;
    let (server, _) = server_with_web_push(pool).await;

    let endpoint = service.endpoint("flaky");
    let (alice, group_id) = subscribed_pair(&server, &endpoint).await;
    post_a_message(&alice, &group_id).await;

    service.wait_for_one().await.expect("the service was never called");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let (rows,): (i64,) =
        sqlx::query_as("SELECT count(*)::bigint FROM push_tokens WHERE token = $1")
            .bind(&endpoint)
            .fetch_one(&server.pool)
            .await
            .unwrap();

    assert_eq!(rows, 1, "a transient failure must not unsubscribe a device");
}

/// A token for a provider this build cannot speak to is skipped, not attempted.
///
/// That is what an FCM or APNs token looks like today: the column accepts any provider name — the
/// server has nothing to decide there — and the emitter simply has no way to reach it yet.
#[tokio::test]
async fn a_token_for_another_provider_is_left_alone() {
    let pool = common::test_pool().await;
    let service = FakeService::start(201).await;
    let (server, _) = server_with_web_push(pool).await;

    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let group_id = unique("group").into_bytes();
    alice
        .post(
            &format!("/v1/groups/{}/members", hex::encode(&group_id)),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    // An endpoint that would work, under a provider name that is not this one.
    bob.post(
        "/v1/push/token",
        serde_json::json!({ "provider": "fcm", "token": service.endpoint("nope") }),
    )
    .await;

    post_a_message(&alice, &group_id).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert_eq!(service.count(), 0, "a webpush request was sent for an fcm token");
}

/// The advertised key is served to clients, and it is the one that signs.
///
/// Checked through the route rather than through the struct: a client subscribes against what the
/// route returns, so a deployment whose route disagreed with its signer would mint subscriptions
/// that are refused later, on a path nobody watches.
#[tokio::test]
async fn the_route_serves_the_key_that_signs() {
    let pool = common::test_pool().await;
    let (server, advertised) = server_with_web_push(pool).await;

    let response = reqwest::get(format!("{}/v1/push/vapid", server.base_url)).await.unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["key"], advertised);

    // And it is a point, not a string that happens to be there.
    let raw = URL_SAFE_NO_PAD.decode(body["key"].as_str().unwrap()).unwrap();
    assert_eq!(raw.len(), 65, "an uncompressed P-256 point is sixty-five bytes");
    assert_eq!(raw[0], 0x04, "not in uncompressed form; a browser would refuse it");
}

/// With push off, the route says the deployment does not offer this — not that it is missing.
///
/// 503 and not 404, the distinction calls already draw: the client hides the control instead of
/// retrying something no retry fixes.
#[tokio::test]
async fn the_key_route_is_unavailable_when_push_is_off() {
    let server = common::start().await;

    let response = reqwest::get(format!("{}/v1/push/vapid", server.base_url)).await.unwrap();

    assert_eq!(response.status(), 503);
}

/// **The one thing the double above cannot settle: does a real push service accept our token?**
///
/// Ignored by default, because it needs a live subscription and a network. Run it with an endpoint
/// taken from a browser — `pushManager.subscribe()` in the console, or the settings switch — and
/// watch the notification arrive:
///
/// ```sh
/// WHISPEE_REAL_ENDPOINT='https://fcm.googleapis.com/fcm/send/…' \
///   cargo test --release -p server --test webpush -- --ignored --nocapture
/// ```
///
/// A refusal shows up two ways, and both are the point of running it: the subscription is dropped
/// here if the service answered `404`/`410`, and a `401` or `403` is logged by the emitter. Success
/// is a notification on the screen, which no assertion in this file can reach.
#[tokio::test]
#[ignore = "needs a live subscription in WHISPEE_REAL_ENDPOINT and a network"]
async fn a_real_push_service_accepts_the_token() {
    let Ok(endpoint) = std::env::var("WHISPEE_REAL_ENDPOINT") else {
        panic!("set WHISPEE_REAL_ENDPOINT to a subscription endpoint from a browser");
    };

    let pool = common::test_pool().await;
    let (server, advertised) = server_with_web_push(pool).await;
    eprintln!("advertised key: {advertised}");
    eprintln!("pushing to:     {endpoint}");

    let (alice, group_id) = subscribed_pair(&server, &endpoint).await;
    post_a_message(&alice, &group_id).await;

    // Long enough for the round trip to Google or Mozilla, which is not a loopback.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let (rows,): (i64,) =
        sqlx::query_as("SELECT count(*)::bigint FROM push_tokens WHERE token = $1")
            .bind(&endpoint)
            .fetch_one(&server.pool)
            .await
            .unwrap();

    assert_eq!(
        rows, 1,
        "the push service reported this subscription gone — the endpoint is stale, or it was \
         minted against a different key than the one this deployment advertises"
    );

    eprintln!("the service did not reject the subscription; a notification should be on screen");
}
