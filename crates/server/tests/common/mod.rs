//! Test harness: real server, real database, real signed requests.
//!
//! Nothing is mocked. A delivery service test that short-circuits authentication or the
//! database only tests its own mock-up.
//!
//! This module is compiled once per test binary, and none of them uses the whole harness:
//! `dead_code` would therefore flag, on every build, whatever only serves the others.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use crypto_core::Account;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sqlx::PgPool;

/// Keeps each test's data apart.
///
/// The counter alone is not enough: the database **persists between runs**, so `alice-0`
/// would already exist on the second `cargo test`, with a different key — and registration
/// would rightly be refused (409). The per-process random prefix isolates each run without
/// having to purge the database.
static COUNTER: AtomicU64 = AtomicU64::new(0);
static RUN_ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    use rand_core::RngCore;
    format!("{:08x}", rand_core::OsRng.next_u32())
});

pub fn unique(prefix: &str) -> String {
    format!("{prefix}-{}-{}", *RUN_ID, COUNTER.fetch_add(1, Ordering::Relaxed))
}

pub struct TestServer {
    pub base_url: String,
    pub pool: PgPool,
}

pub async fn start() -> TestServer {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://whispee:dev_only_not_a_secret@localhost:55432/whispee".into()
    });

    let pool = server::connect(&database_url).await.unwrap_or_else(|e| {
        panic!("database unreachable ({e}) — run `docker compose up -d`");
    });

    // Rate limit disabled: the suite creates dozens of accounts within seconds from the
    // loopback, which no realistic quota would let through. The test that checks the limit
    // bites builds its own application, with a low quota.
    start_with(pool, server::throttle::Throttle::per_minute(0), server::throttle::Claims::per_minute(0)).await
}

/// Test server with an enforced rate limit.
pub async fn start_with_throttle(quota: u32) -> TestServer {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://whispee:dev_only_not_a_secret@localhost:55432/whispee".into()
    });

    let pool = server::connect(&database_url).await.unwrap();
    start_with(pool, server::throttle::Throttle::per_minute(quota), server::throttle::Claims::per_minute(0)).await
}

/// Test server with an enforced KeyPackage claim quota.
///
/// The open-route limit stays disabled: setting up a test's devices consumes several of
/// them, and the two bounds have nothing to do with each other.
pub async fn start_with_claim_quota(quota: u32) -> TestServer {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://whispee:dev_only_not_a_secret@localhost:55432/whispee".into()
    });

    let pool = server::connect(&database_url).await.unwrap();
    start_with(pool, server::throttle::Throttle::per_minute(0), server::throttle::Claims::per_minute(quota)).await
}

/// A wake emitter that keeps whatever it is handed.
///
/// What the server sends to the provider — and above all **to whom** — is a confidentiality
/// property. Checking it means seeing the addresses go by.
#[derive(Default)]
pub struct WakerSpy(pub std::sync::Mutex<Vec<server::push::Address>>);

impl server::push::Waker for WakerSpy {
    fn wake(&self, addresses: Vec<server::push::Address>) {
        self.0.lock().expect("poisoned spy").extend(addresses);
    }
}

impl WakerSpy {
    /// Waits for the detached wake to happen, or gives up.
    ///
    /// The wake runs in its own task so it does not delay the sender's response: there is
    /// nothing to wait for on the HTTP side. A bounded wait beats a fixed delay, which would
    /// be either too short on a loaded machine or wasted time on every run.
    pub async fn wait_for(&self, how_many: usize) -> Vec<server::push::Address> {
        for _ in 0..100 {
            {
                let seen = self.0.lock().expect("poisoned spy");
                if seen.len() >= how_many {
                    return seen.clone();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        self.0.lock().expect("poisoned spy").clone()
    }
}

/// A server whose wakes are observed.
pub async fn start_with_waker() -> (TestServer, std::sync::Arc<WakerSpy>) {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://whispee:dev_only_not_a_secret@localhost:55432/whispee".into()
    });
    let pool = server::connect(&database_url).await.unwrap();
    let spy = std::sync::Arc::new(WakerSpy::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = server::app_with_waker(
        pool.clone(),
        server::throttle::Throttle::per_minute(0),
        server::throttle::Claims::per_minute(0),
        spy.clone(),
    )
    .into_make_service_with_connect_info::<std::net::SocketAddr>();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (TestServer { base_url: format!("http://{addr}"), pool }, spy)
}

async fn start_with(
    pool: PgPool,
    throttle: server::throttle::Throttle,
    claims: server::throttle::Claims,
) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // `into_make_service_with_connect_info` as in production: without it, the limit's
    // `ConnectInfo` extractor fails and the open routes return an internal error. A harness
    // that served differently from the binary would test its own mock-up.
    let app = server::app_with(pool.clone(), throttle, claims)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer { base_url: format!("http://{addr}"), pool }
}

/// A client device: its authentication key and what it needs to sign its requests.
///
/// That key is distinct from the MLS signature key. See `server::auth`.
pub struct Device {
    pub id: String,
    signing_key: SigningKey,
    /// MLS signature key. Distinct from `signing_key`: reusing one key for two protocols is a
    /// classic mistake. Attested along with it, so an attestation from one device cannot be
    /// recombined with another device's MLS key.
    mls_key: [u8; 32],
    http: reqwest::Client,
    base_url: String,
}

/// A pseudonymous account and its root key.
///
/// Tests go through a real account rather than a direct insert: that is the only way to check
/// that the attestations produced on the client side really are the ones the server accepts.
pub struct TestAccount {
    pub handle: String,
    pub account: Account,
}

impl TestAccount {
    pub async fn create(server: &TestServer, handle: &str) -> Self {
        let (account, _phrase) = Account::generate().unwrap();

        let response = reqwest::Client::new()
            .post(format!("{}/v1/accounts", server.base_url))
            .json(&serde_json::json!({
                "handle": handle,
                "identity_key": BASE64_STANDARD.encode(account.identity_key()),
            }))
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success(), "account creation refused");
        Self { handle: handle.to_owned(), account }
    }

    /// Creates a device attached to this account and registers it.
    ///
    /// The identifier is qualified by the handle, as the server requires: the device
    /// namespace is local to the account.
    pub async fn device(&self, server: &TestServer, id: &str) -> Device {
        let device = Device::new(server, &format!("{}:{id}", self.handle));
        let response = device.register_under(self).await;
        assert!(response.status().is_success(), "registration refused: {:?}", response.status());
        device
    }

    /// Revokes a device from the account, backed by a signed certificate.
    ///
    /// Goes through the real route and the real signed format: an SQL shortcut would only
    /// test its own mock-up, and certificate verification is precisely what we want to
    /// exercise.
    pub async fn revoke(
        &self,
        caller: &Device,
        device_id: &str,
    ) -> reqwest::Response {
        let revoked_at = now();
        let certificate = self.account.revoke(&self.handle, device_id, revoked_at).unwrap();

        caller
            .post(
                &format!("/v1/devices/{device_id}/revoke"),
                serde_json::json!({
                    "revocation": BASE64_STANDARD.encode(certificate),
                    "revoked_at": revoked_at,
                }),
            )
            .await
    }

    pub fn identity_key_b64(&self) -> String {
        BASE64_STANDARD.encode(self.account.identity_key())
    }
}

impl Device {
    /// Registers this device under an account, with the matching attestation.
    pub async fn register_under(&self, owner: &TestAccount) -> reqwest::Response {
        let auth_key = self.signing_key.verifying_key().to_bytes();
        let attestation = owner
            .account
            .attest(&owner.handle, &self.id, &auth_key, &self.mls_key)
            .unwrap();

        self.http
            .post(format!("{}/v1/devices", self.base_url))
            .json(&serde_json::json!({
                "id": self.id,
                "handle": owner.handle,
                "auth_key": BASE64_STANDARD.encode(auth_key),
                "mls_key": BASE64_STANDARD.encode(self.mls_key),
                "attestation": BASE64_STANDARD.encode(attestation),
            }))
            .send()
            .await
            .unwrap()
    }

    /// Attempts a registration with an arbitrary attestation. Used by the attack tests.
    pub async fn register_with(&self, handle: &str, attestation: &[u8]) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/devices", self.base_url))
            .json(&serde_json::json!({
                "id": self.id,
                "handle": handle,
                "auth_key": self.public_key_b64(),
                "mls_key": BASE64_STANDARD.encode(self.mls_key),
                "attestation": BASE64_STANDARD.encode(attestation),
            }))
            .send()
            .await
            .unwrap()
    }

    pub fn mls_key(&self) -> &[u8] {
        &self.mls_key
    }

    /// Creates a device along with its own throwaway account.
    ///
    /// Shortcut for tests that do not care about multi-device grouping: one device, one
    /// account. Account tests go through [`TestAccount`].
    pub async fn register(server: &TestServer, id: &str) -> Self {
        let owner = TestAccount::create(server, &unique("account")).await;
        owner.device(server, id).await
    }

    /// Creates a device without registering it: the server does not know its key.
    pub fn new(server: &TestServer, id: &str) -> Self {
        Self {
            id: id.to_owned(),
            signing_key: SigningKey::generate(&mut OsRng),
            mls_key: SigningKey::generate(&mut OsRng).verifying_key().to_bytes(),
            http: reqwest::Client::new(),
            base_url: server.base_url.clone(),
        }
    }

    pub fn public_key_b64(&self) -> String {
        BASE64_STANDARD.encode(self.signing_key.verifying_key().as_bytes())
    }

    /// Signs a gateway challenge, the way a real client would.
    ///
    /// Goes through `attest::gateway_message` rather than rewriting the format: a second
    /// definition in the tests would validate the mock-up, not the server.
    pub fn sign_challenge(&self, challenge: &[u8]) -> String {
        let message = attest::gateway_message(&self.id, challenge).unwrap();
        BASE64_STANDARD.encode(self.signing_key.sign(&message).to_bytes())
    }

    /// Signs a challenge **using the format of an HTTP request**.
    ///
    /// Used by the test checking that a signature captured on the HTTP path opens no session:
    /// domain separation must reject it, not a coincidence of format.
    pub fn sign_challenge_as_http(&self, challenge: &[u8]) -> String {
        let payload =
            server::auth::signing_payload("GET", "/v1/gateway", now(), &[0u8; 16], challenge);
        BASE64_STANDARD.encode(self.signing_key.sign(&payload).to_bytes())
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.signed("GET", path, Vec::new()).await
    }

    pub async fn post(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        self.signed("POST", path, serde_json::to_vec(&body).unwrap()).await
    }

    async fn signed(&self, method: &str, path: &str, body: Vec<u8>) -> reqwest::Response {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.signed_at(method, path, body, timestamp, path).await
    }

    /// Raw variant for the attack tests: allows signing a path, a timestamp or a body
    /// different from the ones actually sent.
    pub async fn signed_at(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        timestamp: u64,
        signed_path: &str,
    ) -> reqwest::Response {
        let signed_body = body.clone();
        self.forge(method, path, body, signed_body, timestamp, signed_path).await
    }

    /// Sends `sent_body` while signing `signed_body`. Used to check that the server detects a
    /// body tampered with after signing.
    pub async fn forge(
        &self,
        method: &str,
        path: &str,
        sent_body: Vec<u8>,
        signed_body: Vec<u8>,
        timestamp: u64,
        signed_path: &str,
    ) -> reqwest::Response {
        // Drawn here rather than passed in: no test cares about its value, and making it
        // explicit everywhere would mean inventing one at every call. The replay test goes
        // through [`Device::forge_with_nonce`] — it must present exactly the same bytes
        // twice, which a randomly drawn nonce would make impossible.
        let nonce: [u8; 16] = rand_core::OsRng.gen_nonce();

        self.forge_with_nonce(method, path, sent_body, signed_body, timestamp, signed_path, nonce)
            .await
    }

    /// Variant with an imposed nonce, to replay a request byte for byte.
    #[allow(clippy::too_many_arguments)]
    pub async fn forge_with_nonce(
        &self,
        method: &str,
        path: &str,
        sent_body: Vec<u8>,
        signed_body: Vec<u8>,
        timestamp: u64,
        signed_path: &str,
        nonce: [u8; 16],
    ) -> reqwest::Response {
        // `server::auth::signing_payload` rather than a second writing of the format: two
        // definitions would drift, and it is the forgotten copy that turns a test green for
        // the wrong reason.
        let payload = server::auth::signing_payload(
            method,
            signed_path,
            timestamp,
            &nonce,
            &signed_body,
        );

        let signature = BASE64_STANDARD.encode(self.signing_key.sign(&payload).to_bytes());

        self.http
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{}{path}", self.base_url),
            )
            .header("x-device-id", &self.id)
            .header("x-timestamp", timestamp.to_string())
            .header("x-signature", signature)
            .header("x-nonce", BASE64_STANDARD.encode(nonce))
            .header("content-type", "application/json")
            .body(sent_body)
            .send()
            .await
            .unwrap()
    }
}

/// Draws a request nonce.
trait NonceSource {
    fn gen_nonce(&mut self) -> [u8; 16];
}

impl NonceSource for rand_core::OsRng {
    fn gen_nonce(&mut self) -> [u8; 16] {
        use rand_core::RngCore;

        let mut nonce = [0u8; 16];
        self.fill_bytes(&mut nonce);
        nonce
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------- gateway session

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

pub type Socket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// Opens a socket and returns the challenge received in `hello`.
pub async fn open_socket(server: &TestServer) -> (Socket, Vec<u8>) {
    let url = format!("{}/v1/gateway", server.base_url.replace("http://", "ws://"));
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.expect("upgrade refused");

    let hello = read_frame(&mut socket).await.expect("the server opens with a hello");
    assert_eq!(hello["op"], "hello");

    let nonce = BASE64_STANDARD.decode(hello["nonce"].as_str().unwrap()).unwrap();
    (socket, nonce)
}

/// Reads the next JSON frame, ignoring ping and pong.
///
/// A timeout bounds the wait: without it, a test that never gets the expected frame would hang
/// instead of failing, and a hanging test tells nobody anything.
pub async fn read_frame(socket: &mut Socket) -> Option<serde_json::Value> {
    let deadline = std::time::Duration::from_secs(5);

    tokio::time::timeout(deadline, async {
        while let Some(message) = socket.next().await {
            match message.ok()? {
                Message::Text(text) => return serde_json::from_str(&text).ok(),
                Message::Close(_) => return None,
                _ => continue,
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

pub async fn send_frame(socket: &mut Socket, frame: serde_json::Value) {
    socket.send(Message::Text(frame.to_string().into())).await.unwrap();
}

/// Opens an authenticated session and consumes the `ready`.
pub async fn session(server: &TestServer, device: &Device, cursors: serde_json::Value) -> Socket {
    let (mut socket, challenge) = open_socket(server).await;

    send_frame(
        &mut socket,
        serde_json::json!({
            "op": "identify",
            "device_id": device.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            "signature": device.sign_challenge(&challenge),
            "cursors": cursors,
        }),
    )
    .await;

    socket
}
