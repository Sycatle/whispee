//! Gateway session tests.
//!
//! Real server, real database, real WebSocket. The gateway protocol moves authentication from
//! the request to the session: what used to be checked for free on every HTTP call is now only
//! checked at the moments this module decides. These tests pin those moments down.

mod common;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use common::{
    Device, TestAccount, TestServer, open_socket, read_frame, send_frame, session, start, unique,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

async fn group_with(server: &TestServer, alice: &Device, bob: &Device) -> Vec<u8> {
    let _ = server;
    let group_id = unique("group").into_bytes();

    alice
        .post(
            &format!("/v1/groups/{}/members", hex::encode(&group_id)),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    group_id
}

/// Same thing, with the posting key the anonymous signal path requires.
async fn group_with_key(alice: &Device, bob: &Device, posting_key: &[u8]) -> Vec<u8> {
    let group_id = unique("group").into_bytes();

    alice
        .post(
            &format!("/v1/groups/{}/members", hex::encode(&group_id)),
            serde_json::json!({
                "device_ids": [alice.id, bob.id],
                "posting_key": BASE64_STANDARD.encode(posting_key),
            }),
        )
        .await;

    group_id
}

// ------------------------------------------------------------------ authentication

/// **The test that justifies the challenge.**
///
/// A socket that is open but not authenticated must get nothing. This is the only barrier: at
/// that point no signed extractor has run and the peer has proved nothing.
#[tokio::test]
async fn an_identify_without_a_valid_signature_subscribes_to_nothing() {
    let server = start().await;
    let device = Device::register(&server, &unique("alice")).await;
    let (mut socket, challenge) = open_socket(&server).await;

    send_frame(
        &mut socket,
        serde_json::json!({
            "op": "identify",
            "device_id": device.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            // A signature valid in itself, but produced over something else.
            "signature": device.sign_challenge(b"another challenge"),
        }),
    )
    .await;

    let response = read_frame(&mut socket).await;

    assert_eq!(
        response.map(|frame| frame["op"].as_str().unwrap().to_owned()),
        Some("error".to_owned()),
        "an invalid signature must be refused, never ignored",
    );

    assert!(read_frame(&mut socket).await.is_none(), "and the socket must be closed behind it");
}

/// **The test that justifies domain separation.**
///
/// The key that opens a session is the same one that signs HTTP requests. Without a domain of
/// its own, capturing any HTTP signature would be enough to open a session in its author's
/// name — and the challenge would serve no purpose.
#[tokio::test]
async fn an_http_signature_opens_no_session() {
    let server = start().await;
    let device = Device::register(&server, &unique("alice")).await;
    let (mut socket, challenge) = open_socket(&server).await;

    send_frame(
        &mut socket,
        serde_json::json!({
            "op": "identify",
            "device_id": device.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            "signature": device.sign_challenge_as_http(&challenge),
        }),
    )
    .await;

    assert_eq!(read_frame(&mut socket).await.map(|f| f["op"].as_str().unwrap().to_owned()).as_deref(),
        Some("error"));
}

/// **The test that justifies the challenge coming from the server.**
///
/// This is what sets this path apart from HTTP, which `server::auth` documents as replayable
/// for sixty seconds for want of remembering nonces. Here, a signature perfectly valid for one
/// session is worth nothing for the next.
#[tokio::test]
async fn a_hello_nonce_cannot_be_replayed() {
    let server = start().await;
    let device = Device::register(&server, &unique("alice")).await;

    // A first, successful opening, whose challenge / signature pair is captured.
    let (mut first, challenge) = open_socket(&server).await;
    let signature = device.sign_challenge(&challenge);
    send_frame(
        &mut first,
        serde_json::json!({
            "op": "identify",
            "device_id": device.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            "signature": signature,
        }),
    )
    .await;
    assert_eq!(read_frame(&mut first).await.unwrap()["op"], "ready");

    // The same pair, replayed on a second socket, which received a different challenge.
    let (mut second, _other_challenge) = open_socket(&server).await;
    send_frame(
        &mut second,
        serde_json::json!({
            "op": "identify",
            "device_id": device.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            "signature": signature,
        }),
    )
    .await;

    assert_eq!(
        read_frame(&mut second).await.map(|f| f["op"].as_str().unwrap().to_owned()).as_deref(),
        Some("error"),
        "the nonce sent back must be the one served to THIS socket",
    );
}

/// An already revoked device opens no session.
#[tokio::test]
async fn a_revoked_device_opens_no_session() {
    let server = start().await;
    let account = TestAccount::create(&server, &unique("account")).await;
    let phone = account.device(&server, "phone").await;
    let tablet = account.device(&server, "tablet").await;

    assert!(account.revoke(&phone, &tablet.id).await.status().is_success());

    let (mut socket, challenge) = open_socket(&server).await;
    send_frame(
        &mut socket,
        serde_json::json!({
            "op": "identify",
            "device_id": tablet.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            "signature": tablet.sign_challenge(&challenge),
        }),
    )
    .await;

    assert_eq!(
        read_frame(&mut socket).await.map(|f| f["op"].as_str().unwrap().to_owned()).as_deref(),
        Some("error"),
    );
}

// ------------------------------------------------------------------ access control

/// **The test that justifies re-checking on every `subscribe`.**
///
/// Trusting the group list computed at opening time would let a device subscribe to a group it
/// never belonged to — the subscription being, here, the whole access control over broadcast.
#[tokio::test]
async fn subscribing_to_a_group_one_is_not_a_member_of_is_refused() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let stranger = Device::register(&server, &unique("stranger")).await;

    let group_id = group_with(&server, &alice, &bob).await;

    let mut socket = session(&server, &stranger, serde_json::json!([])).await;
    assert_eq!(read_frame(&mut socket).await.unwrap()["op"], "ready");

    send_frame(
        &mut socket,
        serde_json::json!({ "op": "subscribe", "group_id": hex::encode(&group_id) }),
    )
    .await;

    let refusal = read_frame(&mut socket).await.expect("a refusal, not silence");
    assert_eq!(refusal["op"], "error");

    // And the subscription did not happen: a post to that group does not reach it.
    post_envelope(&server, &alice, &group_id, b"for members only").await;

    assert!(
        read_frame(&mut socket).await.is_none(),
        "a refusal that left the subscription in place would be worse than useless",
    );
}

/// **The test that justifies [`revalidate`].**
///
/// This is the direct counterpart of moving to session authentication: without that check,
/// revoking a device would cut it off from nothing as long as it keeps its socket.
#[tokio::test]
async fn a_revoked_device_has_its_session_closed() {
    let server = start().await;
    let account = TestAccount::create(&server, &unique("account")).await;
    let phone = account.device(&server, "phone").await;
    let tablet = account.device(&server, "tablet").await;

    let mut socket = session(&server, &tablet, serde_json::json!([])).await;
    assert_eq!(read_frame(&mut socket).await.unwrap()["op"], "ready");

    // The session was perfectly legitimate when it was opened.
    send_frame(&mut socket, serde_json::json!({ "op": "heartbeat" })).await;
    assert_eq!(read_frame(&mut socket).await.unwrap()["op"], "heartbeat_ack");

    assert!(account.revoke(&phone, &tablet.id).await.status().is_success());

    send_frame(&mut socket, serde_json::json!({ "op": "heartbeat" })).await;
    assert_eq!(read_frame(&mut socket).await.unwrap()["op"], "error");
    assert!(read_frame(&mut socket).await.is_none(), "the session must be closed, not merely warned");
}

/// Removal from a group cuts broadcast to an already open session.
///
/// SSE froze its subscriptions at opening time: an evicted member kept being served until it
/// reconnected on its own.
#[tokio::test]
async fn a_group_removal_cuts_an_open_session() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let group_id = group_with(&server, &alice, &bob).await;

    let mut socket = session(&server, &bob, serde_json::json!([])).await;
    let ready = read_frame(&mut socket).await.unwrap();
    assert_eq!(ready["op"], "ready");
    assert!(ready["groups"].as_array().unwrap().contains(&serde_json::json!(hex::encode(&group_id))));

    // Bob is removed from the group, then beats once so the session is recomputed.
    alice
        .post(
            &format!("/v1/groups/{}/members/remove", hex::encode(&group_id)),
            serde_json::json!({ "device_ids": [bob.id] }),
        )
        .await;

    send_frame(&mut socket, serde_json::json!({ "op": "heartbeat" })).await;
    assert_eq!(read_frame(&mut socket).await.unwrap()["op"], "heartbeat_ack");

    post_envelope(&server, &alice, &group_id, b"after the removal").await;

    assert!(read_frame(&mut socket).await.is_none(), "an evicted member must receive nothing more");
}

// ------------------------------------------------------------------ broadcast

/// The nominal path: a post wakes the subscribed sessions.
#[tokio::test]
async fn a_post_reaches_the_subscribed_sessions() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let group_id = group_with(&server, &alice, &bob).await;

    let mut socket = session(&server, &bob, serde_json::json!([])).await;
    assert_eq!(read_frame(&mut socket).await.unwrap()["op"], "ready");

    post_envelope(&server, &alice, &group_id, b"already encrypted").await;

    let frame = read_frame(&mut socket).await.expect("the envelope must be announced");
    assert_eq!(frame["op"], "envelope");
    assert_eq!(frame["group_id"], hex::encode(&group_id));

    // The sequence number, and nothing else: the content is read over the HTTP path, which
    // re-checks membership.
    assert!(frame.get("payload").is_none(), "broadcast must never carry content");
}

/// **The test that justifies catch-up.**
///
/// Without it, a reconnecting client has to poll every conversation with a signed request just
/// to learn it missed nothing — that is, hand the server back the activity log the long-lived
/// connection existed to take away from it.
#[tokio::test]
async fn the_resume_catches_up_on_the_missed_seqs() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let group_id = group_with(&server, &alice, &bob).await;

    // Three posts while Bob is away.
    for i in 0..3 {
        post_envelope(&server, &alice, &group_id, format!("message {i}").as_bytes()).await;
    }

    // Sequences start at 1: Bob comes back announcing he only saw the first one.
    let mut socket = session(
        &server,
        &bob,
        serde_json::json!([{ "group_id": hex::encode(&group_id), "seq": 1 }]),
    )
    .await;
    assert_eq!(read_frame(&mut socket).await.unwrap()["op"], "ready");

    let mut received = Vec::new();
    for _ in 0..2 {
        let frame = read_frame(&mut socket).await.expect("the backlog must be announced");
        assert_eq!(frame["op"], "envelope");
        received.push(frame["seq"].as_i64().unwrap());
    }

    assert_eq!(received, vec![2, 3], "only the sequences after the cursor, in order");

    // And nothing more: the cursor bounds the catch-up from above as well as from below.
    assert!(read_frame(&mut socket).await.is_none());
}

/// A cursor on someone else's group does not say whether that group exists.
///
/// Answering "unknown" rather than staying silent would turn catch-up into a group existence
/// oracle, available to any registered device.
#[tokio::test]
async fn a_cursor_on_someone_elses_group_is_ignored_silently() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let stranger = Device::register(&server, &unique("stranger")).await;
    let group_id = group_with(&server, &alice, &bob).await;

    post_envelope(&server, &alice, &group_id, b"private").await;

    let mut socket = session(
        &server,
        &stranger,
        serde_json::json!([{ "group_id": hex::encode(&group_id), "seq": 0 }]),
    )
    .await;

    assert_eq!(read_frame(&mut socket).await.unwrap()["op"], "ready");
    assert!(read_frame(&mut socket).await.is_none(), "no sequence, no error: nothing");
}

/// **The test that pins down the catch-up amplification bound.**
///
/// An `identify` frame must not buy as many SQL queries as it carries cursors. The membership
/// filter is not enough to prevent that: nothing forbids repeating a thousand times a group one
/// really belongs to, and it is the amplification that is the problem, not the access.
#[tokio::test]
async fn an_identify_loaded_with_cursors_answers_only_once_per_group() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let group_id = group_with(&server, &alice, &bob).await;

    post_envelope(&server, &alice, &group_id, b"a single message").await;

    // The same group, a thousand times, with a cursor that leaves one sequence to catch up on.
    let cursor = serde_json::json!({ "group_id": hex::encode(&group_id), "seq": 0 });
    let cursors = serde_json::Value::Array(vec![cursor; 1000]);

    let mut socket = session(&server, &bob, cursors).await;
    assert_eq!(common::read_frame(&mut socket).await.unwrap()["op"], "ready");

    let frame = common::read_frame(&mut socket).await.expect("the backlog must be announced once");
    assert_eq!(frame["op"], "envelope");

    assert!(
        common::read_frame(&mut socket).await.is_none(),
        "the sequence was announced again: every repeated cursor cost one query",
    );
}

// ------------------------------------------------------------------ multi-instance fanout

/// **The test that proves the hub is no longer locked inside its process.**
///
/// Two instances on the same database, a signal posted to one, a client connected to the other.
/// Without `LISTEN/NOTIFY` this test fails — and that is exactly the production situation it
/// describes: two instances behind a load balancer give two populations that cannot see each
/// other.
#[tokio::test]
async fn a_signal_crosses_two_instances() {
    let first = start().await;
    let second = start().await;

    let alice = Device::register(&first, &unique("alice")).await;
    let bob = Device::register(&first, &unique("bob")).await;

    let posting_key = [42u8; 32];
    let group_id = group_with_key(&alice, &bob, &posting_key).await;

    // Bob listens on the SECOND instance.
    let mut socket = session(&second, &bob, serde_json::json!([])).await;
    assert_eq!(read_frame(&mut socket).await.unwrap()["op"], "ready");

    // Alice signals on the FIRST one.
    let body = b"encrypted-typing-indicator";
    let response = post_signal(&first, &group_id, &posting_key, body).await;
    assert_eq!(response.status(), 204, "signal post refused");

    let frame = read_frame(&mut socket).await.expect("the signal must cross both instances");
    assert_eq!(frame["op"], "signal");
    assert_eq!(BASE64_STANDARD.decode(frame["payload"].as_str().unwrap()).unwrap(), body);
}

/// Partitioning is only useful if it is pruned: a read must touch just one partition out of
/// sixteen.
///
/// That is the property that made `HASH(group_id)` win over a time-based split, and it would be
/// lost at the first `WHERE` that stopped constraining `group_id`.
#[tokio::test]
async fn an_envelope_read_touches_only_one_partition() {
    let server = start().await;

    let plan: Vec<(String,)> = sqlx::query_as(
        "EXPLAIN SELECT seq, payload FROM envelopes
         WHERE group_id = $1 AND seq > 0 ORDER BY seq LIMIT 200",
    )
    .bind(b"some-group-or-other".to_vec())
    .fetch_all(&server.pool)
    .await
    .unwrap();

    let plan = plan.into_iter().map(|(line,)| line).collect::<Vec<_>>().join("\n");

    // Count distinct partitions, not mentions of one. A single partition appears twice in the
    // plan as soon as the planner picks an index scan ("Index Scan using envelopes_pNN_pkey on
    // envelopes_pNN"), and whether it does depends on whether that partition happens to hold
    // rows — which depends on what the rest of the suite inserted.
    let touched: std::collections::BTreeSet<&str> = plan
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|word| word.starts_with("envelopes_p"))
        .map(|word| word.trim_end_matches("_pkey"))
        .collect();

    assert_eq!(touched.len(), 1, "one partition expected, the plan visits {touched:?}:\n{plan}");
}

// ------------------------------------------------------------------ helpers

async fn post_envelope(server: &TestServer, device: &Device, group_id: &[u8], body: &[u8]) {
    let _ = server;

    let response = device
        .post(
            &format!("/v1/groups/{}/envelopes", hex::encode(group_id)),
            serde_json::json!({ "payload": BASE64_STANDARD.encode(body) }),
        )
        .await;

    assert!(response.status().is_success(), "post refused: {}", response.status());

    // Broadcast is asynchronous: let the hub carry it before noting its absence, otherwise a
    // negative test would pass for the wrong reason.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
}

/// Posts an ephemeral signal over the anonymous path: group MAC, no device signature.
///
/// This is the only path a signal can take, on the gateway as over HTTP: `verify_signal`
/// refuses a group without a posting key rather than falling back on identity-based
/// verification.
async fn post_signal(
    server: &TestServer,
    group_id: &[u8],
    posting_key: &[u8],
    payload: &[u8],
) -> reqwest::Response {
    let nonce = [7u8; 16];
    let message = attest::signal_message(group_id, &nonce, &Sha256::digest(payload)).unwrap();

    let mut mac = <Hmac<Sha256>>::new_from_slice(posting_key).unwrap();
    mac.update(&message);

    reqwest::Client::new()
        .post(format!("{}/v1/groups/{}/signals", server.base_url, hex::encode(group_id)))
        .header("content-type", "application/octet-stream")
        .header("x-group-nonce", BASE64_STANDARD.encode(nonce))
        .header("x-group-mac", BASE64_STANDARD.encode(mac.finalize().into_bytes()))
        .body(payload.to_vec())
        .send()
        .await
        .unwrap()
}
