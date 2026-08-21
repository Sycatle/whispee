//! Integration tests for the delivery service, against a real PostgreSQL.
//!
//! ```sh
//! docker compose up -d
//! cargo test -p server --release
//! ```

mod common;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use sha2::Digest;
use common::{TestAccount, Device, TestServer, now, start, unique};
use crypto_core::{Conversation, Identity};

fn group_path(group_id: &[u8], suffix: &str) -> String {
    format!("/v1/groups/{}{}", hex::encode(group_id), suffix)
}

// ---------------------------------------------------------------- registration

#[tokio::test]
async fn registration_is_idempotent_but_a_device_id_cannot_be_taken_over() {
    let server = start().await;
    let account = TestAccount::create(&server, &unique("alice")).await;
    let id = unique("device");
    let device = account.device(&server, &id).await;

    // Re-registering the same device must succeed: that is the reinstall case.
    assert!(device.register_under(&account).await.status().is_success());

    // Claiming the same id with different keys must be refused, even with a valid attestation:
    // otherwise a member of the account takes over another device's id and inherits its access.
    let impostor = Device::new(&server, &format!("{}:{id}", account.handle));
    assert_eq!(impostor.register_under(&account).await.status(), 409);
}

/// The device namespace is local to the account.
///
/// Otherwise the first arrival hogs "laptop", "desktop", "phone", and the second legitimate
/// user is denied registration for a reason that has nothing to do with security.
#[tokio::test]
async fn two_accounts_can_name_their_device_the_same_way() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let bob = TestAccount::create(&server, &unique("bob")).await;

    alice.device(&server, "laptop").await;
    bob.device(&server, "laptop").await;
}

/// The prefix is not a politeness convention: the server checks it. Otherwise one account
/// could squat another's namespace.
#[tokio::test]
async fn an_unprefixed_device_id_is_refused() {
    let server = start().await;
    let account = TestAccount::create(&server, &unique("alice")).await;
    let device = Device::new(&server, &unique("laptop"));

    assert_eq!(device.register_under(&account).await.status(), 400);
}

#[tokio::test]
async fn an_auth_key_of_the_wrong_size_is_refused() {
    let server = start().await;
    let account = TestAccount::create(&server, &unique("alice")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/devices", server.base_url))
        .json(&serde_json::json!({
            "id": unique("device"),
            "handle": account.handle,
            "auth_key": BASE64_STANDARD.encode([0u8; 16]),
            "mls_key": BASE64_STANDARD.encode([0u8; 32]),
            "attestation": BASE64_STANDARD.encode([0u8; 64]),
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

// ---------------------------------------------------------------- accounts and attestations

#[tokio::test]
async fn a_handle_cannot_be_taken_over_by_another_account() {
    let server = start().await;
    let handle = unique("alice");
    let account = TestAccount::create(&server, &handle).await;

    // Same key: reinstall, accepted.
    let response = reqwest::Client::new()
        .post(format!("{}/v1/accounts", server.base_url))
        .json(&serde_json::json!({
            "handle": handle,
            "identity_key": account.identity_key_b64(),
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Different key: refused, otherwise anyone appropriates a known handle.
    let (other, _) = crypto_core::Account::generate().unwrap();
    let response = reqwest::Client::new()
        .post(format!("{}/v1/accounts", server.base_url))
        .json(&serde_json::json!({
            "handle": handle,
            "identity_key": BASE64_STANDARD.encode(other.identity_key()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);
}

/// Without this barrier, anyone declares a device in someone else's account and gets invited
/// into their conversations. This is the "online" version of the ghost device attack; the
/// "complicit server" version is covered further down.
#[tokio::test]
async fn a_device_without_a_valid_attestation_is_refused() {
    let server = start().await;
    let account = TestAccount::create(&server, &unique("alice")).await;
    let intruder = Device::new(&server, &unique("ghost"));

    let response = intruder.register_with(&account.handle, &[0u8; 64]).await;

    assert_eq!(response.status(), 400, "a null attestation was accepted");
}

/// One account cannot attest for another: the attestation only verifies under the key of the
/// account it targets.
#[tokio::test]
async fn an_attestation_from_one_account_is_worthless_in_another() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let bob = TestAccount::create(&server, &unique("bob")).await;

    let intruder = Device::new(&server, &unique("device"));
    // Genuine attestation, produced by Alice, but presented in Bob's account.
    let attestation = alice
        .account
        .attest(&bob.handle, &intruder.id, &[0u8; 32], intruder.mls_key())
        .unwrap();

    assert_eq!(intruder.register_with(&bob.handle, &attestation).await.status(), 400);
}

#[tokio::test]
async fn the_devices_of_an_account_are_listed_with_their_attestations() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, &unique("laptop")).await;
    let tablet = alice.device(&server, &unique("tablet")).await;

    let body: serde_json::Value = laptop
        .get(&format!("/v1/accounts/{}/devices", alice.handle))
        .await
        .json()
        .await
        .unwrap();

    assert_eq!(body["identity_key"], alice.identity_key_b64());
    let ids: Vec<&str> =
        body["devices"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&laptop.id.as_str()));
    assert!(ids.contains(&tablet.id.as_str()));

    // Every served attestation must verify under the account key: that is what the client
    // redoes on its side, and what it actually relies on.
    for device in body["devices"].as_array().unwrap() {
        let claim = attest::DeviceClaim {
            handle: &alice.handle,
            device_id: device["id"].as_str().unwrap(),
            auth_key: &BASE64_STANDARD.decode(device["auth_key"].as_str().unwrap()).unwrap(),
            mls_key: &BASE64_STANDARD.decode(device["mls_key"].as_str().unwrap()).unwrap(),
        };
        let attestation =
            BASE64_STANDARD.decode(device["attestation"].as_str().unwrap()).unwrap();

        assert!(attest::verify(&alice.account.identity_key(), &claim, &attestation).is_ok());
    }
}

/// **The test that matters.**
///
/// We do not simulate a malicious server: we play it. The ghost device is inserted directly in
/// SQL, bypassing the endpoint validation entirely — exactly what an operator, an attacker who
/// obtained the database, or a court order would do.
///
/// The server then serves it without flinching: it has no way of knowing it is lying. The only
/// thing protecting Alice is that she re-verifies the attestation herself, and that the server
/// cannot produce one without holding Bob's account key.
///
/// If this test ever passed because the server filters, the protection would be an illusion:
/// it would rest on the goodwill of the very party it is supposed to protect against.
#[tokio::test]
async fn a_ghost_device_injected_in_sql_does_not_pass_client_verification() {
    let server = start().await;
    let bob = TestAccount::create(&server, &unique("bob")).await;
    let _legitimate = bob.device(&server, &unique("laptop")).await;
    let alice = Device::register(&server, &unique("alice")).await;

    // The server fabricates a device it controls, in Bob's account, with an arbitrary
    // attestation — it cannot produce a valid one.
    let ghost = unique("ghost");
    sqlx::query(
        "INSERT INTO devices (id, handle, auth_key, mls_key, attestation)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&ghost)
    .bind(&bob.handle)
    .bind(&[0xaa_u8; 32][..])
    .bind(&[0xbb_u8; 32][..])
    .bind(&[0xcc_u8; 64][..])
    .execute(&server.pool)
    .await
    .unwrap();

    let body: serde_json::Value = alice
        .get(&format!("/v1/accounts/{}/devices", bob.handle))
        .await
        .json()
        .await
        .unwrap();

    // The server does serve it: the defence is not that it refuses to lie.
    let served = body["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == ghost.as_str())
        .expect("the server should serve what we inserted into its database");

    // But the client rejects it, because the attestation does not verify.
    let claim = attest::DeviceClaim {
        handle: &bob.handle,
        device_id: &ghost,
        auth_key: &BASE64_STANDARD.decode(served["auth_key"].as_str().unwrap()).unwrap(),
        mls_key: &BASE64_STANDARD.decode(served["mls_key"].as_str().unwrap()).unwrap(),
    };
    let attestation = BASE64_STANDARD.decode(served["attestation"].as_str().unwrap()).unwrap();
    let identity_key = BASE64_STANDARD.decode(body["identity_key"].as_str().unwrap()).unwrap();

    assert!(
        attest::verify(&identity_key, &claim, &attestation).is_err(),
        "a ghost device passed verification: the whole multi-device story is compromised",
    );
}

/// Revocation requires the account key. An HTTP request signature only proves possession of a
/// device — and a stolen device would then revoke the others to stay alone in place.
#[tokio::test]
async fn revoking_without_the_account_key_is_refused() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, &unique("laptop")).await;
    let tablet = alice.device(&server, &unique("tablet")).await;

    let response = laptop
        .post(
            &format!("/v1/devices/{}/revoke", tablet.id),
            serde_json::json!({
                "revocation": BASE64_STANDARD.encode([0u8; 64]),
                "revoked_at": common::now(),
            }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

/// **The certificate is what stops the server from inventing a revocation.** A third-party
/// account able to sign in Alice's place would have her devices evicted from all her groups:
/// targeted, durable censorship, indistinguishable from a legitimate revocation.
#[tokio::test]
async fn a_certificate_signed_by_another_account_is_refused() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, &unique("laptop")).await;
    let tablet = alice.device(&server, &unique("tablet")).await;

    // Mallory owns a perfectly valid account, just not Alice's.
    let mallory = TestAccount::create(&server, &unique("mallory")).await;
    let revoked_at = common::now();
    let certificate = mallory.account.revoke(&alice.handle, &tablet.id, revoked_at).unwrap();

    let response = laptop
        .post(
            &format!("/v1/devices/{}/revoke", tablet.id),
            serde_json::json!({
                "revocation": BASE64_STANDARD.encode(certificate),
                "revoked_at": revoked_at,
            }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

/// **The test that pins down the protection of someone else's stock.**
///
/// Consuming a KeyPackage is irreversible, and any authenticated device can target anyone —
/// the caller has no relationship to prove with its target. Without a bound, any account
/// drains whoever it likes and makes them unreachable for any new conversation.
#[tokio::test]
async fn a_third_party_cannot_drain_someone_elses_stock() {
    let server = common::start_with_claim_quota(2).await;
    let victim = Device::register(&server, &unique("victim")).await;

    // A comfortable stock: what we want to observe is the refusal, not exhaustion.
    let packages: Vec<String> =
        (0..10u8).map(|i| BASE64_STANDARD.encode([i; 32])).collect();
    assert!(
        victim
            .post("/v1/key-packages", serde_json::json!({ "packages": packages }))
            .await
            .status()
            .is_success()
    );

    let intruder = Device::register(&server, &unique("intruder")).await;
    let claim = format!("/v1/key-packages/{}/claim", victim.id);

    for round in 1..=2 {
        let response = intruder.post(&claim, serde_json::json!({})).await;
        assert!(response.status().is_success(), "consumption {round} should have passed");
    }

    let refused = intruder.post(&claim, serde_json::json!({})).await;
    assert_eq!(refused.status(), 429, "the intruder could keep draining the stock");

    // The victim stays reachable: the stock only lost what the quota allowed.
    let stock: serde_json::Value =
        victim.get("/v1/key-packages/stock").await.json().await.unwrap();
    assert_eq!(stock["remaining"], 8);
}

/// The quota applies to the caller-target pair, not to the caller alone.
///
/// Opening conversations with many correspondents is legitimate; hounding a single one is not.
/// Counting per caller would punish the first use to prevent the second.
#[tokio::test]
async fn the_stock_quota_does_not_penalise_the_other_targets() {
    let server = common::start_with_claim_quota(1).await;

    let intruder = Device::register(&server, &unique("intruder")).await;

    for _ in 0..2 {
        let target = Device::register(&server, &unique("target")).await;
        target
            .post(
                "/v1/key-packages",
                serde_json::json!({ "packages": [BASE64_STANDARD.encode([1u8; 32])] }),
            )
            .await;

        let response = intruder
            .post(&format!("/v1/key-packages/{}/claim", target.id), serde_json::json!({}))
            .await;

        assert!(response.status().is_success(), "a distinct target was refused");
    }
}

/// **The test that pins down the limit on open routes.**
///
/// Account creation cannot be authenticated — you cannot sign with a key the server does not
/// know yet — and it writes into the transparency log, whose entries cannot be taken over
/// without breaking the consistency proofs. Without a limit, an identity-less third party grows
/// the one table of the schema we do not know how to clean up, indefinitely.
#[tokio::test]
async fn the_open_routes_refuse_beyond_the_quota() {
    let server = common::start_with_throttle(2).await;

    for round in 1..=2 {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/accounts", server.base_url))
            .json(&serde_json::json!({
                "handle": unique("quota"),
                "identity_key": BASE64_STANDARD.encode([7u8; 32]),
            }))
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success(), "creation {round} should have passed");
    }

    let refused = reqwest::Client::new()
        .post(format!("{}/v1/accounts", server.base_url))
        .json(&serde_json::json!({
            "handle": unique("quota"),
            "identity_key": BASE64_STANDARD.encode([7u8; 32]),
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(refused.status(), 429, "the quota was not applied");
}

/// The limit does not spill over onto authenticated routes.
///
/// It would be harmful there: the signature already identifies the caller, and penalising an
/// address would punish everyone sharing it — a NAT, a campus — for the abuse of a single one.
#[tokio::test]
async fn the_limit_does_not_touch_signed_routes() {
    // Two, and no fewer: preparing a device consumes exactly two open routes — creating the
    // account then registering the device. That is also what makes the default of sixty per
    // minute comfortable, a real user only consuming a handful.
    let server = common::start_with_throttle(2).await;
    let alice = Device::register(&server, &unique("alice")).await;

    for round in 1..=5 {
        let response = alice.get("/v1/groups").await;
        assert!(response.status().is_success(), "signed request {round} was rate limited");
    }
}

/// **The test that pins down anti-replay.**
///
/// The same request, byte for byte, must pass only once. Without that guarantee, a network
/// observer can replay any signed request for the whole clock tolerance window — sixty seconds.
#[tokio::test]
async fn a_signed_request_only_passes_once() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    // Everything is frozen — timestamp, body **and nonce**: the two sends are therefore
    // identical byte for byte, which is exactly what a network observer can reproduce.
    let instant = common::now();
    let nonce = [3u8; 16];
    let body = serde_json::to_vec(&serde_json::json!({ "handles": [] })).unwrap();

    let send = async |body: Vec<u8>| {
        alice
            .forge_with_nonce(
                "POST",
                "/v1/presence",
                body.clone(),
                body,
                instant,
                "/v1/presence",
                nonce,
            )
            .await
    };

    assert!(send(body.clone()).await.status().is_success(), "the first one must pass");
    assert_eq!(send(body).await.status(), 401, "the request was accepted twice");
}

/// The nonce is per device.
///
/// It is drawn at random, without coordination between clients: if uniqueness were global, two
/// devices drawing the same nonce would cut each other off, and the refusal would look random.
#[tokio::test]
async fn two_devices_can_draw_the_same_nonce() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let instant = common::now();
    let nonce = [7u8; 16];
    let body = serde_json::to_vec(&serde_json::json!({ "handles": [] })).unwrap();

    for device in [&alice, &bob] {
        let response = device
            .forge_with_nonce(
                "POST",
                "/v1/presence",
                body.clone(),
                body.clone(),
                instant,
                "/v1/presence",
                nonce,
            )
            .await;

        assert!(response.status().is_success(), "one device's nonce blocked the other");
    }
}

/// The timestamp is inside the signed message: presenting it shifted invalidates the
/// signature. Without that bound, a certificate forged in advance would stay usable after a
/// database theft.
#[tokio::test]
async fn a_timestamp_outside_the_window_is_refused() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, &unique("laptop")).await;
    let tablet = alice.device(&server, &unique("tablet")).await;

    let future = common::now() + 3600;
    let certificate = alice.account.revoke(&alice.handle, &tablet.id, future).unwrap();

    let response = laptop
        .post(
            &format!("/v1/devices/{}/revoke", tablet.id),
            serde_json::json!({
                "revocation": BASE64_STANDARD.encode(certificate),
                "revoked_at": future,
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn a_revoked_device_can_no_longer_be_added_to_a_group() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, &unique("laptop")).await;
    let tablet = alice.device(&server, &unique("tablet")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    tablet
        .post("/v1/key-packages", serde_json::json!({ "packages": [BASE64_STANDARD.encode(b"kp")] }))
        .await;

    let response = alice.revoke(&laptop, &tablet.id).await;
    assert!(response.status().is_success(), "legitimate revocation refused");

    // No KeyPackage left: nobody can open a conversation with this device any more, which is
    // the whole point of the revocation.
    let response =
        bob.post(&format!("/v1/key-packages/{}/claim", tablet.id), serde_json::json!({})).await;
    assert_eq!(response.status(), 404);

    // It stays in the list served to correspondents, but marked revoked and accompanied by its
    // certificate. Making it disappear would make the revocation indistinguishable from an
    // omission by the server — and it is that certificate which lets Bob commit the MLS removal
    // without taking our word for it.
    let body: serde_json::Value =
        bob.get(&format!("/v1/accounts/{}/devices", alice.handle)).await.json().await.unwrap();
    let devices = body["devices"].as_array().unwrap();

    let served = devices
        .iter()
        .find(|d| d["id"] == tablet.id)
        .expect("the revoked device must stay listed, with its revocation");

    let revoked_at = served["revoked_at"].as_u64().expect("revocation timestamp missing");
    let certificate =
        BASE64_STANDARD.decode(served["revocation"].as_str().expect("certificate missing")).unwrap();
    let identity_key = BASE64_STANDARD.decode(body["identity_key"].as_str().unwrap()).unwrap();

    let claim = attest::RevocationClaim {
        handle: &alice.handle,
        device_id: &tablet.id,
        revoked_at,
    };
    assert!(
        attest::verify_revocation(&identity_key, &claim, &certificate).is_ok(),
        "the served certificate does not verify: a third party cannot observe the revocation",
    );

    // The active device carries neither of those two keys.
    let active = devices.iter().find(|d| d["id"] == laptop.id).unwrap();
    assert!(active.get("revoked_at").is_none());
    assert!(active.get("revocation").is_none());
}

/// The immediate leak: between the revocation and the MLS commit that actually evicts it, the
/// server stops serving envelopes to the revoked device.
///
/// Defence in depth only. The device still holds the group secrets and would decrypt anything
/// it obtained by another path — it is the MLS `Remove` that cuts it off from what follows, not
/// this filter.
#[tokio::test]
async fn a_revoked_device_no_longer_receives_envelopes() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, &unique("laptop")).await;
    let tablet = alice.device(&server, &unique("tablet")).await;

    let group_id = hex::encode(unique("group").as_bytes());
    laptop
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({ "device_ids": [laptop.id, tablet.id] }),
        )
        .await;

    // Before revocation, the tablet reads the group mailbox.
    assert!(
        tablet.get(&format!("/v1/groups/{group_id}/envelopes?after=0")).await.status().is_success()
    );

    assert!(alice.revoke(&laptop, &tablet.id).await.status().is_success());

    assert_eq!(
        tablet.get(&format!("/v1/groups/{group_id}/envelopes?after=0")).await.status(),
        403,
    );
    // The laptop is not affected.
    assert!(
        laptop.get(&format!("/v1/groups/{group_id}/envelopes?after=0")).await.status().is_success()
    );
}

/// The counterpart of `add_members`: a member removes a device from the broadcast list.
#[tokio::test]
async fn a_member_can_remove_a_device_from_the_broadcast_list() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let group_id = hex::encode(unique("group").as_bytes());
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    assert!(bob.get(&format!("/v1/groups/{group_id}/envelopes?after=0")).await.status().is_success());

    let response = alice
        .post(
            &format!("/v1/groups/{group_id}/members/remove"),
            serde_json::json!({ "device_ids": [bob.id] }),
        )
        .await;
    assert!(response.status().is_success());

    assert_eq!(bob.get(&format!("/v1/groups/{group_id}/envelopes?after=0")).await.status(), 403);
}

/// A non-member removes nobody: otherwise anyone would empty the broadcast list of any group
/// whose id they guess.
#[tokio::test]
async fn a_non_member_cannot_remove_anyone() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let intruder = Device::register(&server, &unique("intruder")).await;

    let group_id = hex::encode(unique("group").as_bytes());
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    let response = intruder
        .post(
            &format!("/v1/groups/{group_id}/members/remove"),
            serde_json::json!({ "device_ids": [bob.id] }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

// ---------------------------------------------------------------- authentication

#[tokio::test]
async fn an_unsigned_request_is_refused() {
    let server = start().await;
    let response = reqwest::Client::new()
        .get(format!("{}/v1/key-packages/stock", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn an_unknown_device_is_refused() {
    let server = start().await;
    // Perfectly valid signature, but the server does not know this key.
    let unknown = Device::new(&server, &unique("ghost"));
    assert_eq!(unknown.get("/v1/key-packages/stock").await.status(), 401);
}

#[tokio::test]
async fn an_expired_timestamp_is_refused() {
    let server = start().await;
    let device = Device::register(&server, &unique("device")).await;

    // The tolerance window is 60 s; two hours in the past must be rejected, otherwise a
    // captured request stays replayable indefinitely.
    let response = device
        .signed_at("GET", "/v1/key-packages/stock", Vec::new(), now() - 7200, "/v1/key-packages/stock")
        .await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn a_signature_valid_for_another_path_is_refused() {
    let server = start().await;
    let device = Device::register(&server, &unique("device")).await;

    // The path is part of the signed message: a signature captured on a harmless endpoint
    // must not be replayable on a sensitive one.
    let response = device
        .signed_at(
            "GET",
            "/v1/key-packages/stock",
            Vec::new(),
            now(),
            "/v1/some/other/path",
        )
        .await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn a_body_tampered_with_after_signing_is_refused() {
    let server = start().await;
    let device = Device::register(&server, &unique("device")).await;

    let signed = serde_json::to_vec(&serde_json::json!({ "packages": ["AAAA"] })).unwrap();
    let mut tampered = signed.clone();
    let last = tampered.len() - 3;
    tampered[last] ^= 0x01;

    // The body fingerprint is part of the signed message: intercepting a request and altering
    // its content in transit must invalidate the signature.
    let response = device
        .forge(
            "POST",
            "/v1/key-packages",
            tampered,
            signed,
            now(),
            "/v1/key-packages",
        )
        .await;
    assert_eq!(response.status(), 401);
}

// ---------------------------------------------------------------- key packages

#[tokio::test]
async fn a_key_package_is_consumed_only_once() {
    let server = start().await;
    let bob = Device::register(&server, &unique("bob")).await;
    let alice = Device::register(&server, &unique("alice")).await;

    let packages = vec![BASE64_STANDARD.encode(b"kp-1"), BASE64_STANDARD.encode(b"kp-2")];
    let response = bob
        .post("/v1/key-packages", serde_json::json!({ "packages": packages }))
        .await;
    assert!(response.status().is_success());

    let stock: serde_json::Value =
        bob.get("/v1/key-packages/stock").await.json().await.unwrap();
    assert_eq!(stock["remaining"], 2);

    // Two consumptions must return two *different* KeyPackages. Serving the same one twice
    // would share the same init key between two groups: the forward secrecy of the add falls.
    // OpenMLS does not prevent it — that is the server's responsibility.
    let claim = format!("/v1/key-packages/{}/claim", bob.id);
    let first: serde_json::Value = alice.post(&claim, serde_json::json!({})).await.json().await.unwrap();
    let second: serde_json::Value = alice.post(&claim, serde_json::json!({})).await.json().await.unwrap();

    assert_ne!(first["package"], second["package"]);
    assert_eq!(first["remaining"], 1);
    assert_eq!(second["remaining"], 0);

    // Stock exhausted: the server must say so clearly so the client replenishes.
    assert_eq!(alice.post(&claim, serde_json::json!({})).await.status(), 404);
}

#[tokio::test]
async fn concurrent_consumptions_never_share_a_key_package() {
    let server = start().await;
    let bob = Device::register(&server, &unique("bob")).await;

    const STOCK: usize = 20;
    let packages: Vec<String> = (0..STOCK)
        .map(|i| BASE64_STANDARD.encode(format!("kp-{i}")))
        .collect();
    bob.post("/v1/key-packages", serde_json::json!({ "packages": packages })).await;

    // The take goes through DELETE ... RETURNING over FOR UPDATE SKIP LOCKED. Under real
    // concurrency, two callers must never get the same package.
    let claim = format!("/v1/key-packages/{}/claim", bob.id);
    let mut handles = Vec::new();
    for i in 0..STOCK {
        let alice = Device::register(&server, &unique(&format!("alice-{i}"))).await;
        let claim = claim.clone();
        handles.push(tokio::spawn(async move {
            let response = alice.post(&claim, serde_json::json!({})).await;
            response.json::<serde_json::Value>().await.unwrap()["package"]
                .as_str()
                .map(str::to_owned)
        }));
    }

    let mut obtained = Vec::new();
    for handle in handles {
        if let Some(package) = handle.await.unwrap() {
            obtained.push(package);
        }
    }

    let distinct: std::collections::HashSet<_> = obtained.iter().collect();
    assert_eq!(obtained.len(), STOCK, "some consumptions failed");
    assert_eq!(distinct.len(), STOCK, "a key package was served twice");
}

// ---------------------------------------------------------------- access control

#[tokio::test]
async fn a_non_member_can_neither_read_nor_write() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let intruder = Device::register(&server, &unique("intruder")).await;

    let group_id = unique("group").into_bytes();
    alice
        .post(&group_path(&group_id, "/members"), serde_json::json!({ "device_ids": [alice.id] }))
        .await;

    // A group id is not a secret: knowing it must open nothing.
    let write = intruder
        .post(
            &group_path(&group_id, "/envelopes"),
            serde_json::json!({ "payload": BASE64_STANDARD.encode(b"hello") }),
        )
        .await;
    assert_eq!(write.status(), 403);

    let read = intruder.get(&group_path(&group_id, "/envelopes")).await;
    assert_eq!(read.status(), 403);

    // And it must not be able to add itself.
    let self_add = intruder
        .post(&group_path(&group_id, "/members"), serde_json::json!({ "device_ids": [intruder.id] }))
        .await;
    assert_eq!(self_add.status(), 403);
}

// ---------------------------------------------------------------- envelopes

#[tokio::test]
async fn envelopes_are_ordered_and_paginated() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let group_id = unique("group").into_bytes();
    alice
        .post(
            &group_path(&group_id, "/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    // MLS requires a total order: two members applying commits in different orders diverge in
    // epoch and can no longer read each other at all.
    for i in 0..5u8 {
        let response = alice
            .post(
                &group_path(&group_id, "/envelopes"),
                serde_json::json!({ "payload": BASE64_STANDARD.encode([i]) }),
            )
            .await;
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["seq"], i as i64 + 1, "non-monotonic sequence");
    }

    let all_of_them: Vec<serde_json::Value> =
        bob.get(&group_path(&group_id, "/envelopes")).await.json().await.unwrap();
    assert_eq!(all_of_them.len(), 5);

    // Cursor: only re-deliver what follows.
    let rest: Vec<serde_json::Value> = bob
        .get(&group_path(&group_id, "/envelopes?after=3"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(rest.len(), 2);
    assert_eq!(rest[0]["seq"], 4);
}

#[tokio::test]
async fn an_empty_envelope_is_refused() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let group_id = unique("group").into_bytes();
    alice
        .post(&group_path(&group_id, "/members"), serde_json::json!({ "device_ids": [alice.id] }))
        .await;

    let response = alice
        .post(&group_path(&group_id, "/envelopes"), serde_json::json!({ "payload": "" }))
        .await;
    assert_eq!(response.status(), 400);
}

// ---------------------------------------------------------------- the test that matters

/// Encrypts a real message with `crypto-core`, sends it through the server, then reads the
/// `envelopes` table **directly in SQL** to check that nothing shows through.
///
/// This is the only proof that counts. Everything else in the project — protocol, unit tests,
/// review — is worth nothing unless this one passes. It is automated precisely so that nobody
/// has to rely on an occasional manual inspection.
#[tokio::test]
async fn the_server_only_sees_ciphertext() {
    let server = start().await;

    // Real MLS identities, real group, real encryption.
    let alice_mls = Identity::create("alice@device-1").unwrap();
    let bob_mls = Identity::create("bob@device-1").unwrap();

    let mut alice_group = Conversation::create(&alice_mls).unwrap();
    let invitation = alice_group
        .invite(&alice_mls, &bob_mls.publish_key_package().unwrap())
        .unwrap();
    let tree = alice_group.apply_pending(&alice_mls).unwrap();
    let mut bob_group =
        Conversation::join(&bob_mls, &invitation.welcome, &tree).unwrap();

    const SECRET: &[u8] = b"the vault code is 4815162342";
    let ciphertext = alice_group.encrypt(&alice_mls, SECRET).unwrap();

    // Transit through the server.
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let group_id = alice_group.id();

    alice
        .post(
            &group_path(&group_id, "/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;
    let posted = alice
        .post(
            &group_path(&group_id, "/envelopes"),
            serde_json::json!({ "payload": BASE64_STANDARD.encode(&ciphertext) }),
        )
        .await;
    assert!(posted.status().is_success());

    // Reading the database directly, as an administrator, a stolen backup or a court order
    // would.
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT payload FROM envelopes WHERE group_id = $1")
        .bind(&group_id)
        .fetch_all(&server.pool)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    let stored = &rows[0].0;

    assert!(
        !stored.windows(SECRET.len()).any(|w| w == SECRET),
        "the plaintext is readable in the database"
    );
    assert!(
        !stored.windows(5).any(|w| w == b"alice"),
        "the sender identity is readable in the database"
    );

    // And the legitimate recipient must indeed be able to read it.
    let received: Vec<serde_json::Value> =
        bob.get(&group_path(&group_id, "/envelopes")).await.json().await.unwrap();
    let payload = BASE64_STANDARD
        .decode(received[0]["payload"].as_str().unwrap())
        .unwrap();

    match bob_group.process(&bob_mls, &payload, &Default::default()).unwrap() {
        crypto_core::Incoming::Application { plaintext, sender } => {
            assert_eq!(plaintext, SECRET);
            assert_eq!(sender.as_deref(), Some("alice@device-1"));
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[tokio::test]
async fn a_device_discovers_the_groups_it_was_added_to() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let stranger = Device::register(&server, &unique("stranger")).await;

    let group_id = unique("group").into_bytes();
    alice
        .post(
            &group_path(&group_id, "/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    // Bob was offline during the add: this is his only way of learning that this group exists
    // and of coming to fetch his Welcome.
    let groups: Vec<String> = bob.get("/v1/groups").await.json().await.unwrap();
    assert!(groups.contains(&hex::encode(&group_id)));

    // And a non-member device must see nothing of that group.
    let none_of_them: Vec<String> = stranger.get("/v1/groups").await.json().await.unwrap();
    assert!(!none_of_them.contains(&hex::encode(&group_id)));
}

/// The add Welcome exposes member identities — but never the content.
///
/// The MLS ratchet tree is **public by construction**: it contains the LeafNodes, hence the
/// credentials, hence the member names. It travels here in the clear from the server's point of
/// view, which already knows those identities from `devices` and `group_members` — so the leak
/// adds nothing to what it knows. But it is real, and a deployment aiming to hide metadata
/// (anonymous group ids, zero-knowledge credentials) would have to deal with it.
///
/// This test pins down both halves of the finding: the **content** is protected, the
/// **identity** is not. If the content ever shows up, CI breaks.
#[tokio::test]
async fn the_welcome_exposes_identities_but_never_the_content() {
    let server = start().await;

    let alice_mls = Identity::create("alice-canary@device").unwrap();
    let bob_mls = Identity::create("bob-canary@device").unwrap();

    let mut alice_group = Conversation::create(&alice_mls).unwrap();
    let invitation = alice_group
        .invite(&alice_mls, &bob_mls.publish_key_package().unwrap())
        .unwrap();
    let tree = alice_group.apply_pending(&alice_mls).unwrap();

    const SECRET: &[u8] = b"content-canary-4815162342";
    let ciphertext = alice_group.encrypt(&alice_mls, SECRET).unwrap();

    let alice = Device::register(&server, &unique("alice")).await;
    let group_id = alice_group.id();
    alice
        .post(&group_path(&group_id, "/members"), serde_json::json!({ "device_ids": [alice.id] }))
        .await;

    // The Welcome and the ratchet tree go through the same transport as the messages.
    for blob in [&invitation.welcome, &tree, &ciphertext] {
        let response = alice
            .post(
                &group_path(&group_id, "/envelopes"),
                serde_json::json!({ "payload": BASE64_STANDARD.encode(blob) }),
            )
            .await;
        assert!(response.status().is_success());
    }

    let rows: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT payload FROM envelopes WHERE group_id = $1")
        .bind(&group_id)
        .fetch_all(&server.pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);

    let contains = |pattern: &[u8]| {
        rows.iter()
            .any(|(payload,)| payload.windows(pattern.len()).any(|w| w == pattern))
    };

    // What must hold, whatever happens.
    assert!(!contains(SECRET), "the message content is readable in the database");

    // What leaks, and what we document rather than pretend otherwise.
    assert!(
        contains(b"alice-canary"),
        "the identity no longer appears in the ratchet tree: update this note"
    );
}

// ---------------------------------------------------------------- attachments

/// Prepares a two-member group and returns (owner, other member, group_id).
async fn group_with_two_members(server: &TestServer) -> (Device, Device, Vec<u8>) {
    let alice = Device::register(server, &unique("alice")).await;
    let bob = Device::register(server, &unique("bob")).await;
    let group_id = unique("group").into_bytes();

    alice
        .post(
            &group_path(&group_id, "/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    (alice, bob, group_id)
}

#[tokio::test]
async fn an_attachment_transits_without_being_readable() {
    let server = start().await;
    let (alice, bob, group_id) = group_with_two_members(&server).await;

    // The client encrypts before sending; the server only ever sees those bytes.
    const ENCRYPTED: &[u8] = b"\x00\x01this-is-already-encrypted\xff\xfe";

    let response = alice
        .forge(
            "POST",
            &group_path(&group_id, "/attachments"),
            ENCRYPTED.to_vec(),
            ENCRYPTED.to_vec(),
            now(),
            &group_path(&group_id, "/attachments"),
        )
        .await;
    assert!(response.status().is_success());

    let id = response.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Another member of the group gets exactly the same bytes back.
    let received = bob
        .get(&group_path(&group_id, &format!("/attachments/{id}")))
        .await;
    assert!(received.status().is_success());

    // The announced type must stay opaque: letting the browser guess would allow an SVG or an
    // HTML file to be rendered inline, hence to run script on this origin.
    assert_eq!(
        received.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
    assert_eq!(received.headers().get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(received.headers().get("content-disposition").unwrap(), "attachment");

    assert_eq!(received.bytes().await.unwrap().as_ref(), ENCRYPTED);

    // And nothing of the file is kept in the clear server-side: no name, no type, no key.
    let columns: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name::text FROM information_schema.columns WHERE table_name = 'attachments'",
    )
    .fetch_all(&server.pool)
    .await
    .unwrap();
    let names: Vec<String> = columns.into_iter().map(|(c,)| c).collect();
    assert_eq!(names.len(), 4, "unexpected columns on attachments: {names:?}");
    for forbidden in ["name", "filename", "mime", "content_type", "key"] {
        assert!(!names.iter().any(|c| c == forbidden), "{forbidden} must not be stored");
    }
}

#[tokio::test]
async fn a_non_member_can_neither_upload_nor_download() {
    let server = start().await;
    let (alice, _bob, group_id) = group_with_two_members(&server).await;
    let intruder = Device::register(&server, &unique("intruder")).await;

    let encrypted = b"blob".to_vec();
    let path = group_path(&group_id, "/attachments");
    let id = alice
        .forge("POST", &path, encrypted.clone(), encrypted.clone(), now(), &path)
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let upload = intruder
        .forge("POST", &path, encrypted.clone(), encrypted, now(), &path)
        .await;
    assert_eq!(upload.status(), 403);

    let read = intruder
        .get(&group_path(&group_id, &format!("/attachments/{id}")))
        .await;
    assert_eq!(read.status(), 403);
}

#[tokio::test]
async fn an_attachment_is_not_reachable_from_another_group() {
    let server = start().await;
    let (alice, _bob, group_id) = group_with_two_members(&server).await;

    let encrypted = b"secret-of-group-1".to_vec();
    let path = group_path(&group_id, "/attachments");
    let id = alice
        .forge("POST", &path, encrypted.clone(), encrypted, now(), &path)
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Alice creates a second group she is also a member of, then tries to read the first
    // group's attachment from it. The `group_id` is part of the SQL clause: without it, a
    // member could siphon other groups' files by guessing ids.
    let other_group = unique("other").into_bytes();
    alice
        .post(
            &group_path(&other_group, "/members"),
            serde_json::json!({ "device_ids": [alice.id] }),
        )
        .await;

    let theft = alice
        .get(&group_path(&other_group, &format!("/attachments/{id}")))
        .await;
    assert_eq!(theft.status(), 404);
}

#[tokio::test]
async fn an_empty_attachment_is_refused() {
    let server = start().await;
    let (alice, _bob, group_id) = group_with_two_members(&server).await;
    let path = group_path(&group_id, "/attachments");

    let response = alice
        .forge("POST", &path, Vec::new(), Vec::new(), now(), &path)
        .await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn a_malformed_attachment_id_is_refused() {
    let server = start().await;
    let (alice, _bob, group_id) = group_with_two_members(&server).await;

    // The id comes from the URL: it must be validated as a UUID before reaching the database,
    // and an absurd value must produce a clear error, not an SQL error.
    let response = alice
        .get(&group_path(&group_id, "/attachments/not-a-uuid"))
        .await;
    assert_eq!(response.status(), 400);
}

// ---------------------------------------------------------------- pairing
#[tokio::test]
async fn the_pairing_packet_can_only_be_picked_up_once() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, "desktop").await;

    // Unique id: the database persists between runs, and a fixed id would already be taken on
    // the second `cargo test`.
    let id = hex::encode(&sha2::Sha256::digest(unique("pairing").as_bytes())[..16]);
    let packet = BASE64_STANDARD.encode(b"sealed packet, opaque to the server");

    let response = laptop
        .post(&format!("/v1/pairings/{id}"), serde_json::json!({ "payload": packet }))
        .await;
    assert!(response.status().is_success());

    // The pickup is unsigned: the new device has no identity yet. Security rests on the
    // encryption of the packet, not on authenticating the request.
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/v1/pairings/{id}", server.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["payload"], packet);

    // A second pickup succeeding would mean a third party could have grabbed the packet.
    let response = reqwest::Client::new()
        .get(format!("{}/v1/pairings/{id}", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
}

/// An id already taken must not be overwritten: otherwise a malicious device replaces the
/// legitimate packet while the user is looking at their QR code.
#[tokio::test]
async fn a_pairing_id_cannot_be_overwritten() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, "desktop").await;
    let id = hex::encode(&sha2::Sha256::digest(unique("pairing").as_bytes())[..16]);

    let first = serde_json::json!({ "payload": BASE64_STANDARD.encode(b"legitimate") });
    assert!(laptop.post(&format!("/v1/pairings/{id}"), first).await.status().is_success());

    let second = serde_json::json!({ "payload": BASE64_STANDARD.encode(b"hostile") });
    assert_eq!(laptop.post(&format!("/v1/pairings/{id}"), second).await.status(), 409);
}

#[tokio::test]
async fn posting_a_pairing_requires_a_signature() {
    let server = start().await;
    let id = hex::encode(&sha2::Sha256::digest(unique("pairing").as_bytes())[..16]);

    let response = reqwest::Client::new()
        .post(format!("{}/v1/pairings/{id}", server.base_url))
        .json(&serde_json::json!({ "payload": BASE64_STANDARD.encode(b"x") }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
}

/// The stored packet must be opaque: it contains the account seed, and a server able to read it
/// would hold every account.
#[tokio::test]
async fn the_server_only_sees_a_pairing_blob() {
    use crypto_core::pairing::{PairingOffer, seal};

    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, "desktop").await;

    let offer = PairingOffer::generate();
    let secret = b"ACCOUNT-SEED-4815162342";
    let (packet, code) = seal(&offer.public_key(), &offer.id(), secret).unwrap();

    let id = hex::encode(offer.id());
    laptop
        .post(
            &format!("/v1/pairings/{id}"),
            serde_json::json!({ "payload": BASE64_STANDARD.encode(&packet) }),
        )
        .await;

    let (stored,): (Vec<u8>,) = sqlx::query_as("SELECT payload FROM pairings WHERE id = $1")
        .bind(offer.id().as_slice())
        .fetch_one(&server.pool)
        .await
        .unwrap();

    assert!(
        !stored.windows(secret.len()).any(|w| w == secret),
        "the account seed appears in the clear in the database",
    );

    // And the legitimate recipient does open it.
    let opened = offer.open(&stored).unwrap();
    assert_eq!(opened.plaintext, secret);
    assert_eq!(opened.confirmation, code);
}

// ---------------------------------------------------------------- history vault

#[tokio::test]
async fn the_vault_is_private_to_its_account() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let bob = TestAccount::create(&server, &unique("bob")).await;
    let alice_desktop = alice.device(&server, "desktop").await;
    let bob_desktop = bob.device(&server, "desktop").await;

    // A shared group: both are members of it.
    let group = hex::encode(unique("g").as_bytes());
    alice_desktop
        .post(
            &format!("/v1/groups/{group}/members"),
            serde_json::json!({ "device_ids": [bob_desktop.id] }),
        )
        .await;

    let secret = BASE64_STANDARD.encode(b"alice's encrypted archive");
    let response = alice_desktop
        .post(
            &format!("/v1/vault/{group}"),
            serde_json::json!({ "entries": [{ "seq": 1, "payload": secret }] }),
        )
        .await;
    assert!(response.status().is_success(), "deposit refused");

    // Alice finds her entry again.
    let mine: serde_json::Value =
        alice_desktop.get(&format!("/v1/vault/{group}")).await.json().await.unwrap();
    assert_eq!(mine.as_array().unwrap().len(), 1);
    assert_eq!(mine[0]["payload"], secret);

    // Bob, a member of the **same group**, sees nothing: the vault is indexed by account.
    // Otherwise a correspondent would read the other's backups long after the conversation.
    let theirs: serde_json::Value =
        bob_desktop.get(&format!("/v1/vault/{group}")).await.json().await.unwrap();
    assert!(theirs.as_array().unwrap().is_empty(), "bob read alice's vault");
}

/// Two devices of the same account archive the same conversation: the deposits must overlay
/// without conflict, and the history stay readable from both.
#[tokio::test]
async fn depositing_into_the_vault_is_idempotent() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let desktop = alice.device(&server, "desktop").await;
    let tablet = alice.device(&server, "mobile").await;

    let group = hex::encode(unique("g").as_bytes());
    desktop
        .post(
            &format!("/v1/groups/{group}/members"),
            serde_json::json!({ "device_ids": [tablet.id] }),
        )
        .await;

    let entry = serde_json::json!({ "entries": [{ "seq": 7, "payload": BASE64_STANDARD.encode(b"m") }] });
    assert!(desktop.post(&format!("/v1/vault/{group}"), entry.clone()).await.status().is_success());
    assert!(tablet.post(&format!("/v1/vault/{group}"), entry).await.status().is_success());

    let rows: serde_json::Value =
        tablet.get(&format!("/v1/vault/{group}")).await.json().await.unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "the entry was duplicated");
}

/// The vault is not free storage: you have to be a member of the group you archive.
#[tokio::test]
async fn archiving_a_group_you_are_not_a_member_of_is_refused() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let desktop = alice.device(&server, "desktop").await;

    let response = desktop
        .post(
            &format!("/v1/vault/{}", hex::encode(unique("stranger").as_bytes())),
            serde_json::json!({ "entries": [{ "seq": 1, "payload": BASE64_STANDARD.encode(b"x") }] }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

/// The server must be able to read nothing of the vault: it does not hold the recovery phrase
/// the key is derived from.
#[tokio::test]
async fn the_server_only_sees_ciphertext_in_the_vault() {
    use crypto_core::Account;

    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let desktop = alice.device(&server, "desktop").await;

    let group = hex::encode(unique("g").as_bytes());
    desktop
        .post(
            &format!("/v1/groups/{group}/members"),
            serde_json::json!({ "device_ids": [desktop.id] }),
        )
        .await;

    // Encryption under the vault key, exactly as the client does it.
    let (account, _phrase) = Account::generate().unwrap();
    let key = account.vault_key();
    const SECRET: &[u8] = b"archive-canary-4815162342";

    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let ciphertext = cipher.encrypt(Nonce::from_slice(&[0u8; 12]), SECRET).unwrap();

    desktop
        .post(
            &format!("/v1/vault/{group}"),
            serde_json::json!({ "entries": [{ "seq": 1, "payload": BASE64_STANDARD.encode(&ciphertext) }] }),
        )
        .await;

    let (stored,): (Vec<u8>,) =
        sqlx::query_as("SELECT payload FROM vault_entries WHERE handle = $1")
            .bind(&alice.handle)
            .fetch_one(&server.pool)
            .await
            .unwrap();

    assert!(
        !stored.windows(SECRET.len()).any(|w| w == SECRET),
        "the archived content appears in the clear in the database",
    );
}

// ---------------------------------------------------------------- account rotation

/// **The test that matters for rotation.**
///
/// Every device of an account holds the seed — that is parity. A stolen device therefore holds
/// the account, and revoking it is pointless: whoever carries it attests a new one.
///
/// Rotation, on the other hand, has a mechanical effect: by changing the account key, it makes
/// **every existing attestation unverifiable**. Total revocation is not a separate mechanism,
/// it is a consequence — and that is what this test establishes.
#[tokio::test]
async fn a_rotation_invalidates_every_existing_attestation() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, &unique("laptop")).await;
    let _stolen = alice.device(&server, &unique("stolen")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    // Before rotation: both devices pass the verification any client performs.
    let before: serde_json::Value =
        bob.get(&format!("/v1/accounts/{}/devices", alice.handle)).await.json().await.unwrap();
    assert_eq!(verifiable_devices(&before), 2);

    // Alice rotates from her laptop.
    let (new_one, _phrase) = crypto_core::Account::generate().unwrap();
    let rotated_at = common::now();
    let signature = alice
        .account
        .rotate(&alice.handle, &new_one.identity_key(), rotated_at)
        .unwrap();

    let response = laptop
        .post(
            &format!("/v1/accounts/{}/rotate", alice.handle),
            serde_json::json!({
                "new_identity_key": BASE64_STANDARD.encode(new_one.identity_key()),
                "rotation": BASE64_STANDARD.encode(signature),
                "rotated_at": rotated_at,
            }),
        )
        .await;
    assert!(response.status().is_success(), "legitimate rotation refused");

    // NO attestation verifies any more: neither the stolen device's, nor even the laptop's,
    // which has to re-attest itself.
    let after: serde_json::Value =
        bob.get(&format!("/v1/accounts/{}/devices", alice.handle)).await.json().await.unwrap();
    assert_eq!(
        verifiable_devices(&after),
        0,
        "an attestation survived the rotation: the stolen device is still recognised",
    );

    // The laptop re-attests under the new key, and only it can — the stolen device could too if
    // it held the new seed, which it does not.
    let auth_key = BASE64_STANDARD.decode(laptop.public_key_b64()).unwrap();
    let reattestation = new_one
        .attest(&alice.handle, &laptop.id, &auth_key, laptop.mls_key())
        .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/devices", server.base_url))
        .json(&serde_json::json!({
            "id": laptop.id,
            "handle": alice.handle,
            "auth_key": BASE64_STANDARD.encode(&auth_key),
            "mls_key": BASE64_STANDARD.encode(laptop.mls_key()),
            "attestation": BASE64_STANDARD.encode(reattestation),
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "re-attestation refused after rotation");

    let final_: serde_json::Value =
        bob.get(&format!("/v1/accounts/{}/devices", alice.handle)).await.json().await.unwrap();
    assert_eq!(verifiable_devices(&final_), 1, "only the re-attested device must be recognised");
}

/// Counts the devices whose attestation verifies against the account's current key — that is,
/// exactly what a client does on every read.
fn verifiable_devices(body: &serde_json::Value) -> usize {
    let handle = body["handle"].as_str().unwrap();
    let identity_key = BASE64_STANDARD.decode(body["identity_key"].as_str().unwrap()).unwrap();

    body["devices"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| {
            let claim = attest::DeviceClaim {
                handle,
                device_id: d["id"].as_str().unwrap(),
                auth_key: &BASE64_STANDARD.decode(d["auth_key"].as_str().unwrap()).unwrap(),
                mls_key: &BASE64_STANDARD.decode(d["mls_key"].as_str().unwrap()).unwrap(),
            };
            let attestation =
                BASE64_STANDARD.decode(d["attestation"].as_str().unwrap()).unwrap();
            attest::verify(&identity_key, &claim, &attestation).is_ok()
        })
        .count()
}

/// Without proven continuity, any account would take over someone else's handle.
#[tokio::test]
async fn a_third_party_cannot_rotate_an_account() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, &unique("laptop")).await;

    let mallory = TestAccount::create(&server, &unique("mallory")).await;
    let (target, _) = crypto_core::Account::generate().unwrap();
    let rotated_at = common::now();
    let signature =
        mallory.account.rotate(&alice.handle, &target.identity_key(), rotated_at).unwrap();

    let response = laptop
        .post(
            &format!("/v1/accounts/{}/rotate", alice.handle),
            serde_json::json!({
                "new_identity_key": BASE64_STANDARD.encode(target.identity_key()),
                "rotation": BASE64_STANDARD.encode(signature),
                "rotated_at": rotated_at,
            }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

/// A device from another account has no business here, even carrying a valid signature.
#[tokio::test]
async fn a_foreign_device_cannot_trigger_the_rotation() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let _laptop = alice.device(&server, &unique("laptop")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let (new_one, _) = crypto_core::Account::generate().unwrap();
    let rotated_at = common::now();
    let signature =
        alice.account.rotate(&alice.handle, &new_one.identity_key(), rotated_at).unwrap();

    let response = bob
        .post(
            &format!("/v1/accounts/{}/rotate", alice.handle),
            serde_json::json!({
                "new_identity_key": BASE64_STANDARD.encode(new_one.identity_key()),
                "rotation": BASE64_STANDARD.encode(signature),
                "rotated_at": rotated_at,
            }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

// ---------------------------------------------------------------- transparency log

/// A served account key must be provable in the log, and the client must be able to check it
/// **on its own** — that is the whole point of the mechanism.
#[tokio::test]
async fn an_account_key_is_provable_in_the_log() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let reader = Device::register(&server, &unique("reader")).await;

    let body: serde_json::Value = reader
        .get(&format!("/v1/log/proof/{}", alice.handle))
        .await
        .json()
        .await
        .unwrap();

    let head = &body["head"];
    let log_key = BASE64_STANDARD.decode(head["log_key"].as_str().unwrap()).unwrap();
    let root: [u8; 32] =
        BASE64_STANDARD.decode(head["root"].as_str().unwrap()).unwrap().try_into().unwrap();
    let signature = BASE64_STANDARD.decode(head["signature"].as_str().unwrap()).unwrap();
    let size = head["size"].as_u64().unwrap();

    // The head does come from the log.
    let sth = transparency::TreeHead { size, root, timestamp: head["timestamp"].as_u64().unwrap() };
    assert!(sth.verify(&log_key, &signature).is_ok(), "head not signed by the log");

    // And the served key is in it, at the announced index.
    let identity_key = BASE64_STANDARD.decode(body["identity_key"].as_str().unwrap()).unwrap();
    assert_eq!(identity_key, alice.account.identity_key());

    let leaf = transparency::leaf_hash(&transparency::entry(&alice.handle, &identity_key));
    let proof: Vec<[u8; 32]> = body["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| BASE64_STANDARD.decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
        .collect();

    assert_eq!(
        transparency::verify_inclusion(
            &leaf,
            body["index"].as_u64().unwrap() as usize,
            size as usize,
            &proof,
            &root,
        ),
        Ok(()),
        "the served inclusion proof does not verify",
    );
}

/// **The test that matters for transparency.**
///
/// A server substituting an account key on first contact — the attack attestations do not cover
/// — cannot produce an inclusion proof for it: it is not in the tree. Without that property,
/// the log would be decorative.
#[tokio::test]
async fn a_substituted_key_does_not_appear_in_the_log() {
    let server = start().await;
    let bob = TestAccount::create(&server, &unique("bob")).await;
    let alice = Device::register(&server, &unique("alice")).await;

    let body: serde_json::Value =
        alice.get(&format!("/v1/log/proof/{}", bob.handle)).await.json().await.unwrap();

    let head = &body["head"];
    let root: [u8; 32] =
        BASE64_STANDARD.decode(head["root"].as_str().unwrap()).unwrap().try_into().unwrap();
    let proof: Vec<[u8; 32]> = body["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| BASE64_STANDARD.decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
        .collect();

    // The server tries to pass its own key off as Bob's, reusing the legitimate proof — the
    // only one it has.
    let (impostor, _) = crypto_core::Account::generate().unwrap();
    let forged_leaf =
        transparency::leaf_hash(&transparency::entry(&bob.handle, &impostor.identity_key()));

    assert!(
        transparency::verify_inclusion(
            &forged_leaf,
            body["index"].as_u64().unwrap() as usize,
            head["size"].as_u64().unwrap() as usize,
            &proof,
            &root,
        )
        .is_err(),
        "a substituted key passed inclusion verification: the log proves nothing",
    );
}

/// A rotation **appends** to the log. The old key stays in it: that is what makes it possible
/// to observe that an identity changed rather than see it disappear.
#[tokio::test]
async fn a_rotation_appends_to_the_log_without_erasing_anything() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let laptop = alice.device(&server, &unique("laptop")).await;

    let before: serde_json::Value =
        laptop.get("/v1/log/sth").await.json().await.unwrap();
    let size_before = before["size"].as_u64().unwrap();

    let (new_one, _) = crypto_core::Account::generate().unwrap();
    let rotated_at = common::now();
    let signature =
        alice.account.rotate(&alice.handle, &new_one.identity_key(), rotated_at).unwrap();

    let response = laptop
        .post(
            &format!("/v1/accounts/{}/rotate", alice.handle),
            serde_json::json!({
                "new_identity_key": BASE64_STANDARD.encode(new_one.identity_key()),
                "rotation": BASE64_STANDARD.encode(signature),
                "rotated_at": rotated_at,
            }),
        )
        .await;
    assert!(response.status().is_success());

    let after: serde_json::Value = laptop.get("/v1/log/sth").await.json().await.unwrap();
    assert!(
        after["size"].as_u64().unwrap() > size_before,
        "the rotation appended nothing to the log",
    );

    // And it is indeed the NEW key that is now proven.
    let proof: serde_json::Value =
        laptop.get(&format!("/v1/log/proof/{}", alice.handle)).await.json().await.unwrap();
    assert_eq!(
        BASE64_STANDARD.decode(proof["identity_key"].as_str().unwrap()).unwrap(),
        new_one.identity_key(),
    );
}

/// The log must prove that it extends what the client already saw, without rewriting.
#[tokio::test]
async fn the_log_proves_its_consistency_over_time() {
    let server = start().await;
    let reader = Device::register(&server, &unique("reader")).await;

    let before: serde_json::Value = reader.get("/v1/log/sth").await.json().await.unwrap();
    let size_before = before["size"].as_u64().unwrap() as usize;
    let root_before: [u8; 32] =
        BASE64_STANDARD.decode(before["root"].as_str().unwrap()).unwrap().try_into().unwrap();

    // The log grows.
    for _ in 0..3 {
        TestAccount::create(&server, &unique("new")).await;
    }

    let body: serde_json::Value = reader
        .get(&format!("/v1/log/consistency?from={size_before}"))
        .await
        .json()
        .await
        .unwrap();

    let head = &body["head"];
    let root_after: [u8; 32] =
        BASE64_STANDARD.decode(head["root"].as_str().unwrap()).unwrap().try_into().unwrap();
    let proof: Vec<[u8; 32]> = body["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| BASE64_STANDARD.decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
        .collect();

    assert_eq!(
        transparency::verify_consistency(
            size_before,
            &root_before,
            head["size"].as_u64().unwrap() as usize,
            &root_after,
            &proof,
        ),
        Ok(()),
        "the log does not prove that it extends the previous head",
    );
}

// ---------------------------------------------------------------- anonymous post

/// Posts an envelope without a device signature, using the group MAC.
async fn anonymous_post(
    server: &TestServer,
    group_id: &str,
    posting_key: &[u8],
    payload: &[u8],
    nonce: [u8; 16],
) -> reqwest::Response {
    use hmac::{Hmac, Mac};

    let body = serde_json::to_vec(&serde_json::json!({
        "payload": BASE64_STANDARD.encode(payload),
    }))
    .unwrap();

    let group = hex::decode(group_id).unwrap();
    let message =
        attest::post_message(&group, &nonce, &sha2::Sha256::digest(&body)).unwrap();

    let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(posting_key).unwrap();
    mac.update(&message);

    reqwest::Client::new()
        .post(format!("{}/v1/groups/{group_id}/envelopes", server.base_url))
        .header("content-type", "application/octet-stream")
        .header("x-group-nonce", BASE64_STANDARD.encode(nonce))
        .header("x-group-mac", BASE64_STANDARD.encode(mac.finalize().into_bytes()))
        .body(body)
        .send()
        .await
        .unwrap()
}

/// **The test that matters for sealed sender.**
///
/// The post succeeds **without any device signature**: no `x-device-id`, no `x-signature`, no
/// timestamp. The server cannot tell which of the members wrote — it only knows the poster
/// holds the group key, which is all it needs.
#[tokio::test]
async fn an_anonymous_post_succeeds_without_identifying_the_sender() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let group_id = hex::encode(unique("group").as_bytes());
    let posting_key = [42u8; 32];

    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({
                "device_ids": [alice.id],
                "posting_key": BASE64_STANDARD.encode(posting_key),
            }),
        )
        .await;

    let response =
        anonymous_post(&server, &group_id, &posting_key, b"envelope", [1u8; 16]).await;
    assert!(response.status().is_success(), "anonymous post refused: {:?}", response.status());

    // And the envelope is there, readable by the members.
    let envelopes: serde_json::Value = alice
        .get(&format!("/v1/groups/{group_id}/envelopes?after=0"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(envelopes.as_array().unwrap().len(), 1);
}

/// Without the key, the anonymous post is refused: the server is not an open mailbox. That is
/// the only thing the MAC has to guarantee, and it must guarantee it.
#[tokio::test]
async fn an_anonymous_post_without_the_key_is_refused() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let group_id = hex::encode(unique("group").as_bytes());
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({
                "device_ids": [alice.id],
                "posting_key": BASE64_STANDARD.encode([42u8; 32]),
            }),
        )
        .await;

    let response =
        anonymous_post(&server, &group_id, &[7u8; 32], b"intrusion", [2u8; 16]).await;
    assert_eq!(response.status(), 403);
}

/// **Anti-replay.** The MAC does not depend on any timestamp: without nonce uniqueness, whoever
/// intercepts a post replays it indefinitely.
#[tokio::test]
async fn an_anonymous_post_cannot_be_replayed() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let group_id = hex::encode(unique("group").as_bytes());
    let posting_key = [42u8; 32];
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({
                "device_ids": [alice.id],
                "posting_key": BASE64_STANDARD.encode(posting_key),
            }),
        )
        .await;

    let nonce = [3u8; 16];
    assert!(
        anonymous_post(&server, &group_id, &posting_key, b"once", nonce)
            .await
            .status()
            .is_success()
    );

    assert_eq!(
        anonymous_post(&server, &group_id, &posting_key, b"once", nonce).await.status(),
        403,
        "a replayed post was accepted",
    );
}

/// The `group_id` goes into the MAC: without it, an intercepted post would replay into any
/// other group sharing the key.
#[tokio::test]
async fn a_mac_is_only_valid_for_its_own_group() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let posting_key = [42u8; 32];
    let first = hex::encode(unique("group-a").as_bytes());
    let second = hex::encode(unique("group-b").as_bytes());

    for group_id in [&first, &second] {
        alice
            .post(
                &format!("/v1/groups/{group_id}/members"),
                serde_json::json!({
                    "device_ids": [alice.id],
                    "posting_key": BASE64_STANDARD.encode(posting_key),
                }),
            )
            .await;
    }

    // MAC computed for the first group, presented to the second.
    use hmac::{Hmac, Mac};
    let body =
        serde_json::to_vec(&serde_json::json!({ "payload": BASE64_STANDARD.encode(b"x") })).unwrap();
    let nonce = [4u8; 16];
    let message = attest::post_message(
        &hex::decode(&first).unwrap(),
        &nonce,
        &sha2::Sha256::digest(&body),
    )
    .unwrap();
    let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(&posting_key).unwrap();
    mac.update(&message);

    let response = reqwest::Client::new()
        .post(format!("{}/v1/groups/{second}/envelopes", server.base_url))
        .header("content-type", "application/octet-stream")
        .header("x-group-nonce", BASE64_STANDARD.encode(nonce))
        .header("x-group-mac", BASE64_STANDARD.encode(mac.finalize().into_bytes()))
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
}

/// A group without a posting key refuses the anonymous path rather than silently falling back
/// to the signed one: a client that believes it is anonymous without being so is worse than a
/// client that fails.
#[tokio::test]
async fn a_group_without_a_key_refuses_the_anonymous_post() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let group_id = hex::encode(unique("group").as_bytes());
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({ "device_ids": [alice.id] }),
        )
        .await;

    let response = anonymous_post(&server, &group_id, &[9u8; 32], b"x", [5u8; 16]).await;
    assert_eq!(response.status(), 403);
}

// ---------------------------------------------------------------- ephemeral signals

/// Posts an ephemeral signal, with the group MAC and without a device signature.
async fn post_signal(
    server: &TestServer,
    group_id: &str,
    posting_key: &[u8],
    payload: &[u8],
    nonce: [u8; 16],
) -> reqwest::Response {
    use hmac::{Hmac, Mac};

    let group = hex::decode(group_id).unwrap();
    let message = attest::signal_message(&group, &nonce, &sha2::Sha256::digest(payload)).unwrap();

    let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(posting_key).unwrap();
    mac.update(&message);

    reqwest::Client::new()
        .post(format!("{}/v1/groups/{group_id}/signals", server.base_url))
        .header("content-type", "application/octet-stream")
        .header("x-group-nonce", BASE64_STANDARD.encode(nonce))
        .header("x-group-mac", BASE64_STANDARD.encode(mac.finalize().into_bytes()))
        .body(payload.to_vec())
        .send()
        .await
        .unwrap()
}

/// Prepares a group equipped with a posting key, and returns its id.
async fn group_with_key(alice: &Device, posting_key: &[u8]) -> String {
    let group_id = hex::encode(unique("group").as_bytes());
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({
                "device_ids": [alice.id],
                "posting_key": BASE64_STANDARD.encode(posting_key),
            }),
        )
        .await;
    group_id
}

/// **The test that matters for signals: nothing reaches the disk.**
///
/// This is the property that justifies having a separate route. The `envelopes` table is never
/// purged — and cannot be without punching a hole in the application ratchet — so a typing
/// indicator that got in would never come out again.
#[tokio::test]
async fn a_signal_leaves_no_trace_in_the_database() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let posting_key = [42u8; 32];
    let group_id = group_with_key(&alice, &posting_key).await;

    let response = post_signal(&server, &group_id, &posting_key, b"signal", [7u8; 16]).await;
    assert_eq!(response.status(), 204, "the signal was refused");

    let group = hex::decode(&group_id).unwrap();

    let (envelopes,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM envelopes WHERE group_id = $1")
            .bind(&group)
            .fetch_one(&server.pool)
            .await
            .unwrap();
    assert_eq!(envelopes, 0, "a signal was kept as an envelope");

    // No nonce consumed either: anti-replay is deliberately absent from this path, and adding it
    // there by mistake would grow a table every three seconds.
    let (nonces,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM posting_nonces WHERE group_id = $1")
            .bind(&group)
            .fetch_one(&server.pool)
            .await
            .unwrap();
    assert_eq!(nonces, 0, "the ephemeral channel must write nothing, not even a nonce");
}

/// Without the group MAC, the server is not an open relay: anyone could otherwise make a whole
/// conversation believe someone is typing.
#[tokio::test]
async fn a_signal_with_an_invalid_mac_is_refused() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let group_id = group_with_key(&alice, &[42u8; 32]).await;

    let response = post_signal(&server, &group_id, &[9u8; 32], b"signal", [7u8; 16]).await;
    assert_eq!(response.status(), 403);
}

/// An envelope-posting MAC is not valid as a signal MAC.
///
/// Both share the same key; only the domain of the canonical message separates them. Without
/// that separation, a captured signal — which has no anti-replay — would be replayable as a
/// post.
#[tokio::test]
async fn the_mac_of_a_post_is_not_valid_for_a_signal() {
    use hmac::{Hmac, Mac};

    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let posting_key = [42u8; 32];
    let group_id = group_with_key(&alice, &posting_key).await;

    let group = hex::decode(&group_id).unwrap();
    let nonce = [7u8; 16];
    let body = b"signal";

    // The MAC is computed in the post domain, not in the signal one.
    let message = attest::post_message(&group, &nonce, &sha2::Sha256::digest(body)).unwrap();
    let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(&posting_key).unwrap();
    mac.update(&message);

    let response = reqwest::Client::new()
        .post(format!("{}/v1/groups/{group_id}/signals", server.base_url))
        .header("x-group-nonce", BASE64_STANDARD.encode(nonce))
        .header("x-group-mac", BASE64_STANDARD.encode(mac.finalize().into_bytes()))
        .body(body.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
}

// ---------------------------------------------------------------- presence

/// Brings a device online, then waits for the database to record it.
///
/// # Why a session, and no longer a request
///
/// Presence used to be a side effect of the `Signed` extractor: any signed request was enough.
/// It is now fed by the gateway heartbeat, which is a truer signal — an open session says a
/// client is there, where a request may come from a forgotten tab.
///
/// The socket is **kept open** during the wait: closing it right away would not change the
/// value written, but would race the test against the server-side close.
async fn bring_online(server: &TestServer, device: &Device) -> Option<i64> {
    let mut socket = common::session(server, device, serde_json::json!([])).await;
    assert_eq!(common::read_frame(&mut socket).await.unwrap()["op"], "ready");

    // One heartbeat, because that is what writes presence — not the server tick. An open
    // session proves nothing: a suspended phone's socket stays open until `SILENCE_MAX`, and
    // the server would declare awake someone who no longer is.
    common::send_frame(&mut socket, serde_json::json!({ "op": "heartbeat" })).await;
    assert_eq!(common::read_frame(&mut socket).await.unwrap()["op"], "heartbeat_ack");

    let seen = wait_for_presence(&server.pool, &device.id).await;
    drop(socket);
    seen
}

/// Waits for a spawned presence write to reach the database, or gives up.
///
/// The touch is detached — it must not slow down what triggers it — so a test reading the column
/// right after races with it. Polling is more honest than an arbitrary `sleep`: the test passes
/// as soon as the value arrives, and fails plainly otherwise.
async fn wait_for_presence(pool: &sqlx::PgPool, device_id: &str) -> Option<i64> {
    for _ in 0..40 {
        let row: Option<(Option<i64>,)> = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM last_seen_at)::BIGINT FROM devices WHERE id = $1",
        )
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .unwrap();

        if let Some((Some(seen),)) = row {
            return Some(seen);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    None
}

async fn last_presence(pool: &sqlx::PgPool, device_id: &str) -> Option<i64> {
    let (seen,): (Option<i64>,) = sqlx::query_as(
        "SELECT EXTRACT(EPOCH FROM last_seen_at)::BIGINT FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await
    .unwrap();
    seen
}

async fn forget_presence(pool: &sqlx::PgPool, device_id: &str) {
    sqlx::query("UPDATE devices SET last_seen_at = NULL WHERE id = $1")
        .bind(device_id)
        .execute(pool)
        .await
        .unwrap();
}

/// **The test that protects sealed sender.**
///
/// Anonymous posts and typing signals prove group membership with a MAC, not identity: the
/// server does not know who posts. Deriving presence from them would amount to telling it —
/// that is, undoing what migration 0007 put in place.
///
/// The protection rests today on a single line: in `post_envelope`, the `Signed` extractor is
/// only built in the signed branch. That is correct, and free; this test exists so that it
/// stays that way.
#[tokio::test]
async fn an_anonymous_post_never_updates_presence() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let posting_key = [42u8; 32];
    let group_id = group_with_key(&alice, &posting_key).await;

    // We first bring the device online for real, then clear it: without that step, a
    // `last_seen_at` left null would make the test green whatever happens, including if presence
    // had stopped working entirely.
    bring_online(&server, &alice).await.expect("the session recorded nothing");
    forget_presence(&server.pool, &alice.id).await;

    let post = anonymous_post(&server, &group_id, &posting_key, b"ciphertext", [1u8; 16]).await;
    assert!(post.status().is_success(), "the anonymous post was refused");

    let signal = post_signal(&server, &group_id, &posting_key, b"typing", [2u8; 16]).await;
    assert_eq!(signal.status(), 204, "the signal was refused");

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(
        last_presence(&server.pool, &alice.id).await,
        None,
        "an anonymous path marked presence: sealed sender no longer holds",
    );
}

/// **The test that pins down the new presence trigger.**
///
/// An open session brings a device online; a signed request does not. This is a deliberate
/// behaviour change — see the `server::auth` header — not an invisible optimisation: a client
/// that queries the server without ever opening a session stays offline.
#[tokio::test]
async fn only_a_session_marks_the_device_online() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    // Registration is not signed: this device has never been seen yet.
    assert_eq!(last_presence(&server.pool, &alice.id).await, None);

    // Signed requests, plenty of them, without a session: the column must stay empty.
    for _ in 0..3 {
        alice.get("/v1/groups").await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(
        last_presence(&server.pool, &alice.id).await,
        None,
        "presence went back to the request latency path",
    );

    assert!(bring_online(&server, &alice).await.is_some());
}

/// Pins down the cost decision: one write per device per minute, not one per heartbeat.
///
/// The test calls `touch` directly rather than beating through the socket: the real heartbeat
/// rhythm is measured in tens of seconds, and waiting for it would make this the slowest test in
/// the suite just to check a guard that is purely local.
#[tokio::test]
async fn presence_is_not_rewritten_on_every_heartbeat() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let first = bring_online(&server, &alice).await.unwrap();

    // An artificially old value: only the in-memory guard can still hold the write back, and
    // that is precisely what we are checking.
    sqlx::query("UPDATE devices SET last_seen_at = now() - interval '1 hour' WHERE id = $1")
        .bind(&alice.id)
        .execute(&server.pool)
        .await
        .unwrap();
    let pushed_back = last_presence(&server.pool, &alice.id).await.unwrap();
    assert!(pushed_back < first);

    for _ in 0..5 {
        server::presence::touch(&server.pool, &alice.id).await.unwrap();
    }

    assert_eq!(last_presence(&server.pool, &alice.id).await, Some(pushed_back));
}

/// Prepares two accounts that are members of the same group, plus a third one left out.
async fn trio(server: &TestServer) -> (TestAccount, Device, TestAccount, Device, TestAccount, Device)
{
    let a = TestAccount::create(server, &unique("alice")).await;
    let alice = a.device(server, "phone").await;
    let b = TestAccount::create(server, &unique("bob")).await;
    let bob = b.device(server, "phone").await;
    let c = TestAccount::create(server, &unique("carol")).await;
    let carol = c.device(server, "phone").await;

    let group_id = hex::encode(unique("group").as_bytes());
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    (a, alice, b, bob, c, carol)
}

async fn presence_of(caller: &Device, handles: &[&str]) -> serde_json::Value {
    let response = caller
        .post("/v1/presence", serde_json::json!({ "handles": handles }))
        .await;
    assert!(response.status().is_success(), "presence refused: {:?}", response.status());
    response.json().await.unwrap()
}

/// Without this clause, the route would be an activity oracle on any handle.
#[tokio::test]
async fn presence_is_only_visible_within_a_shared_group() {
    let server = start().await;
    let (a, alice, b, bob, _c, carol) = trio(&server).await;

    alice.get("/v1/groups").await;
    bob.get("/v1/groups").await;
    bring_online(&server, &alice).await.unwrap();
    bring_online(&server, &bob).await.unwrap();

    let seen = presence_of(&bob, &[&a.handle]).await;
    assert_eq!(seen["accounts"].as_array().unwrap().len(), 1, "bob shares a group with alice");

    let nothing = presence_of(&carol, &[&a.handle, &b.handle]).await;
    assert!(
        nothing["accounts"].as_array().unwrap().is_empty(),
        "carol has no group in common and yet sees something",
    );
}

/// Telling them apart would turn the route into an account-existence oracle.
#[tokio::test]
async fn an_unknown_handle_and_a_handle_with_no_shared_group_are_indistinguishable() {
    let server = start().await;
    let (a, alice, _b, _bob, _c, carol) = trio(&server).await;

    alice.get("/v1/groups").await;
    bring_online(&server, &alice).await.unwrap();

    let stranger = presence_of(&carol, &[&a.handle]).await;
    let nonexistent = presence_of(&carol, &["nobody-by-that-name"]).await;

    assert_eq!(stranger["accounts"], nonexistent["accounts"]);
}

/// An account is online as soon as a single one of its devices is — and only that maximum goes
/// out.
///
/// Serving the per-device detail would tell how many devices a person owns and which one they
/// use at what time: a leak distinct from "online".
#[tokio::test]
async fn an_account_is_online_as_soon_as_a_single_one_of_its_devices_is() {
    let server = start().await;
    let a = TestAccount::create(&server, &unique("alice")).await;
    let phone = a.device(&server, "phone").await;
    let laptop = a.device(&server, "laptop").await;
    let b = TestAccount::create(&server, &unique("bob")).await;
    let bob = b.device(&server, "phone").await;

    let group_id = hex::encode(unique("group").as_bytes());
    phone.post(
        &format!("/v1/groups/{group_id}/members"),
        serde_json::json!({ "device_ids": [phone.id, laptop.id, bob.id] }),
    )
    .await;

    // Only the laptop showed up; the phone stayed off.
    forget_presence(&server.pool, &phone.id).await;
    laptop.get("/v1/groups").await;
    let seen_laptop = bring_online(&server, &laptop).await.unwrap();

    let response = presence_of(&bob, &[&a.handle]).await;
    let accounts = response["accounts"].as_array().unwrap();

    assert_eq!(accounts.len(), 1, "one account, one entry — never one per device");
    assert_eq!(accounts[0]["handle"], a.handle);
    assert_eq!(accounts[0]["last_seen"].as_i64(), Some(seen_laptop));
}

/// A device that was stolen then revoked must no longer keep its owner awake.
#[tokio::test]
async fn a_revoked_device_no_longer_keeps_its_account_online() {
    let server = start().await;
    let a = TestAccount::create(&server, &unique("alice")).await;
    let phone = a.device(&server, "phone").await;
    let stolen = a.device(&server, "stolen").await;
    let b = TestAccount::create(&server, &unique("bob")).await;
    let bob = b.device(&server, "phone").await;

    let group_id = hex::encode(unique("group").as_bytes());
    phone.post(
        &format!("/v1/groups/{group_id}/members"),
        serde_json::json!({ "device_ids": [phone.id, stolen.id, bob.id] }),
    )
    .await;

    stolen.get("/v1/groups").await;
    bring_online(&server, &stolen).await.unwrap();
    forget_presence(&server.pool, &phone.id).await;

    assert_eq!(presence_of(&bob, &[&a.handle]).await["accounts"].as_array().unwrap().len(), 1);

    let revocation = a.revoke(&phone, &stolen.id).await;
    assert!(revocation.status().is_success(), "revocation refused");

    let after = presence_of(&bob, &[&a.handle]).await;
    assert!(
        after["accounts"].as_array().unwrap().is_empty(),
        "a revoked device still keeps its account online",
    );
}

/// The opt-out is honoured **on write**: nothing is recorded, and the past is erased.
///
/// A setting that merely filtered on read would let the server keep the register anyway — that
/// is, would settle nothing.
#[tokio::test]
async fn opting_out_of_presence_prevents_the_recording() {
    let server = start().await;
    let a = TestAccount::create(&server, &unique("alice")).await;
    let alice = a.device(&server, "phone").await;

    alice.get("/v1/groups").await;
    bring_online(&server, &alice).await.unwrap();

    let response = alice.post("/v1/presence/optout", serde_json::json!({ "optout": true })).await;
    assert!(response.status().is_success());

    assert_eq!(
        last_presence(&server.pool, &alice.id).await,
        None,
        "the recorded past survives the opt-out",
    );

    // The in-memory guard must not mask the result: we work around it by starting from an old
    // value, as in the amortisation test.
    sqlx::query("UPDATE devices SET last_seen_at = NULL WHERE id = $1")
        .bind(&alice.id)
        .execute(&server.pool)
        .await
        .unwrap();

    for _ in 0..5 {
        alice.get("/v1/groups").await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(last_presence(&server.pool, &alice.id).await, None);
}

/// Reciprocity: no longer broadcasting your presence also means no longer seeing others'.
///
/// Without that symmetry, the setting would allow seeing without being seen — exactly what it
/// claims to prevent. The same rule applies to read receipts.
#[tokio::test]
async fn refusing_to_broadcast_your_presence_also_cuts_off_reading_it() {
    let server = start().await;
    let (a, alice, _b, bob, _c, _carol) = trio(&server).await;

    alice.get("/v1/groups").await;
    bring_online(&server, &alice).await.unwrap();

    assert_eq!(presence_of(&bob, &[&a.handle]).await["accounts"].as_array().unwrap().len(), 1);

    bob.post("/v1/presence/optout", serde_json::json!({ "optout": true })).await;

    assert!(
        presence_of(&bob, &[&a.handle]).await["accounts"].as_array().unwrap().is_empty(),
        "bob cut off his presence and still sees other people's",
    );
}

#[tokio::test]
async fn asking_for_presence_without_a_signature_is_refused() {
    let server = start().await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/presence", server.base_url))
        .json(&serde_json::json!({ "handles": ["alice"] }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn too_many_handles_in_one_request_is_refused() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let handles: Vec<String> = (0..65).map(|i| format!("account{i}")).collect();
    let response = alice.post("/v1/presence", serde_json::json!({ "handles": handles })).await;

    assert_eq!(response.status(), 400);
}

/// The per-device detail never goes out to a third party.
///
/// It would tell how many devices a person owns and which one they use at what time: a leak
/// distinct from "online", and one the per-account maximum is enough to avoid.
#[tokio::test]
async fn the_per_device_detail_is_only_served_to_its_owner() {
    let server = start().await;
    let a = TestAccount::create(&server, &unique("alice")).await;
    let alice = a.device(&server, "phone").await;
    let b = TestAccount::create(&server, &unique("bob")).await;
    let bob = b.device(&server, "phone").await;

    alice.get("/v1/groups").await;
    bring_online(&server, &alice).await.unwrap();

    let own: serde_json::Value = alice
        .get(&format!("/v1/accounts/{}/devices", a.handle))
        .await
        .json()
        .await
        .unwrap();
    assert!(own["devices"][0]["last_seen"].is_i64(), "the owner cannot see their own devices");

    let third_party: serde_json::Value = bob
        .get(&format!("/v1/accounts/{}/devices", a.handle))
        .await
        .json()
        .await
        .unwrap();
    assert!(
        third_party["devices"][0]["last_seen"].is_null(),
        "a third party gets device-by-device activity",
    );
}

// ---------------------------------------------------------------- wake

/// **The test that carries the property of the wake module.**
///
/// Two things, and the second matters more than the first: the sleeping member is woken, and
/// what goes out to the provider contains **only** its address. No text, no sender, no group id
/// — the type already forbids it, this test pins down the usage.
#[tokio::test]
async fn a_post_wakes_the_members_that_have_a_token() {
    let (server, wakes) = common::start_with_waker().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let group_id = unique("group").into_bytes();
    alice
        .post(
            &group_path(&group_id, "/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    let registration = bob
        .post("/v1/push/token", serde_json::json!({ "provider": "fcm", "token": "bob-token" }))
        .await;
    assert_eq!(registration.status(), 200);

    alice
        .post(
            &group_path(&group_id, "/envelopes"),
            serde_json::json!({ "payload": BASE64_STANDARD.encode([7u8]) }),
        )
        .await;

    let woken = wakes.wait_for(1).await;
    assert_eq!(woken.len(), 1, "only one device has a token");
    assert_eq!(woken[0].token, "bob-token");
    assert_eq!(woken[0].provider, "fcm");
}

/// The sender does not wake itself.
///
/// A phone vibrating for the message it just wrote is not only inelegant: it is one more
/// notification sent to Google or Apple, hence one more trace, for nothing.
#[tokio::test]
async fn the_known_sender_is_not_woken() {
    let (server, wakes) = common::start_with_waker().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let group_id = unique("group").into_bytes();
    alice
        .post(&group_path(&group_id, "/members"), serde_json::json!({ "device_ids": [alice.id] }))
        .await;
    alice
        .post("/v1/push/token", serde_json::json!({ "provider": "fcm", "token": "alice-token" }))
        .await;

    alice
        .post(
            &group_path(&group_id, "/envelopes"),
            serde_json::json!({ "payload": BASE64_STANDARD.encode([1u8]) }),
        )
        .await;

    // Give the detached wake time to be wrong.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(wakes.0.lock().unwrap().is_empty(), "the sender was woken");
}

/// Removing the token cuts off the wake, and drops the address.
///
/// A "disabled" setting that kept the row would leave the server an address it no longer has any
/// use for: what is not stored can neither be demanded later, nor leak with the database.
#[tokio::test]
async fn a_removed_token_no_longer_wakes() {
    let (server, wakes) = common::start_with_waker().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let group_id = unique("group").into_bytes();
    alice
        .post(
            &group_path(&group_id, "/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    bob.post("/v1/push/token", serde_json::json!({ "provider": "fcm", "token": "token" })).await;
    let removal = bob.post("/v1/push/forget", serde_json::json!({})).await;
    assert_eq!(removal.status(), 200);

    alice
        .post(
            &group_path(&group_id, "/envelopes"),
            serde_json::json!({ "payload": BASE64_STANDARD.encode([2u8]) }),
        )
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(wakes.0.lock().unwrap().is_empty(), "a removed token was used");
}

// ---------------------------------------------------------------- purge

/// Sixteen random bytes, the length both nonce tables and `pairings.id` require.
///
/// Random rather than derived from `unique`: these tests share a database with whatever else is
/// running against it, and a collision on a primary key would fail the insert for a reason that
/// has nothing to do with what is being checked.
fn random_id() -> Vec<u8> {
    use rand_core::RngCore;

    let mut bytes = vec![0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// **The test that pins down the purge.**
///
/// `posting_nonces` and `pairings` had no `DELETE` anywhere in the tree. Every sealed-sender
/// post added a row plus an index entry, for the lifetime of the deployment — migration 0007
/// even creates `posting_nonces_used_at_idx`, an index built for a cleanup nobody had written.
///
/// The assertions look at named rows and never at the counts the purge returns: the database is
/// shared, and another test posting an envelope at the same moment would move any total.
#[tokio::test]
async fn the_purge_erases_what_has_expired_and_keeps_what_has_not() {
    let server = start().await;

    let group_id = random_id();
    let (stale_nonce, fresh_nonce) = (random_id(), random_id());

    for (nonce, age) in [(&stale_nonce, "30 days"), (&fresh_nonce, "1 second")] {
        sqlx::query(&format!(
            "INSERT INTO posting_nonces (group_id, nonce, used_at)
             VALUES ($1, $2, now() - interval '{age}')"
        ))
        .bind(&group_id)
        .bind(nonce)
        .execute(&server.pool)
        .await
        .unwrap();
    }

    let (expired_pairing, live_pairing) = (random_id(), random_id());

    for (id, expiry) in [(&expired_pairing, "-1 minute"), (&live_pairing, "5 minutes")] {
        sqlx::query(&format!(
            "INSERT INTO pairings (id, payload, expires_at)
             VALUES ($1, $2, now() + interval '{expiry}')"
        ))
        .bind(id)
        .bind(b"sealed".as_slice())
        .execute(&server.pool)
        .await
        .unwrap();
    }

    server::purge_once(&server.pool).await.expect("the purge ran");

    let survives = async |table: &str, column: &str, id: &Vec<u8>| -> bool {
        let found: Option<(i32,)> =
            sqlx::query_as(&format!("SELECT 1 FROM {table} WHERE {column} = $1"))
                .bind(id)
                .fetch_optional(&server.pool)
                .await
                .unwrap();
        found.is_some()
    };

    assert!(
        !survives("posting_nonces", "nonce", &stale_nonce).await,
        "a nonce older than the retention keeps the table growing forever"
    );
    assert!(
        survives("posting_nonces", "nonce", &fresh_nonce).await,
        "erasing a recent nonce reopens the replay it exists to refuse"
    );

    assert!(
        !survives("pairings", "id", &expired_pairing).await,
        "an expired drop box no reader can see is dead weight"
    );
    assert!(
        survives("pairings", "id", &live_pairing).await,
        "a pairing still inside its window was destroyed under the user's QR code"
    );
}

/// A pairing survives the purge until it expires, and no longer.
///
/// Deleting exactly at expiry needs no safety margin, unlike the nonce windows: `claim_pairing`
/// already filters on `expires_at > now()`, so the row is invisible to every reader before the
/// purge touches it. The test pins that equivalence — a margin added later would be a
/// misunderstanding of why there is none.
#[tokio::test]
async fn an_expired_pairing_is_already_unreadable_before_it_is_purged() {
    let server = start().await;
    let id = random_id();

    sqlx::query(
        "INSERT INTO pairings (id, payload, expires_at) VALUES ($1, $2, now() - interval '1 second')",
    )
    .bind(&id)
    .bind(b"sealed".as_slice())
    .execute(&server.pool)
    .await
    .unwrap();

    let refused = reqwest::Client::new()
        .get(format!("{}/v1/pairings/{}", server.base_url, hex::encode(&id)))
        .send()
        .await
        .unwrap();

    assert_eq!(refused.status(), 404, "an expired packet was served");
}
