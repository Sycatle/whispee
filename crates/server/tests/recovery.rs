//! Recovery escrow: the server side of getting an account back with no device left.
//!
//! What is worth pinning here is not that a blob round-trips — `crypto_core::escrow` owns that
//! — but the four properties that only exist because a *server* is in the middle:
//!
//! * the unauthenticated route answers the same thing to a wrong guess and to an account that
//!   has no escrow, so it is not an oracle;
//! * replacing a password leaves no second password behind;
//! * one account cannot touch another's escrow;
//! * a rotation destroys the escrow, because the seed it holds has just been abandoned.
//!
//! Most tests use the passkey factor. It is the same code path server-side and it skips
//! Argon2id's 256 MiB, which the one password test pays so the suite does not pay it eleven
//! times.

mod common;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use common::{Device, TestAccount, TestServer, start, start_with_recovery_quota, unique};
use crypto_core::escrow::{self, Factor, Kind};
use sha2::{Digest, Sha256};

/// Builds a factor from a labelled PRF secret. Cheap: there is no password to stretch.
///
/// **The label must be unique per run, not merely per test.** The database persists between
/// `cargo test` invocations — that is why `common::unique` exists — and a lookup value is the
/// primary key of `recovery_escrows`. A fixed secret therefore deposits fine on the first run
/// and collides with its own leftover row, under a different account, on the second. Which is
/// the server behaving correctly: it answers 409 rather than letting one account overwrite
/// another's only way back in.
fn passkey_factor(label: &str) -> Factor {
    let secret: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    escrow::derive_prf_factor(&secret).expect("prf factor")
}

fn body(factor: &Factor, account: &str, kind: Kind, seed: [u8; 64]) -> serde_json::Value {
    let params = escrow::Params::current(kind);
    let sealed = escrow::seal(&seed, factor, account, kind, &params).expect("seal");

    serde_json::json!({
        "kind": kind.as_str(),
        "lookup": BASE64_STANDARD.encode(factor.lookup_id()),
        "params": BASE64_STANDARD.encode(params.encode()),
        "sealed": BASE64_STANDARD.encode(sealed),
    })
}

async fn claim(server: &TestServer, factor: &Factor) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/v1/recovery/claim", server.base_url))
        .json(&serde_json::json!({ "lookup": BASE64_STANDARD.encode(factor.lookup_id()) }))
        .send()
        .await
        .expect("claim")
}

async fn account_with_device(server: &TestServer, name: &str) -> (TestAccount, Device) {
    let account = TestAccount::create(server, &unique(name)).await;
    let device = account.device(server, "laptop").await;
    (account, device)
}

/// The whole point, end to end: a factor deposited by a device is served back to a caller with
/// no device at all, and the seed comes out intact.
#[tokio::test]
async fn an_escrow_deposited_by_a_device_is_served_to_a_caller_with_none() {
    let server = start().await;
    let (account, device) = account_with_device(&server, "alice").await;
    let seed = account.account.export_seed();

    let factor = passkey_factor(&account.handle);
    let response =
        device.post("/v1/recovery", body(&factor, &account.id, Kind::Passkey, seed)).await;
    assert!(response.status().is_success(), "deposit refused: {}", response.status());

    let claimed: serde_json::Value = claim(&server, &factor).await.json().await.expect("json");

    assert_eq!(claimed["account"], account.id);
    assert_eq!(claimed["handle"], account.handle);
    assert_eq!(claimed["kind"], "passkey");

    let sealed = BASE64_STANDARD.decode(claimed["sealed"].as_str().expect("sealed")).unwrap();
    let params =
        escrow::Params::decode(&BASE64_STANDARD.decode(claimed["params"].as_str().unwrap()).unwrap())
            .expect("params");

    let recovered =
        escrow::open(&sealed, &factor, &account.id, Kind::Passkey, &params).expect("open");
    assert_eq!(recovered, seed, "the recovered seed is not the account's");
}

/// **The property that keeps this route from being an enumeration oracle.**
///
/// A wrong secret and an account that never enabled recovery must be indistinguishable. If they
/// were not, an unauthenticated caller could sweep for accounts that have an escrow — which is
/// to say, for accounts worth grinding.
#[tokio::test]
async fn a_wrong_secret_and_an_absent_escrow_are_the_same_answer() {
    let server = start().await;
    let (account, device) = account_with_device(&server, "bob").await;

    let never_deposited = claim(&server, &passkey_factor(&unique("never_deposited"))).await.status();

    device
        .post("/v1/recovery", body(&passkey_factor(&account.handle), &account.id, Kind::Passkey, account.account.export_seed()))
        .await;

    let wrong_secret = claim(&server, &passkey_factor(&unique("wrong_secret"))).await.status();

    assert_eq!(never_deposited, reqwest::StatusCode::NOT_FOUND);
    assert_eq!(wrong_secret, never_deposited, "a wrong guess is distinguishable from no escrow");
}

/// Changing the password must not leave the old one working.
///
/// This is the failure the delete-then-insert in `set_recovery` exists to prevent: the lookup
/// moves with the secret, so an upsert keyed on it would keep the previous row — a password its
/// owner believes they have replaced, still opening the account.
#[tokio::test]
async fn replacing_a_factor_leaves_no_second_one_behind() {
    let server = start().await;
    let (account, device) = account_with_device(&server, "carol").await;
    let seed = account.account.export_seed();

    let old = passkey_factor(&format!("{}:old", account.handle));
    let new = passkey_factor(&format!("{}:new", account.handle));

    device.post("/v1/recovery", body(&old, &account.id, Kind::Passkey, seed)).await;
    let replaced = device.post("/v1/recovery", body(&new, &account.id, Kind::Passkey, seed)).await;
    assert!(replaced.status().is_success());

    assert_eq!(claim(&server, &old).await.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(claim(&server, &new).await.status().is_success());
}

/// One of each kind, and they do not evict each other: a passkey is the everyday path and a
/// password is the one that works on a borrowed computer.
#[tokio::test]
async fn the_two_kinds_coexist() {
    let server = start().await;
    let (account, device) = account_with_device(&server, "dave").await;
    let seed = account.account.export_seed();

    let passkey = passkey_factor(&account.handle);
    let password = escrow::derive_password_factor(
        &account.handle,
        "a password nobody has to remember here",
        &escrow::Params::current(Kind::Password),
    )
    .expect("password factor");

    device.post("/v1/recovery", body(&passkey, &account.id, Kind::Passkey, seed)).await;
    device.post("/v1/recovery", body(&password, &account.id, Kind::Password, seed)).await;

    assert!(claim(&server, &passkey).await.status().is_success());
    assert!(claim(&server, &password).await.status().is_success());

    let listed: serde_json::Value = device.get("/v1/recovery").await.json().await.expect("json");
    let kinds: Vec<&str> =
        listed.as_array().expect("array").iter().map(|f| f["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, vec!["passkey", "password"]);

    // And the listing never carries the ciphertext: an authenticated device already holds the
    // seed, so serving it here would open a second door the recovery quota does not watch.
    assert!(listed[0].get("sealed").is_none());
}

#[tokio::test]
async fn forgetting_a_factor_removes_it_and_is_idempotent() {
    let server = start().await;
    let (account, device) = account_with_device(&server, "erin").await;

    let factor = passkey_factor(&account.handle);
    device
        .post("/v1/recovery", body(&factor, &account.id, Kind::Passkey, account.account.export_seed()))
        .await;

    let forgotten =
        device.post("/v1/recovery/forget", serde_json::json!({ "kind": "passkey" })).await;
    assert!(forgotten.status().is_success());
    assert_eq!(claim(&server, &factor).await.status(), reqwest::StatusCode::NOT_FOUND);

    // Asking again is a success, not a 404: the caller wanted this factor gone and it is gone.
    let again = device.post("/v1/recovery/forget", serde_json::json!({ "kind": "passkey" })).await;
    assert!(again.status().is_success());
}

/// A device of one account must not be able to remove another account's escrow.
///
/// The account is taken from the signing device and never from the request, exactly as the
/// vault routes do — so there is no parameter to point elsewhere. Checked anyway, because that
/// is a property of the handler and not of the schema.
#[tokio::test]
async fn one_account_cannot_forget_another_s_escrow() {
    let server = start().await;
    let (owner, owner_device) = account_with_device(&server, "frank").await;
    let (_stranger, stranger_device) = account_with_device(&server, "grace").await;

    let factor = passkey_factor(&owner.handle);
    owner_device
        .post("/v1/recovery", body(&factor, &owner.id, Kind::Passkey, owner.account.export_seed()))
        .await;

    stranger_device.post("/v1/recovery/forget", serde_json::json!({ "kind": "passkey" })).await;

    assert!(
        claim(&server, &factor).await.status().is_success(),
        "a stranger's request removed this account's escrow"
    );
}

/// **Rotation destroys the escrow.**
///
/// Rotation is the answer to a stolen device, and a stolen device holds the seed. An escrow
/// left behind is the abandoned seed still sitting on the server, openable by a password the
/// thief may well have watched being typed. The ciphertext is worthless to its owner the
/// moment the key moves, and dangerous to leave.
#[tokio::test]
async fn rotating_the_account_destroys_the_escrow() {
    let server = start().await;
    let (account, device) = account_with_device(&server, "heidi").await;

    let factor = passkey_factor(&account.handle);
    device
        .post("/v1/recovery", body(&factor, &account.id, Kind::Passkey, account.account.export_seed()))
        .await;
    assert!(claim(&server, &factor).await.status().is_success(), "escrow was not deposited");

    let (successor, _phrase) = crypto_core::Account::generate().expect("successor");
    let rotated_at = common::now();
    let rotation = account
        .account
        .rotate(&account.id, &successor.identity_key(), rotated_at)
        .expect("rotation");

    let response = device
        .post(
            &format!("/v1/accounts/{}/rotate", account.id),
            serde_json::json!({
                "new_identity_key": BASE64_STANDARD.encode(successor.identity_key()),
                "rotation": BASE64_STANDARD.encode(rotation),
                "rotated_at": rotated_at,
            }),
        )
        .await;
    assert!(response.status().is_success(), "rotation refused: {}", response.status());

    assert_eq!(
        claim(&server, &factor).await.status(),
        reqwest::StatusCode::NOT_FOUND,
        "the old seed is still recoverable after a rotation"
    );
}

/// The deposit route is authenticated, and the escrow is not something an unsigned caller may
/// write. Otherwise anyone could overwrite an account's only way back in.
#[tokio::test]
async fn depositing_an_escrow_without_a_signature_is_refused() {
    let server = start().await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/recovery", server.base_url))
        .json(&body(&passkey_factor(&unique("unsigned")), "0123456789abcdef0123456789abcdef", Kind::Passkey, [0u8; 64]))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// Lengths are checked before anything reaches the database.
///
/// The sealed blob is fixed-length by construction — nonce, seed, tag — and letting a caller
/// choose its size would make this table, the one an unauthenticated route reads back, into a
/// storage channel.
#[tokio::test]
async fn a_blob_of_the_wrong_size_is_refused() {
    let server = start().await;
    let (account, device) = account_with_device(&server, "ivan").await;

    let mut payload = body(&passkey_factor(&account.handle), &account.id, Kind::Passkey, account.account.export_seed());
    payload["sealed"] = serde_json::Value::String(BASE64_STANDARD.encode([0u8; 91]));

    let response = device.post("/v1/recovery", payload).await;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// The one bound that exists on online guessing.
///
/// It is not much and it is not claimed to be: an attacker holding the table never calls this
/// route. What it closes is the door that does not require stealing a database first.
#[tokio::test]
async fn the_recovery_quota_bites() {
    let server = start_with_recovery_quota(2).await;

    let missing = passkey_factor(&unique("missing"));
    assert_eq!(claim(&server, &missing).await.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(claim(&server, &missing).await.status(), reqwest::StatusCode::NOT_FOUND);

    assert_eq!(
        claim(&server, &missing).await.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "a third guess in the same minute went through"
    );
}
