//! Attachments, against a running server.
//!
//! Ignored by default and release-only, for the reasons given in `against_a_server.rs`.
//!
//! ```sh
//! WHISPEE_TEST_SERVER=http://127.0.0.1:8790 cargo test --release -p client -- --ignored
//! ```

use client::Enrolled;

fn server() -> Option<String> {
    std::env::var("WHISPEE_TEST_SERVER").ok()
}

/// Handles are never reissued once released, and a mailbox already declared cannot be declared
/// again, so every run takes fresh names.
fn unique(prefix: &str) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_nanos();
    format!("{prefix}_{}", stamp % 100_000_000)
}

/// An attachment goes up encrypted and comes back the same bytes.
#[tokio::test]
#[ignore = "needs a running server; set WHISPEE_TEST_SERVER"]
async fn an_attachment_round_trips_through_the_server() {
    let Some(base) = server() else { panic!("WHISPEE_TEST_SERVER is not set") };

    let alice = Enrolled::create(&base, &unique("alice"), "web").await.expect("alice");
    let group_id = unique("files").into_bytes();
    alice
        .api
        .add_members(&group_id, std::slice::from_ref(&alice.device_id))
        .await
        .expect("declare");

    let file = b"%PDF-1.7 a quote, or near enough".repeat(40);
    let reference = client::attachments::upload(
        &alice.api,
        &group_id,
        "devis.pdf",
        "application/pdf",
        &file,
    )
    .await
    .expect("upload");

    assert_eq!(reference.size, file.len() as u64);
    assert_eq!(reference.padded, Some(true));

    let back = client::attachments::download(&alice.api, &group_id, &reference)
        .await
        .expect("download");
    assert_eq!(back, file, "the file must come back byte for byte");

    // The server holds ciphertext, not the file. Fetching the blob raw and finding the
    // plaintext in it would mean the encryption never happened.
    let raw = alice
        .api
        .transport()
        .get_bytes(&format!(
            "/v1/groups/{}/attachments/{}",
            hex::encode(&group_id),
            reference.id
        ))
        .await
        .expect("raw fetch");
    assert!(
        !raw.windows(8).any(|window| window == &file[..8]),
        "the plaintext is readable in what the server stores"
    );

    // A key that is not the one it was sealed with must fail, not return plausible bytes.
    let mut wrong = reference.clone();
    wrong.key = base64_of_zero_key();
    assert!(
        client::attachments::download(&alice.api, &group_id, &wrong).await.is_err(),
        "the GCM tag must refuse a substituted key"
    );
}

fn base64_of_zero_key() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([0u8; 32])
}
