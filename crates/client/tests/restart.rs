//! What a client keeps across a restart, against a running server.
//!
//! Ignored by default and release-only, for the reasons given in `against_a_server.rs`.
//!
//! ```sh
//! WHISPEE_TEST_SERVER=http://127.0.0.1:8790 cargo test --release -p client -- --ignored
//! ```

use client::Enrolled;
use crypto_core::{Conversation, Incoming, roles};
use wire::{content, envelope, padding};

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

/// Encodes a message the way every client must: content, then padding, then MLS.
fn outgoing(
    conversation: &mut Conversation,
    identity: &crypto_core::Identity,
    body: &content::Content,
    sent_at: Option<u64>,
) -> Vec<u8> {
    let encoded = content::encode(body, sent_at).expect("encodable body");
    let padded = padding::pad(&encoded);
    envelope::encode_mls(&conversation.encrypt(identity, &padded).expect("encrypt"))
}

/// A restarted client is the same device, in the same conversations.
///
/// The failure this guards against is quiet: a client that re-enrols instead of restoring gets a
/// **different account**, which is a stranger to every group the old one was in, and it looks
/// like it recovered.
#[tokio::test]
#[ignore = "needs a running server; set WHISPEE_TEST_SERVER"]
async fn a_persisted_client_comes_back_as_the_same_device() {
    let Some(base) = server() else { panic!("WHISPEE_TEST_SERVER is not set") };

    let store = client::store::Memory::new();
    let alice = Enrolled::create(&base, &unique("alice"), "web").await.expect("alice");
    let bot = Enrolled::create(&base, &unique("bot"), "asap").await.expect("bot");

    // The bot joins a conversation, then saves.
    let claimed = alice.api.claim_key_package(&bot.device_id).await.expect("claim");
    let mut alice_group =
        Conversation::create_administered(&alice.identity, alice.account_id.clone()).expect("create");
    let invitation = alice_group.invite(&alice.identity, &claimed.package).expect("invite");
    let tree = alice_group.apply_pending(&alice.identity).expect("apply");
    let group_id = alice_group.id();

    let joined = Conversation::join(&bot.identity, &invitation.welcome, &tree).expect("join");
    drop(joined);
    bot.persist(&store).expect("persist");

    let saved_account = bot.account_id.clone();
    let saved_device = bot.device_id.clone();
    drop(bot);

    // --- the restart ------------------------------------------------------
    let revived = Enrolled::restore(&base, &store).expect("restore").expect("something was saved");

    assert_eq!(revived.account_id, saved_account, "a restart must not mint a new account");
    assert_eq!(revived.device_id, saved_device);
    assert!(
        revived.api.key_package_stock().await.is_ok(),
        "the restored device must still be able to sign requests: the auth key is not in the \
         MLS state, and a client that only restored the latter looks healthy until its first call"
    );

    // And it is still a member: the group reloads out of the restored state.
    let mut revived_group =
        Conversation::load(&revived.identity, &group_id).expect("the group survives the restart");

    alice
        .api
        .add_members(&group_id, &[alice.device_id.clone(), revived.device_id.clone()])
        .await
        .expect("declare");

    let sent_at = client::unix_millis();
    let blob = outgoing(
        &mut alice_group,
        &alice.identity,
        &content::Content::Text("après redémarrage".to_owned()),
        Some(sent_at),
    );
    let envelope::Envelope::Mls(payload) = envelope::decode(&blob).expect("decode") else {
        panic!("expected an mls envelope");
    };

    match revived_group.process(&revived.identity, payload, &roles::Context::default()).expect("process")
    {
        Incoming::Application { plaintext, .. } => {
            let decoded = content::decode(padding::unpad(&plaintext).expect("unpad")).expect("decode");
            assert_eq!(decoded.body, content::Content::Text("après redémarrage".to_owned()));
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}
