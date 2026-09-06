//! The SDK against a running delivery server.
//!
//! Ignored by default: it needs a server, and `cargo test` on a laptop with no Postgres should
//! not fail for that. Run it with one up:
//!
//! ```sh
//! docker compose up -d postgres && scripts/dev-server.sh &
//! WHISPEE_TEST_SERVER=http://127.0.0.1:8790 cargo test --release -p client -- --ignored
//! ```
//!
//! **Release only.** In debug, OpenMLS panics rather than returning its decryption error, so
//! `a_tampered_ciphertext_is_refused` measures a `debug_assert` instead of the protocol.

use client::{Cursor, Enrolled, Event, Gateway, Poll};
use crypto_core::{Conversation, Incoming, roles};
use wire::{content, envelope, padding};

fn server() -> Option<String> {
    std::env::var("WHISPEE_TEST_SERVER").ok()
}

/// Handles are never reissued once released, so every run takes a fresh one.
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

/// The whole path a bridge takes, end to end, with nothing stubbed.
#[tokio::test]
#[ignore = "needs a running server; set WHISPEE_TEST_SERVER"]
async fn a_native_client_joins_a_conversation_and_exchanges_messages() {
    let Some(base) = server() else { panic!("WHISPEE_TEST_SERVER is not set") };

    // --- both sides enrol -------------------------------------------------
    let alice = Enrolled::create(&base, &unique("alice"), "web").await.expect("alice enrols");
    let bot = Enrolled::create(&base, &unique("bot"), "asap").await.expect("bot enrols");

    assert_eq!(bot.api.key_package_stock().await.expect("stock"), 10);
    assert_eq!(
        bot.api.replenish_key_packages(&bot.identity).await.expect("replenish"),
        0,
        "a full stock is not topped up: the low-water mark exists to avoid pointless writes"
    );

    // --- alice invites the bot into an administered conversation -----------
    //
    // Administered, not flat: a flat group has no authority and can never take a third member,
    // so a conversation meant to gain a service later has to be created this way.
    let claimed = alice.api.claim_key_package(&bot.device_id).await.expect("claim");
    assert_eq!(claimed.remaining, 9, "a key package is single-use");

    let mut alice_group = Conversation::create_administered(&alice.identity, alice.account_id.clone())
        .expect("create");
    let invitation = alice_group.invite(&alice.identity, &claimed.package).expect("invite");
    let tree = alice_group.apply_pending(&alice.identity).expect("apply");
    let group_id = alice_group.id();

    alice
        .api
        .add_members(&group_id, &[alice.device_id.clone(), bot.device_id.clone()])
        .await
        .expect("declare the mailbox members");

    let welcome_seq = alice
        .api
        .post_envelope(&group_id, &envelope::encode_welcome(&invitation.welcome, &tree))
        .await
        .expect("post welcome");

    // --- the bot finds its own welcome ------------------------------------
    let groups = bot.api.groups().await.expect("groups");
    assert!(groups.contains(&hex::encode(&group_id)), "the server names the bot's groups");

    let page = bot.api.envelopes_after(&group_id, 0).await.expect("read the mailbox");
    let mut bot_group = page
        .iter()
        .find_map(|entry| {
            let blob = entry.bytes().ok()?;
            match envelope::decode(&blob).ok()? {
                envelope::Envelope::Welcome { welcome, ratchet_tree } => {
                    Conversation::join(&bot.identity, welcome, ratchet_tree).ok()
                }
                envelope::Envelope::Mls(_) => None,
            }
        })
        .expect("the bot finds a welcome addressed to it");

    assert_eq!(bot_group.member_count(), 2);
    assert_eq!(
        bot_group.lifetime().expect("lifetime").map(|life| life.get()),
        Some(7 * 24 * 60 * 60),
        "every conversation starts at seven days, and a member reads it from authenticated state"
    );

    // --- the gateway wakes the bot ----------------------------------------
    //
    // Resuming from the Welcome's sequence, not from zero: a client that reconnects at zero is
    // woken by its own Welcome and takes it for a message.
    let mut gateway = Gateway::connect(
        bot.api.transport(),
        &[Cursor { group_id: group_id.clone(), seq: welcome_seq }],
    )
    .await
    .expect("gateway");

    assert!(
        matches!(gateway.poll().await.expect("ready"), Poll::Event(Event::Ready { .. })),
        "the session announces itself before anything else"
    );

    const TEXT: &str = "Bonjour, il me faudrait un devis.";
    let sent_at = client::unix_millis();
    alice
        .api
        .post_envelope(
            &group_id,
            &outgoing(
                &mut alice_group,
                &alice.identity,
                &content::Content::Text(TEXT.to_owned()),
                Some(sent_at),
            ),
        )
        .await
        .expect("post message");

    let seq = loop {
        match gateway.poll().await.expect("event") {
            Poll::Event(Event::Envelope { seq, group }) => {
                assert_eq!(group, hex::encode(&group_id));
                break seq;
            }
            Poll::Event(_) | Poll::Idle => continue,
            Poll::Closed => panic!("the gateway closed before announcing the envelope"),
        }
    };
    assert_eq!(seq, welcome_seq + 1);

    // --- and the bot reads it ---------------------------------------------
    let fetched = bot.api.envelopes_after(&group_id, welcome_seq).await.expect("fetch");
    let blob = fetched.first().expect("one envelope").bytes().expect("payload");
    let envelope::Envelope::Mls(payload) = envelope::decode(&blob).expect("decode") else {
        panic!("expected an mls envelope");
    };

    match bot_group.process(&bot.identity, payload, &roles::Context::default()).expect("process") {
        Incoming::Application { plaintext, sender } => {
            let unpadded = padding::unpad(&plaintext).expect("unpad");
            let decoded = content::decode(unpadded).expect("decode content");

            assert_eq!(decoded.body, content::Content::Text(TEXT.to_owned()));
            assert_eq!(decoded.sent_at, Some(sent_at));
            assert_eq!(
                sender.as_deref(),
                Some(alice.account_id.as_str()),
                "the credential names the account, not the device"
            );
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // --- the bot answers, and alice reads it ------------------------------
    bot.api
        .post_envelope(
            &group_id,
            &outgoing(
                &mut bot_group,
                &bot.identity,
                &content::Content::Text("Devis préparé.".to_owned()),
                Some(client::unix_millis()),
            ),
        )
        .await
        .expect("bot posts");

    let back = alice.api.envelopes_after(&group_id, seq).await.expect("alice fetches");
    let blob = back.first().expect("the reply").bytes().expect("payload");
    let envelope::Envelope::Mls(payload) = envelope::decode(&blob).expect("decode") else {
        panic!("expected an mls envelope");
    };
    match alice_group.process(&alice.identity, payload, &roles::Context::default()).expect("process")
    {
        Incoming::Application { plaintext, .. } => {
            let decoded = content::decode(padding::unpad(&plaintext).expect("unpad")).expect("decode");
            assert_eq!(decoded.body, content::Content::Text("Devis préparé.".to_owned()));
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// The negative controls. Without them the test above could be passing for the wrong reason.
#[tokio::test]
#[ignore = "needs a running server; set WHISPEE_TEST_SERVER"]
async fn the_server_refuses_what_it_should() {
    let Some(base) = server() else { panic!("WHISPEE_TEST_SERVER is not set") };

    let owner = Enrolled::create(&base, &unique("owner"), "web").await.expect("owner enrols");
    let stranger = Enrolled::create(&base, &unique("nosy"), "web").await.expect("stranger enrols");

    // Unique per run: a mailbox already declared cannot be declared again, so a fixed id
    // makes the test pass exactly once per database.
    let group_id = unique("mailbox").into_bytes();
    owner.api.add_members(&group_id, std::slice::from_ref(&owner.device_id)).await.expect("declare");
    owner.api.post_envelope(&group_id, &[0u8, 1, 2, 3]).await.expect("post");

    // A stranger reading a mailbox it was never added to.
    let refused = stranger.api.envelopes_after(&group_id, 0).await;
    assert!(refused.is_err(), "a stranger must not read another group's mailbox");

    // And the owner still can, in the same run — otherwise the refusal above would prove
    // nothing about authorisation and only that something is broken.
    assert_eq!(owner.api.envelopes_after(&group_id, 0).await.expect("owner reads").len(), 1);

    // A signature made with a key the server does not know for this device.
    let impostor = client::Transport::new(
        &base,
        owner.device_id.clone(),
        ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
    );
    assert_eq!(
        impostor.status("GET", "/v1/key-packages/stock").await.expect("request"),
        401,
        "the device id is not the credential: the signature is"
    );
}

/// A tampered ciphertext must be rejected, not accepted and not fatal.
///
/// Only meaningful in release: in debug, OpenMLS panics before returning the error.
#[tokio::test]
#[ignore = "needs a running server; set WHISPEE_TEST_SERVER"]
async fn a_tampered_ciphertext_is_refused() {
    let Some(base) = server() else { panic!("WHISPEE_TEST_SERVER is not set") };

    let alice = Enrolled::create(&base, &unique("alice"), "web").await.expect("alice");
    let bot = Enrolled::create(&base, &unique("bot"), "asap").await.expect("bot");

    let claimed = alice.api.claim_key_package(&bot.device_id).await.expect("claim");
    let mut alice_group =
        Conversation::create_administered(&alice.identity, alice.account_id.clone()).expect("create");
    let invitation = alice_group.invite(&alice.identity, &claimed.package).expect("invite");
    let tree = alice_group.apply_pending(&alice.identity).expect("apply");
    let mut bot_group =
        Conversation::join(&bot.identity, &invitation.welcome, &tree).expect("join");

    let mut ciphertext = alice_group
        .encrypt(&alice.identity, &padding::pad(b"\x00hello"))
        .expect("encrypt");

    // The honest message decrypts — so the failure below is about the tampering and not about
    // the setup.
    assert!(
        bot_group.process(&bot.identity, &ciphertext, &roles::Context::default()).is_ok(),
        "the untampered message must decrypt, or this test measures nothing"
    );

    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xff;
    assert!(
        bot_group.process(&bot.identity, &ciphertext, &roles::Context::default()).is_err(),
        "a flipped byte must be refused cleanly"
    );
}
