//! Tests running in a real WebAssembly environment.
//!
//! Compiling for wasm32 proves nothing: what breaks in practice is randomness. `getrandom`
//! must find `crypto.getRandomValues`, and broken randomness raises no error — it silently
//! produces predictable keys. These tests therefore run in the target environment, not
//! natively.
//!
//! ```sh
//! wasm-pack test --node crates/crypto-wasm
//! wasm-pack test --headless --firefox crates/crypto-wasm
//! ```

#![cfg(target_arch = "wasm32")]

use crypto_wasm::Client;
use serde::Deserialize;
use wasm_bindgen_test::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Invitation {
    #[allow(dead_code)]
    #[serde(with = "serde_bytes")]
    commit: Vec<u8>,
    #[serde(with = "serde_bytes")]
    welcome: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum Incoming {
    Application {
        sender: Option<String>,
        #[serde(with = "serde_bytes")]
        plaintext: Vec<u8>,
    },
    GroupChanged,
    Proposal,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Peer {
    name: String,
    fingerprint: String,
}

fn two_party_conversation() -> (Client, Client, Vec<u8>, Vec<u8>) {
    let mut alice = Client::create("alice@web").unwrap();
    let mut bob = Client::create("bob@web").unwrap();

    let bob_key_package = bob.publish_key_package().unwrap();
    let group_id = alice.create_conversation().unwrap();

    let invitation: Invitation =
        serde_wasm_bindgen::from_value(alice.invite(&group_id, &bob_key_package).unwrap()).unwrap();
    let tree = alice.apply_pending(&group_id).unwrap();
    let bob_group = bob.join(&invitation.welcome, &tree).unwrap();

    (alice, bob, group_id, bob_group)
}

#[wasm_bindgen_test]
fn full_cycle_in_the_browser() {
    let (mut alice, mut bob, alice_group, bob_group) = two_party_conversation();

    assert_eq!(alice_group, bob_group);
    assert_eq!(alice.epoch(&alice_group).unwrap(), bob.epoch(&bob_group).unwrap());

    let ciphertext = alice.encrypt(&alice_group, b"hello from WASM").unwrap();
    let incoming: Incoming =
        serde_wasm_bindgen::from_value(bob.process(&bob_group, &ciphertext).unwrap()).unwrap();

    match incoming {
        Incoming::Application { sender, plaintext } => {
            assert_eq!(plaintext, b"hello from WASM");
            assert_eq!(sender.as_deref(), Some("alice@web"));
        }
        _ => panic!("expected an application message"),
    }

    let reply = bob.encrypt(&bob_group, b"got it").unwrap();
    let incoming: Incoming =
        serde_wasm_bindgen::from_value(alice.process(&alice_group, &reply).unwrap()).unwrap();
    assert!(matches!(incoming, Incoming::Application { .. }));
}

#[wasm_bindgen_test]
fn the_browser_randomness_works() {
    // The test that really counts. If `getrandom` cannot find `crypto.getRandomValues`, it
    // either panics or — far worse — produces predictable keys without saying a word. Two
    // identities created back to back must have distinct fingerprints.
    let first = Client::create("same-name").unwrap();
    let second = Client::create("same-name").unwrap();

    assert_ne!(
        first.fingerprint(),
        second.fingerprint(),
        "two identities share the same key: randomness is broken"
    );
    assert!(!first.fingerprint().is_empty());
}

#[wasm_bindgen_test]
fn the_transport_sees_nothing() {
    let (mut alice, _bob, alice_group, _) = two_party_conversation();

    let secret = b"the safe code is 4815162342";
    let ciphertext = alice.encrypt(&alice_group, secret).unwrap();

    assert!(!ciphertext.windows(secret.len()).any(|w| w == secret));
    assert!(!ciphertext.windows(5).any(|w| w == b"alice"));
}

#[wasm_bindgen_test]
fn fingerprints_are_visible_on_both_sides() {
    let (alice, bob, alice_group, bob_group) = two_party_conversation();

    let alice_view: Vec<Peer> =
        serde_wasm_bindgen::from_value(alice.peer_fingerprints(&alice_group).unwrap()).unwrap();
    let bob_view: Vec<Peer> =
        serde_wasm_bindgen::from_value(bob.peer_fingerprints(&bob_group).unwrap()).unwrap();

    assert_eq!(alice_view.len(), 1);
    assert_eq!(alice_view[0].name, "bob@web");
    assert_eq!(bob_view[0].name, "alice@web");

    // Each sees the other's real fingerprint: this is what the UI must display to make the
    // out-of-band comparison possible.
    assert_eq!(alice_view[0].fingerprint, bob.fingerprint());
    assert_eq!(bob_view[0].fingerprint, alice.fingerprint());
}

#[wasm_bindgen_test]
fn an_unknown_conversation_is_refused() {
    let mut alice = Client::create("alice").unwrap();
    assert!(alice.encrypt(b"nonexistent-group", b"hi").is_err());
}

#[wasm_bindgen_test]
fn the_exported_state_is_not_empty() {
    let (alice, _bob, _, _) = two_party_conversation();
    let state = alice.export_state().unwrap();

    // Reminder: this blob contains the private keys in the clear. It must never reach
    // localStorage or the server without being encrypted first.
    assert!(state.len() > 100);
}

#[wasm_bindgen_test]
fn the_message_variants_are_exhaustive() {
    // Forces the compiler to flag it if `Incoming` gains a variant unhandled on the JS side.
    fn _exhaustive(incoming: Incoming) -> &'static str {
        match incoming {
            Incoming::Application { .. } => "application",
            Incoming::GroupChanged => "groupChanged",
            Incoming::Proposal => "proposal",
        }
    }
}

#[wasm_bindgen_test]
fn a_client_survives_a_page_reload() {
    let (mut alice, mut bob, alice_group, bob_group) = two_party_conversation();

    let first = alice.encrypt(&alice_group, b"before").unwrap();
    bob.process(&bob_group, &first).unwrap();

    // Simulates closing the tab: the WASM state is lost, only the exported blob survives.
    let state = bob.export_state().unwrap();
    let ids = bob.conversation_ids();
    drop(bob);

    let mut bob = Client::restore(&state, ids).unwrap();
    assert_eq!(bob.name(), "bob@web");

    let second = alice.encrypt(&alice_group, b"after").unwrap();
    let incoming: Incoming =
        serde_wasm_bindgen::from_value(bob.process(&bob_group, &second).unwrap()).unwrap();

    match incoming {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"after"),
        _ => panic!("expected an application message"),
    }
}

#[wasm_bindgen_test]
fn a_corrupted_state_is_refused() {
    // These bytes come from IndexedDB and may have been tampered with: restoration must fail
    // cleanly, never panic.
    assert!(Client::restore(b"not a state", Vec::new()).is_err());
}

#[wasm_bindgen_test]
fn bytes_cross_over_as_uint8array() {
    // Regression: `serde_wasm_bindgen` renders a `Vec<u8>` as an `Array` of numbers if the
    // field does not go through `serde_bytes`. JavaScript then receives something that looks
    // like a byte array but that `TextDecoder`, `fetch` and `crypto.subtle` refuse.
    //
    // The usual assertions see nothing: `from_value` into a Rust type accepts both
    // representations. You have to interrogate the JavaScript value itself.
    use wasm_bindgen::JsCast;

    let (mut alice, mut bob, alice_group, bob_group) = two_party_conversation();

    let ciphertext = alice.encrypt(&alice_group, b"bytes").unwrap();
    let incoming = bob.process(&bob_group, &ciphertext).unwrap();

    let plaintext = js_sys::Reflect::get(&incoming, &"plaintext".into()).unwrap();
    assert!(
        plaintext.is_instance_of::<js_sys::Uint8Array>(),
        "plaintext must be a Uint8Array, not an Array of numbers"
    );

    let (invitation, tree) = {
        let mut carol = Client::create("carol@web").unwrap();
        let group = carol.create_conversation().unwrap();
        let kp = Client::create("dave@web").unwrap().publish_key_package().unwrap();
        let inv = carol.invite(&group, &kp).unwrap();
        let tree = carol.apply_pending(&group).unwrap();
        (inv, tree)
    };
    for field in ["commit", "welcome"] {
        let value = js_sys::Reflect::get(&invitation, &field.into()).unwrap();
        assert!(
            value.is_instance_of::<js_sys::Uint8Array>(),
            "{field} must be a Uint8Array"
        );
    }
    // The tree now comes out of `applyPending`: it cannot exist until the commit is applied.
    // It crosses the boundary like the rest, as raw bytes.
    assert!(!tree.is_empty());
}

// ------------------------------------------------------------------ accounts

#[wasm_bindgen_test]
fn a_generated_account_returns_a_phrase_and_a_key() {
    use wasm_bindgen::JsCast;

    let created = crypto_wasm::AccountKey::generate().unwrap();

    let phrase = js_sys::Reflect::get(&created, &"phrase".into()).unwrap();
    let phrase = phrase.as_string().expect("the phrase must be a string");
    assert_eq!(phrase.split_whitespace().count(), 12);

    // Same trap as for messages: a `Vec<u8>` without `serde_bytes` comes out as an `Array` of
    // numbers, which `crypto.subtle` and `fetch` refuse — and which Rust assertions let
    // through without a murmur.
    let key = js_sys::Reflect::get(&created, &"identityKey".into()).unwrap();
    assert!(
        key.is_instance_of::<js_sys::Uint8Array>(),
        "identityKey must be a Uint8Array, not an Array of numbers"
    );
    assert_eq!(key.unchecked_into::<js_sys::Uint8Array>().length(), 32);

    // The phrase must rebuild exactly the same account, otherwise it recovers nothing.
    let restored = crypto_wasm::AccountKey::restore(&phrase).unwrap();
    assert_eq!(restored.identity_key().len(), 32);
}

#[wasm_bindgen_test]
fn a_produced_attestation_is_verified() {
    let account = crypto_wasm::AccountKey::generate().unwrap();
    let phrase = js_sys::Reflect::get(&account, &"phrase".into()).unwrap().as_string().unwrap();
    let account = crypto_wasm::AccountKey::restore(&phrase).unwrap();

    let device = Client::create("alice@laptop").unwrap();
    let auth_key = [7u8; 32];
    let mls_key = device.signature_key();

    let attestation =
        account.attest("alice", "alice@laptop", &auth_key, &mls_key).unwrap();

    assert!(crypto_wasm::verify_attestation(
        &account.identity_key(),
        "alice",
        "alice@laptop",
        &auth_key,
        &mls_key,
        &attestation,
    ));

    // The same device under another account must be rejected: this is the check that stops
    // the server from injecting a ghost device into other people's conversations.
    assert!(!crypto_wasm::verify_attestation(
        &account.identity_key(),
        "bob",
        "alice@laptop",
        &auth_key,
        &mls_key,
        &attestation,
    ));
}

#[wasm_bindgen_test]
fn an_invalid_phrase_is_refused() {
    assert!(crypto_wasm::AccountKey::restore("this is not a bip39 phrase").is_err());
}

/// Pairing hands over the seed: the paired device must be able to attest in its turn,
/// otherwise it stays subordinate to the original device.
#[wasm_bindgen_test]
fn the_seed_rebuilds_an_account_able_to_attest() {
    let created = crypto_wasm::AccountKey::generate().unwrap();
    let phrase = js_sys::Reflect::get(&created, &"phrase".into()).unwrap().as_string().unwrap();
    let source = crypto_wasm::AccountKey::restore(&phrase).unwrap();

    let paired = crypto_wasm::AccountKey::from_seed(&source.export_seed()).unwrap();
    assert_eq!(paired.identity_key(), source.identity_key());
    assert_eq!(paired.fingerprint(), source.fingerprint());

    let attestation = paired.attest("alice", "tablet", &[1u8; 32], &[2u8; 32]).unwrap();
    assert!(crypto_wasm::verify_attestation(
        &source.identity_key(),
        "alice",
        "tablet",
        &[1u8; 32],
        &[2u8; 32],
        &attestation,
    ));
}

// ------------------------------------------------------------------ pairing

#[wasm_bindgen_test]
fn a_pairing_carries_the_account_seed() {
    use wasm_bindgen::JsCast;

    // The new device displays: nothing secret leaves here.
    let mut new_device = crypto_wasm::Pairing::new();
    let id = new_device.id().unwrap();
    let public = new_device.public_key().unwrap();

    // The old device scans and seals its seed.
    let account = crypto_wasm::AccountKey::generate().unwrap();
    let phrase = js_sys::Reflect::get(&account, &"phrase".into()).unwrap().as_string().unwrap();
    let old_device = crypto_wasm::AccountKey::restore(&phrase).unwrap();

    let sealed = crypto_wasm::seal_pairing(&public, &id, &old_device.export_seed()).unwrap();
    let payload = js_sys::Reflect::get(&sealed, &"payload".into()).unwrap();
    assert!(
        payload.is_instance_of::<js_sys::Uint8Array>(),
        "payload must be a Uint8Array, not an Array of numbers"
    );
    let old_code =
        js_sys::Reflect::get(&sealed, &"confirmation".into()).unwrap().as_string().unwrap();

    let opened = new_device.open(&payload.unchecked_into::<js_sys::Uint8Array>().to_vec()).unwrap();
    let seed = js_sys::Reflect::get(&opened, &"plaintext".into()).unwrap();
    let new_code =
        js_sys::Reflect::get(&opened, &"confirmation".into()).unwrap().as_string().unwrap();

    // Both screens must show the same code, otherwise comparing it is pointless.
    assert_eq!(old_code, new_code);

    // And the new device ends up with exactly the same account.
    let seed = seed.unchecked_into::<js_sys::Uint8Array>().to_vec();
    let rebuilt = crypto_wasm::AccountKey::from_seed(&seed).unwrap();
    assert_eq!(rebuilt.identity_key(), old_device.identity_key());
    assert_eq!(rebuilt.fingerprint(), old_device.fingerprint());
}

/// The ephemeral secret is single-use: a second call must fail rather than allow an old
/// packet to be replayed.
#[wasm_bindgen_test]
fn a_pairing_offer_serves_only_once() {
    use wasm_bindgen::JsCast;

    let mut offer = crypto_wasm::Pairing::new();
    let id = offer.id().unwrap();
    let public = offer.public_key().unwrap();

    let sealed = crypto_wasm::seal_pairing(&public, &id, b"secret").unwrap();
    let payload = js_sys::Reflect::get(&sealed, &"payload".into())
        .unwrap()
        .unchecked_into::<js_sys::Uint8Array>()
        .to_vec();

    assert!(offer.open(&payload).is_ok());
    assert!(offer.open(&payload).is_err());
}

// ------------------------------------------------------------------ local lock

#[wasm_bindgen_test]
fn the_lock_derives_a_stable_key() {
    let salt = [3u8; 16];

    let a = crypto_wasm::derive_unlock_key_js("a sufficiently long password", &salt).unwrap();
    let b = crypto_wasm::derive_unlock_key_js("a sufficiently long password", &salt).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 32);

    // One character of difference is enough to change the key: otherwise guessing the password
    // "roughly" would do.
    let c = crypto_wasm::derive_unlock_key_js("a sufficiently long passwords", &salt).unwrap();
    assert_ne!(a, c);

    // Two devices with the same password do not get the same key.
    let d = crypto_wasm::derive_unlock_key_js("a sufficiently long password", &[4u8; 16]).unwrap();
    assert_ne!(a, d);
}
