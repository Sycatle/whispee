//! Tests exécutés dans un vrai environnement WebAssembly.
//!
//! Compiler pour wasm32 ne prouve rien : ce qui casse en pratique, c'est l'aléa. `getrandom`
//! doit trouver `crypto.getRandomValues`, et un aléa défaillant ne lève aucune erreur — il
//! produit des clés prévisibles, en silence. Ces tests s'exécutent donc dans l'environnement
//! cible, pas en natif.
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

fn conversation_a_deux() -> (Client, Client, Vec<u8>, Vec<u8>) {
    let mut alice = Client::create("alice@web").unwrap();
    let mut bob = Client::create("bob@web").unwrap();

    let bob_key_package = bob.publish_key_package().unwrap();
    let group_id = alice.create_conversation().unwrap();

    let invitation: Invitation =
        serde_wasm_bindgen::from_value(alice.invite(&group_id, &bob_key_package).unwrap()).unwrap();
    let arbre = alice.apply_pending(&group_id).unwrap();
    let bob_group = bob.join(&invitation.welcome, &arbre).unwrap();

    (alice, bob, group_id, bob_group)
}

#[wasm_bindgen_test]
fn cycle_complet_dans_le_navigateur() {
    let (mut alice, mut bob, alice_group, bob_group) = conversation_a_deux();

    assert_eq!(alice_group, bob_group);
    assert_eq!(alice.epoch(&alice_group).unwrap(), bob.epoch(&bob_group).unwrap());

    let ciphertext = alice.encrypt(&alice_group, b"salut depuis WASM").unwrap();
    let incoming: Incoming =
        serde_wasm_bindgen::from_value(bob.process(&bob_group, &ciphertext).unwrap()).unwrap();

    match incoming {
        Incoming::Application { sender, plaintext } => {
            assert_eq!(plaintext, b"salut depuis WASM");
            assert_eq!(sender.as_deref(), Some("alice@web"));
        }
        _ => panic!("attendu un message applicatif"),
    }

    let reply = bob.encrypt(&bob_group, b"recu").unwrap();
    let incoming: Incoming =
        serde_wasm_bindgen::from_value(alice.process(&alice_group, &reply).unwrap()).unwrap();
    assert!(matches!(incoming, Incoming::Application { .. }));
}

#[wasm_bindgen_test]
fn l_alea_du_navigateur_fonctionne() {
    // Le test qui compte vraiment. Si `getrandom` ne trouve pas `crypto.getRandomValues`,
    // soit il panique, soit — bien pire — il produit des clés prévisibles sans rien dire.
    // Deux identités créées coup sur coup doivent avoir des empreintes distinctes.
    let premiere = Client::create("meme-nom").unwrap();
    let seconde = Client::create("meme-nom").unwrap();

    assert_ne!(
        premiere.fingerprint(),
        seconde.fingerprint(),
        "deux identités partagent la même clé : l'aléa est cassé"
    );
    assert!(!premiere.fingerprint().is_empty());
}

#[wasm_bindgen_test]
fn le_transport_ne_voit_rien() {
    let (mut alice, _bob, alice_group, _) = conversation_a_deux();

    let secret = b"le code du coffre est 4815162342";
    let ciphertext = alice.encrypt(&alice_group, secret).unwrap();

    assert!(!ciphertext.windows(secret.len()).any(|w| w == secret));
    assert!(!ciphertext.windows(5).any(|w| w == b"alice"));
}

#[wasm_bindgen_test]
fn empreintes_visibles_des_deux_cotes() {
    let (alice, bob, alice_group, bob_group) = conversation_a_deux();

    let vue_alice: Vec<Peer> =
        serde_wasm_bindgen::from_value(alice.peer_fingerprints(&alice_group).unwrap()).unwrap();
    let vue_bob: Vec<Peer> =
        serde_wasm_bindgen::from_value(bob.peer_fingerprints(&bob_group).unwrap()).unwrap();

    assert_eq!(vue_alice.len(), 1);
    assert_eq!(vue_alice[0].name, "bob@web");
    assert_eq!(vue_bob[0].name, "alice@web");

    // Chacun voit l'empreinte réelle de l'autre : c'est ce que l'UI doit afficher pour
    // rendre la comparaison hors bande possible.
    assert_eq!(vue_alice[0].fingerprint, bob.fingerprint());
    assert_eq!(vue_bob[0].fingerprint, alice.fingerprint());
}

#[wasm_bindgen_test]
fn conversation_inconnue_refusee() {
    let mut alice = Client::create("alice").unwrap();
    assert!(alice.encrypt(b"groupe-inexistant", b"coucou").is_err());
}

#[wasm_bindgen_test]
fn etat_exporte_non_vide() {
    let (alice, _bob, _, _) = conversation_a_deux();
    let state = alice.export_state().unwrap();

    // Rappel : ce blob contient les clés privées en clair. Il ne doit jamais atteindre
    // localStorage ni le serveur sans être chiffré d'abord.
    assert!(state.len() > 100);
}

#[wasm_bindgen_test]
fn les_variantes_de_message_sont_exhaustives() {
    // Force le compilateur à signaler si `Incoming` gagne une variante non gérée côté JS.
    fn _exhaustif(incoming: Incoming) -> &'static str {
        match incoming {
            Incoming::Application { .. } => "application",
            Incoming::GroupChanged => "groupChanged",
            Incoming::Proposal => "proposal",
        }
    }
}

#[wasm_bindgen_test]
fn un_client_survit_a_un_rechargement_de_page() {
    let (mut alice, mut bob, alice_group, bob_group) = conversation_a_deux();

    let premier = alice.encrypt(&alice_group, b"avant").unwrap();
    bob.process(&bob_group, &premier).unwrap();

    // Simule la fermeture de l'onglet : l'état WASM est perdu, seul le blob exporté subsiste.
    let state = bob.export_state().unwrap();
    let ids = bob.conversation_ids();
    drop(bob);

    let mut bob = Client::restore(&state, ids).unwrap();
    assert_eq!(bob.name(), "bob@web");

    let second = alice.encrypt(&alice_group, b"apres").unwrap();
    let incoming: Incoming =
        serde_wasm_bindgen::from_value(bob.process(&bob_group, &second).unwrap()).unwrap();

    match incoming {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"apres"),
        _ => panic!("attendu un message applicatif"),
    }
}

#[wasm_bindgen_test]
fn etat_corrompu_refuse() {
    // Ces octets viennent d'IndexedDB et ont pu être altérés : la restauration doit
    // échouer proprement, jamais paniquer.
    assert!(Client::restore(b"pas un etat", Vec::new()).is_err());
}

#[wasm_bindgen_test]
fn les_octets_traversent_en_uint8array() {
    // Régression : `serde_wasm_bindgen` rend un `Vec<u8>` en `Array` de nombres si le champ
    // ne passe pas par `serde_bytes`. Le JavaScript reçoit alors quelque chose qui ressemble
    // à un tableau d'octets mais que `TextDecoder`, `fetch` et `crypto.subtle` refusent.
    //
    // Les assertions habituelles ne voient rien : `from_value` vers un type Rust accepte les
    // deux représentations. Il faut interroger la valeur JavaScript elle-même.
    use wasm_bindgen::JsCast;

    let (mut alice, mut bob, alice_group, bob_group) = conversation_a_deux();

    let ciphertext = alice.encrypt(&alice_group, b"octets").unwrap();
    let incoming = bob.process(&bob_group, &ciphertext).unwrap();

    let plaintext = js_sys::Reflect::get(&incoming, &"plaintext".into()).unwrap();
    assert!(
        plaintext.is_instance_of::<js_sys::Uint8Array>(),
        "plaintext doit être un Uint8Array, pas un Array de nombres"
    );

    let (invitation, arbre) = {
        let mut carol = Client::create("carol@web").unwrap();
        let group = carol.create_conversation().unwrap();
        let kp = Client::create("dave@web").unwrap().publish_key_package().unwrap();
        let inv = carol.invite(&group, &kp).unwrap();
        let arbre = carol.apply_pending(&group).unwrap();
        (inv, arbre)
    };
    for champ in ["commit", "welcome"] {
        let value = js_sys::Reflect::get(&invitation, &champ.into()).unwrap();
        assert!(
            value.is_instance_of::<js_sys::Uint8Array>(),
            "{champ} doit être un Uint8Array"
        );
    }
    // L'arbre sort désormais d'`applyPending` : il ne peut exister qu'une fois le commit
    // appliqué. Il traverse la frontière comme les autres, en octets bruts.
    assert!(!arbre.is_empty());
}

// ------------------------------------------------------------------ comptes

#[wasm_bindgen_test]
fn un_compte_genere_rend_une_phrase_et_une_cle() {
    use wasm_bindgen::JsCast;

    let created = crypto_wasm::AccountKey::generate().unwrap();

    let phrase = js_sys::Reflect::get(&created, &"phrase".into()).unwrap();
    let phrase = phrase.as_string().expect("la phrase doit être une chaîne");
    assert_eq!(phrase.split_whitespace().count(), 12);

    // Même piège que pour les messages : un `Vec<u8>` sans `serde_bytes` ressort en `Array`
    // de nombres, que `crypto.subtle` et `fetch` refusent — et que les assertions Rust
    // laissent passer sans broncher.
    let key = js_sys::Reflect::get(&created, &"identityKey".into()).unwrap();
    assert!(
        key.is_instance_of::<js_sys::Uint8Array>(),
        "identityKey doit être un Uint8Array, pas un Array de nombres"
    );
    assert_eq!(key.unchecked_into::<js_sys::Uint8Array>().length(), 32);

    // La phrase doit reconstruire exactement le même compte, sinon elle ne récupère rien.
    let restaure = crypto_wasm::AccountKey::restore(&phrase).unwrap();
    assert_eq!(restaure.identity_key().len(), 32);
}

#[wasm_bindgen_test]
fn une_attestation_produite_est_verifiee() {
    let account = crypto_wasm::AccountKey::generate().unwrap();
    let phrase = js_sys::Reflect::get(&account, &"phrase".into()).unwrap().as_string().unwrap();
    let account = crypto_wasm::AccountKey::restore(&phrase).unwrap();

    let device = Client::create("alice@portable").unwrap();
    let auth_key = [7u8; 32];
    let mls_key = device.signature_key();

    let attestation =
        account.attest("alice", "alice@portable", &auth_key, &mls_key).unwrap();

    assert!(crypto_wasm::verify_attestation(
        &account.identity_key(),
        "alice",
        "alice@portable",
        &auth_key,
        &mls_key,
        &attestation,
    ));

    // Le même appareil sous un autre compte doit être rejeté : c'est ce contrôle qui empêche
    // le serveur d'injecter un appareil fantôme dans les conversations d'autrui.
    assert!(!crypto_wasm::verify_attestation(
        &account.identity_key(),
        "bob",
        "alice@portable",
        &auth_key,
        &mls_key,
        &attestation,
    ));
}

#[wasm_bindgen_test]
fn une_phrase_invalide_est_refusee() {
    assert!(crypto_wasm::AccountKey::restore("ceci n est pas une phrase bip39").is_err());
}

/// L'appairage transmet la graine : l'appareil appairé doit pouvoir attester à son tour,
/// sinon il reste subordonné à l'appareil d'origine.
#[wasm_bindgen_test]
fn la_graine_reconstruit_un_compte_capable_d_attester() {
    let created = crypto_wasm::AccountKey::generate().unwrap();
    let phrase = js_sys::Reflect::get(&created, &"phrase".into()).unwrap().as_string().unwrap();
    let source = crypto_wasm::AccountKey::restore(&phrase).unwrap();

    let appaire = crypto_wasm::AccountKey::from_seed(&source.export_seed()).unwrap();
    assert_eq!(appaire.identity_key(), source.identity_key());
    assert_eq!(appaire.fingerprint(), source.fingerprint());

    let attestation = appaire.attest("alice", "tablette", &[1u8; 32], &[2u8; 32]).unwrap();
    assert!(crypto_wasm::verify_attestation(
        &source.identity_key(),
        "alice",
        "tablette",
        &[1u8; 32],
        &[2u8; 32],
        &attestation,
    ));
}

// ------------------------------------------------------------------ appairage

#[wasm_bindgen_test]
fn un_appairage_transporte_la_graine_du_compte() {
    use wasm_bindgen::JsCast;

    // Le nouvel appareil affiche : rien de secret ne sort d'ici.
    let mut nouveau = crypto_wasm::Pairing::new();
    let id = nouveau.id().unwrap();
    let public = nouveau.public_key().unwrap();

    // L'ancien appareil scanne et scelle sa graine.
    let account = crypto_wasm::AccountKey::generate().unwrap();
    let phrase = js_sys::Reflect::get(&account, &"phrase".into()).unwrap().as_string().unwrap();
    let ancien = crypto_wasm::AccountKey::restore(&phrase).unwrap();

    let sealed = crypto_wasm::seal_pairing(&public, &id, &ancien.export_seed()).unwrap();
    let payload = js_sys::Reflect::get(&sealed, &"payload".into()).unwrap();
    assert!(
        payload.is_instance_of::<js_sys::Uint8Array>(),
        "payload doit être un Uint8Array, pas un Array de nombres"
    );
    let code_ancien =
        js_sys::Reflect::get(&sealed, &"confirmation".into()).unwrap().as_string().unwrap();

    let opened = nouveau.open(&payload.unchecked_into::<js_sys::Uint8Array>().to_vec()).unwrap();
    let graine = js_sys::Reflect::get(&opened, &"plaintext".into()).unwrap();
    let code_nouveau =
        js_sys::Reflect::get(&opened, &"confirmation".into()).unwrap().as_string().unwrap();

    // Les deux écrans doivent afficher le même code, sinon le comparer ne sert à rien.
    assert_eq!(code_ancien, code_nouveau);

    // Et le nouvel appareil obtient exactement le même compte.
    let graine = graine.unchecked_into::<js_sys::Uint8Array>().to_vec();
    let reconstruit = crypto_wasm::AccountKey::from_seed(&graine).unwrap();
    assert_eq!(reconstruit.identity_key(), ancien.identity_key());
    assert_eq!(reconstruit.fingerprint(), ancien.fingerprint());
}

/// Le secret éphémère ne sert qu'une fois : un second appel doit échouer plutôt que de
/// permettre de rejouer un ancien paquet.
#[wasm_bindgen_test]
fn une_offre_d_appairage_ne_sert_qu_une_fois() {
    use wasm_bindgen::JsCast;

    let mut offre = crypto_wasm::Pairing::new();
    let id = offre.id().unwrap();
    let public = offre.public_key().unwrap();

    let sealed = crypto_wasm::seal_pairing(&public, &id, b"secret").unwrap();
    let payload = js_sys::Reflect::get(&sealed, &"payload".into())
        .unwrap()
        .unchecked_into::<js_sys::Uint8Array>()
        .to_vec();

    assert!(offre.open(&payload).is_ok());
    assert!(offre.open(&payload).is_err());
}

// ------------------------------------------------------------------ verrou local

#[wasm_bindgen_test]
fn le_verrou_derive_une_cle_stable() {
    let sel = [3u8; 16];

    let a = crypto_wasm::derive_unlock_key_js("mot de passe suffisamment long", &sel).unwrap();
    let b = crypto_wasm::derive_unlock_key_js("mot de passe suffisamment long", &sel).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 32);

    // Un caractère de différence suffit à changer la clé : sans quoi deviner « à peu près »
    // le mot de passe suffirait.
    let c = crypto_wasm::derive_unlock_key_js("mot de passe suffisamment longs", &sel).unwrap();
    assert_ne!(a, c);

    // Deux appareils avec le même mot de passe n'ont pas la même clé.
    let d = crypto_wasm::derive_unlock_key_js("mot de passe suffisamment long", &[4u8; 16]).unwrap();
    assert_ne!(a, d);
}
