//! Tests de la session gateway.
//!
//! Serveur réel, base réelle, vraie WebSocket. Le protocole gateway déplace l'authentification
//! de la requête vers la session : ce qui se vérifiait gratuitement à chaque appel HTTP ne se
//! vérifie plus qu'aux moments où ce module décide de le faire. Ces tests figent ces moments.

mod common;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use common::{Device, TestAccount, TestServer, envoyer, lire, ouvrir, session, start, unique};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

async fn groupe_avec(server: &TestServer, alice: &Device, bob: &Device) -> Vec<u8> {
    let _ = server;
    let group_id = unique("groupe").into_bytes();

    alice
        .post(
            &format!("/v1/groups/{}/members", hex::encode(&group_id)),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    group_id
}

/// Même chose, dotée de la clé de dépôt qu'exige le chemin anonyme des signaux.
async fn groupe_avec_cle(alice: &Device, bob: &Device, posting_key: &[u8]) -> Vec<u8> {
    let group_id = unique("groupe").into_bytes();

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

// ------------------------------------------------------------------ authentification

/// **Le test qui justifie le défi.**
///
/// Une socket ouverte mais non authentifiée ne doit rien obtenir. C'est la seule barrière : à ce
/// stade, aucun extracteur signé n'est passé et le pair n'a rien prouvé.
#[tokio::test]
async fn un_identify_sans_signature_valide_n_abonne_rien() {
    let server = start().await;
    let device = Device::register(&server, &unique("alice")).await;
    let (mut socket, challenge) = ouvrir(&server).await;

    envoyer(
        &mut socket,
        serde_json::json!({
            "op": "identify",
            "device_id": device.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            // Une signature valide en soi, mais produite sur autre chose.
            "signature": device.sign_challenge(b"un autre defi"),
        }),
    )
    .await;

    let reponse = lire(&mut socket).await;

    assert_eq!(
        reponse.map(|frame| frame["op"].as_str().unwrap().to_owned()),
        Some("error".to_owned()),
        "une signature invalide doit être refusée, jamais ignorée",
    );

    assert!(lire(&mut socket).await.is_none(), "et la socket doit être fermée derrière");
}

/// **Le test qui justifie la séparation de domaine.**
///
/// La clé qui ouvre une session est la même que celle qui signe les requêtes HTTP. Sans domaine
/// propre, capter n'importe quelle signature HTTP suffirait à ouvrir une session au nom de son
/// auteur — et le défi ne servirait plus à rien.
#[tokio::test]
async fn une_signature_http_n_ouvre_pas_de_session() {
    let server = start().await;
    let device = Device::register(&server, &unique("alice")).await;
    let (mut socket, challenge) = ouvrir(&server).await;

    envoyer(
        &mut socket,
        serde_json::json!({
            "op": "identify",
            "device_id": device.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            "signature": device.sign_challenge_as_http(&challenge),
        }),
    )
    .await;

    assert_eq!(lire(&mut socket).await.map(|f| f["op"].as_str().unwrap().to_owned()).as_deref(),
        Some("error"));
}

/// **Le test qui justifie que le défi vienne du serveur.**
///
/// C'est ce qui distingue ce chemin du HTTP, dont `server::auth` documente qu'il reste rejouable
/// pendant soixante secondes faute de mémoriser les nonces. Ici, une signature parfaitement
/// valide pour une session ne vaut rien pour la suivante.
#[tokio::test]
async fn un_nonce_de_hello_ne_peut_pas_etre_rejoue() {
    let server = start().await;
    let device = Device::register(&server, &unique("alice")).await;

    // Une première ouverture, réussie, dont on capte le couple défi / signature.
    let (mut premiere, challenge) = ouvrir(&server).await;
    let signature = device.sign_challenge(&challenge);
    envoyer(
        &mut premiere,
        serde_json::json!({
            "op": "identify",
            "device_id": device.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            "signature": signature,
        }),
    )
    .await;
    assert_eq!(lire(&mut premiere).await.unwrap()["op"], "ready");

    // Le même couple, rejoué sur une seconde socket, qui a reçu un autre défi.
    let (mut seconde, _autre_challenge) = ouvrir(&server).await;
    envoyer(
        &mut seconde,
        serde_json::json!({
            "op": "identify",
            "device_id": device.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            "signature": signature,
        }),
    )
    .await;

    assert_eq!(
        lire(&mut seconde).await.map(|f| f["op"].as_str().unwrap().to_owned()).as_deref(),
        Some("error"),
        "le nonce renvoyé doit être celui qui a été servi à CETTE socket",
    );
}

/// Un appareil déjà révoqué n'ouvre pas de session.
#[tokio::test]
async fn un_appareil_revoque_n_ouvre_pas_de_session() {
    let server = start().await;
    let compte = TestAccount::create(&server, &unique("compte")).await;
    let portable = compte.device(&server, "portable").await;
    let tablette = compte.device(&server, "tablette").await;

    assert!(compte.revoke(&portable, &tablette.id).await.status().is_success());

    let (mut socket, challenge) = ouvrir(&server).await;
    envoyer(
        &mut socket,
        serde_json::json!({
            "op": "identify",
            "device_id": tablette.id,
            "nonce": BASE64_STANDARD.encode(&challenge),
            "signature": tablette.sign_challenge(&challenge),
        }),
    )
    .await;

    assert_eq!(
        lire(&mut socket).await.map(|f| f["op"].as_str().unwrap().to_owned()).as_deref(),
        Some("error"),
    );
}

// ------------------------------------------------------------------ contrôle d'accès

/// **Le test qui justifie la revérification à chaque `subscribe`.**
///
/// Se fier à la liste des groupes calculée à l'ouverture laisserait un appareil s'abonner à un
/// groupe où il n'a jamais mis les pieds — l'abonnement étant, ici, tout le contrôle d'accès à
/// la diffusion.
#[tokio::test]
async fn subscribe_sur_un_groupe_non_membre_est_refuse() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let etranger = Device::register(&server, &unique("etranger")).await;

    let group_id = groupe_avec(&server, &alice, &bob).await;

    let mut socket = session(&server, &etranger, serde_json::json!([])).await;
    assert_eq!(lire(&mut socket).await.unwrap()["op"], "ready");

    envoyer(
        &mut socket,
        serde_json::json!({ "op": "subscribe", "group_id": hex::encode(&group_id) }),
    )
    .await;

    let refus = lire(&mut socket).await.expect("un refus, pas un silence");
    assert_eq!(refus["op"], "error");

    // Et l'abonnement n'a pas eu lieu : un dépôt dans ce groupe ne lui parvient pas.
    deposer(&server, &alice, &group_id, b"pour les membres").await;

    assert!(
        lire(&mut socket).await.is_none(),
        "un refus qui laisserait l'abonnement en place serait pire qu'inutile",
    );
}

/// **Le test qui justifie [`revalidate`].**
///
/// C'est la contrepartie directe du passage à une authentification par session : sans cette
/// vérification, révoquer un appareil ne le couperait de rien tant qu'il garde sa socket.
#[tokio::test]
async fn un_appareil_revoque_voit_sa_session_fermee() {
    let server = start().await;
    let compte = TestAccount::create(&server, &unique("compte")).await;
    let portable = compte.device(&server, "portable").await;
    let tablette = compte.device(&server, "tablette").await;

    let mut socket = session(&server, &tablette, serde_json::json!([])).await;
    assert_eq!(lire(&mut socket).await.unwrap()["op"], "ready");

    // La session était parfaitement légitime au moment de son ouverture.
    envoyer(&mut socket, serde_json::json!({ "op": "heartbeat" })).await;
    assert_eq!(lire(&mut socket).await.unwrap()["op"], "heartbeat_ack");

    assert!(compte.revoke(&portable, &tablette.id).await.status().is_success());

    envoyer(&mut socket, serde_json::json!({ "op": "heartbeat" })).await;
    assert_eq!(lire(&mut socket).await.unwrap()["op"], "error");
    assert!(lire(&mut socket).await.is_none(), "la session doit être fermée, pas seulement avertie");
}

/// Un retrait de groupe coupe la diffusion d'une session déjà ouverte.
///
/// Le SSE figeait ses abonnements à l'ouverture : un membre évincé continuait d'être servi
/// jusqu'à ce qu'il se reconnecte de lui-même.
#[tokio::test]
async fn un_retrait_de_groupe_coupe_une_session_ouverte() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let group_id = groupe_avec(&server, &alice, &bob).await;

    let mut socket = session(&server, &bob, serde_json::json!([])).await;
    let ready = lire(&mut socket).await.unwrap();
    assert_eq!(ready["op"], "ready");
    assert!(ready["groups"].as_array().unwrap().contains(&serde_json::json!(hex::encode(&group_id))));

    // Bob est retiré du groupe, puis bat une fois pour que la session soit recalculée.
    alice
        .post(
            &format!("/v1/groups/{}/members/remove", hex::encode(&group_id)),
            serde_json::json!({ "device_ids": [bob.id] }),
        )
        .await;

    envoyer(&mut socket, serde_json::json!({ "op": "heartbeat" })).await;
    assert_eq!(lire(&mut socket).await.unwrap()["op"], "heartbeat_ack");

    deposer(&server, &alice, &group_id, b"apres le retrait").await;

    assert!(lire(&mut socket).await.is_none(), "un évincé ne doit plus rien recevoir");
}

// ------------------------------------------------------------------ diffusion

/// Le chemin nominal : un dépôt réveille les sessions abonnées.
#[tokio::test]
async fn un_depot_parvient_aux_sessions_abonnees() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let group_id = groupe_avec(&server, &alice, &bob).await;

    let mut socket = session(&server, &bob, serde_json::json!([])).await;
    assert_eq!(lire(&mut socket).await.unwrap()["op"], "ready");

    deposer(&server, &alice, &group_id, b"deja chiffre").await;

    let frame = lire(&mut socket).await.expect("l'enveloppe doit être annoncée");
    assert_eq!(frame["op"], "envelope");
    assert_eq!(frame["group_id"], hex::encode(&group_id));

    // Le numéro de séquence, et rien d'autre : le contenu se lit par le chemin HTTP, qui
    // revérifie l'appartenance.
    assert!(frame.get("payload").is_none(), "la diffusion ne doit jamais porter de contenu");
}

/// **Le test qui justifie le rattrapage.**
///
/// Sans lui, un client qui se reconnecte doit relever chaque conversation par une requête signée
/// pour découvrir qu'il n'a rien manqué — c'est-à-dire redonner au serveur le journal d'activité
/// que la connexion longue existait pour lui retirer.
#[tokio::test]
async fn le_resume_rattrape_les_seq_manques() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let group_id = groupe_avec(&server, &alice, &bob).await;

    // Trois dépôts pendant que Bob est absent.
    for i in 0..3 {
        deposer(&server, &alice, &group_id, format!("message {i}").as_bytes()).await;
    }

    // Les séquences commencent à 1 : Bob revient en annonçant n'avoir vu que la première.
    let mut socket = session(
        &server,
        &bob,
        serde_json::json!([{ "group_id": hex::encode(&group_id), "seq": 1 }]),
    )
    .await;
    assert_eq!(lire(&mut socket).await.unwrap()["op"], "ready");

    let mut recues = Vec::new();
    for _ in 0..2 {
        let frame = lire(&mut socket).await.expect("le retard doit être annoncé");
        assert_eq!(frame["op"], "envelope");
        recues.push(frame["seq"].as_i64().unwrap());
    }

    assert_eq!(recues, vec![2, 3], "seules les séquences postérieures au curseur, dans l'ordre");

    // Et rien de plus : le curseur borne le rattrapage par le haut comme par le bas.
    assert!(lire(&mut socket).await.is_none());
}

/// Un curseur sur un groupe étranger ne dit pas si ce groupe existe.
///
/// Répondre « inconnu » plutôt que de se taire ferait du rattrapage un oracle d'existence de
/// groupe, accessible à tout appareil enregistré.
#[tokio::test]
async fn un_curseur_sur_un_groupe_etranger_est_ignore_en_silence() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let etranger = Device::register(&server, &unique("etranger")).await;
    let group_id = groupe_avec(&server, &alice, &bob).await;

    deposer(&server, &alice, &group_id, b"prive").await;

    let mut socket = session(
        &server,
        &etranger,
        serde_json::json!([{ "group_id": hex::encode(&group_id), "seq": 0 }]),
    )
    .await;

    assert_eq!(lire(&mut socket).await.unwrap()["op"], "ready");
    assert!(lire(&mut socket).await.is_none(), "ni séquence, ni erreur : rien");
}

// ------------------------------------------------------------------ fanout multi-instance

/// **Le test qui prouve que le hub n'est plus enfermé dans son processus.**
///
/// Deux instances sur la même base, un signal déposé sur l'une, un client connecté à l'autre.
/// Sans `LISTEN/NOTIFY`, ce test échoue — et c'est exactement l'état de production qu'il décrit :
/// deux instances derrière un répartiteur de charge donnent deux populations qui ne se voient
/// pas.
#[tokio::test]
async fn un_signal_traverse_deux_instances() {
    let premiere = start().await;
    let seconde = start().await;

    let alice = Device::register(&premiere, &unique("alice")).await;
    let bob = Device::register(&premiere, &unique("bob")).await;

    let posting_key = [42u8; 32];
    let group_id = groupe_avec_cle(&alice, &bob, &posting_key).await;

    // Bob écoute sur la SECONDE instance.
    let mut socket = session(&seconde, &bob, serde_json::json!([])).await;
    assert_eq!(lire(&mut socket).await.unwrap()["op"], "ready");

    // Alice signale sur la PREMIÈRE.
    let corps = b"indicateur-de-frappe-chiffre";
    let reponse = post_signal(&premiere, &group_id, &posting_key, corps).await;
    assert_eq!(reponse.status(), 204, "dépôt du signal refusé");

    let frame = lire(&mut socket).await.expect("le signal doit traverser les deux instances");
    assert_eq!(frame["op"], "signal");
    assert_eq!(BASE64_STANDARD.decode(frame["payload"].as_str().unwrap()).unwrap(), corps);
}

/// Le partitionnement n'est utile que s'il est élagué : une lecture ne doit toucher qu'une
/// partition sur seize.
///
/// C'est la propriété qui a fait choisir `HASH(group_id)` plutôt qu'un découpage temporel, et
/// elle se perdrait au premier `WHERE` qui cesserait de porter sur `group_id`.
#[tokio::test]
async fn une_lecture_d_enveloppes_ne_touche_qu_une_partition() {
    let server = start().await;

    let plan: Vec<(String,)> = sqlx::query_as(
        "EXPLAIN SELECT seq, payload FROM envelopes
         WHERE group_id = $1 AND seq > 0 ORDER BY seq LIMIT 200",
    )
    .bind(b"un-groupe-quelconque".to_vec())
    .fetch_all(&server.pool)
    .await
    .unwrap();

    let plan = plan.into_iter().map(|(ligne,)| ligne).collect::<Vec<_>>().join("\n");
    let touchees = plan.matches("envelopes_p").count();

    assert_eq!(touchees, 1, "une partition attendue, le plan en visite {touchees} :\n{plan}");
}

// ------------------------------------------------------------------ utilitaires

async fn deposer(server: &TestServer, device: &Device, group_id: &[u8], corps: &[u8]) {
    let _ = server;

    let reponse = device
        .post(
            &format!("/v1/groups/{}/envelopes", hex::encode(group_id)),
            serde_json::json!({ "payload": BASE64_STANDARD.encode(corps) }),
        )
        .await;

    assert!(reponse.status().is_success(), "dépôt refusé : {}", reponse.status());

    // La diffusion est asynchrone : laisser le hub la porter avant de constater son absence,
    // sans quoi un test négatif passerait pour la mauvaise raison.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
}

/// Dépose un signal éphémère par le chemin anonyme : MAC du groupe, aucune signature
/// d'appareil.
///
/// C'est le seul chemin par lequel un signal peut passer, sur la gateway comme en HTTP :
/// `verify_signal` refuse un groupe sans clé de dépôt plutôt que de retomber sur une
/// vérification par identité.
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
