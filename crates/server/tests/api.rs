//! Tests d'intégration du delivery service, contre un vrai PostgreSQL.
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

// ---------------------------------------------------------------- enregistrement

#[tokio::test]
async fn enregistrement_idempotent_mais_identifiant_non_reprenable() {
    let server = start().await;
    let compte = TestAccount::create(&server, &unique("alice")).await;
    let id = unique("device");
    let device = compte.device(&server, &id).await;

    // Réenregistrer le même appareil doit passer : c'est le cas d'une réinstallation.
    assert!(device.register_under(&compte).await.status().is_success());

    // Réclamer le même identifiant avec d'autres clés doit être refusé, même en présentant
    // une attestation valide : sinon un membre du compte reprend l'identifiant d'un autre
    // appareil et hérite de ses accès.
    let usurpateur = Device::new(&server, &format!("{}:{id}", compte.handle));
    assert_eq!(usurpateur.register_under(&compte).await.status(), 409);
}

/// L'espace de noms des appareils est local au compte.
///
/// Sans cela le premier arrivé accapare « portable », « bureau », « téléphone », et le
/// deuxième utilisateur légitime se voit refuser l'enregistrement pour une raison qui n'a
/// rien à voir avec la sécurité.
#[tokio::test]
async fn deux_comptes_peuvent_nommer_leur_appareil_pareil() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let bob = TestAccount::create(&server, &unique("bob")).await;

    alice.device(&server, "portable").await;
    bob.device(&server, "portable").await;
}

/// Le préfixe n'est pas une convention de politesse : le serveur le vérifie. Sinon un compte
/// pourrait squatter l'espace de noms d'un autre.
#[tokio::test]
async fn un_identifiant_non_prefixe_est_refuse() {
    let server = start().await;
    let compte = TestAccount::create(&server, &unique("alice")).await;
    let device = Device::new(&server, &unique("portable"));

    assert_eq!(device.register_under(&compte).await.status(), 400);
}

#[tokio::test]
async fn cle_auth_de_mauvaise_taille_refusee() {
    let server = start().await;
    let compte = TestAccount::create(&server, &unique("alice")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/devices", server.base_url))
        .json(&serde_json::json!({
            "id": unique("device"),
            "handle": compte.handle,
            "auth_key": BASE64_STANDARD.encode([0u8; 16]),
            "mls_key": BASE64_STANDARD.encode([0u8; 32]),
            "attestation": BASE64_STANDARD.encode([0u8; 64]),
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

// ---------------------------------------------------------------- comptes et attestations

#[tokio::test]
async fn un_handle_ne_peut_pas_etre_repris_par_un_autre_compte() {
    let server = start().await;
    let handle = unique("alice");
    let compte = TestAccount::create(&server, &handle).await;

    // Même clé : réinstallation, accepté.
    let response = reqwest::Client::new()
        .post(format!("{}/v1/accounts", server.base_url))
        .json(&serde_json::json!({
            "handle": handle,
            "identity_key": compte.identity_key_b64(),
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Autre clé : refusé, sinon n'importe qui s'approprie un pseudonyme connu.
    let (autre, _) = crypto_core::Account::generate().unwrap();
    let response = reqwest::Client::new()
        .post(format!("{}/v1/accounts", server.base_url))
        .json(&serde_json::json!({
            "handle": handle,
            "identity_key": BASE64_STANDARD.encode(autre.identity_key()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);
}

/// Sans cette barrière, n'importe qui déclare un appareil dans le compte d'autrui et se fait
/// inviter dans ses conversations. C'est la version « en ligne » de l'attaque de l'appareil
/// fantôme ; la version « serveur complice » est couverte plus bas.
#[tokio::test]
async fn un_appareil_sans_attestation_valide_est_refuse() {
    let server = start().await;
    let compte = TestAccount::create(&server, &unique("alice")).await;
    let intrus = Device::new(&server, &unique("fantome"));

    let response = intrus.register_with(&compte.handle, &[0u8; 64]).await;

    assert_eq!(response.status(), 400, "une attestation nulle a été acceptée");
}

/// Un compte ne peut pas attester pour un autre : l'attestation ne vérifie que sous la clé du
/// compte visé.
#[tokio::test]
async fn l_attestation_d_un_compte_ne_vaut_pas_dans_un_autre() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let bob = TestAccount::create(&server, &unique("bob")).await;

    let intrus = Device::new(&server, &unique("device"));
    // Attestation authentique, produite par Alice, mais présentée dans le compte de Bob.
    let attestation = alice
        .account
        .attest(&bob.handle, &intrus.id, &[0u8; 32], intrus.mls_key())
        .unwrap();

    assert_eq!(intrus.register_with(&bob.handle, &attestation).await.status(), 400);
}

#[tokio::test]
async fn les_appareils_d_un_compte_sont_listes_avec_leurs_attestations() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, &unique("portable")).await;
    let tablette = alice.device(&server, &unique("tablette")).await;

    let body: serde_json::Value = portable
        .get(&format!("/v1/accounts/{}/devices", alice.handle))
        .await
        .json()
        .await
        .unwrap();

    assert_eq!(body["identity_key"], alice.identity_key_b64());
    let ids: Vec<&str> =
        body["devices"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&portable.id.as_str()));
    assert!(ids.contains(&tablette.id.as_str()));

    // Chaque attestation servie doit vérifier sous la clé du compte : c'est ce que le client
    // refera de son côté, et ce sur quoi il se fonde réellement.
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

/// **Le test qui compte.**
///
/// On ne simule pas un serveur malveillant : on l'incarne. L'appareil fantôme est inséré
/// directement en SQL, en contournant entièrement la validation de l'endpoint — exactement ce
/// que ferait un opérateur, un attaquant ayant obtenu la base, ou une injonction judiciaire.
///
/// Le serveur le sert ensuite sans broncher : il n'a aucun moyen de savoir qu'il ment. La
/// seule chose qui protège Alice est qu'elle revérifie l'attestation elle-même, et que le
/// serveur ne peut pas la produire faute de détenir la clé du compte de Bob.
///
/// Si ce test venait à passer parce que le serveur filtre, la protection serait illusoire :
/// elle reposerait sur la bonne volonté de la partie contre laquelle elle est censée protéger.
#[tokio::test]
async fn un_appareil_fantome_injecte_en_sql_ne_passe_pas_la_verification_du_client() {
    let server = start().await;
    let bob = TestAccount::create(&server, &unique("bob")).await;
    let _legitime = bob.device(&server, &unique("portable")).await;
    let alice = Device::register(&server, &unique("alice")).await;

    // Le serveur fabrique un appareil qu'il contrôle, dans le compte de Bob, avec une
    // attestation quelconque — il ne peut pas en produire une valide.
    let fantome = unique("fantome");
    sqlx::query(
        "INSERT INTO devices (id, handle, auth_key, mls_key, attestation)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&fantome)
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

    // Le serveur le sert bel et bien : la défense n'est pas qu'il refuse de mentir.
    let servi = body["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == fantome.as_str())
        .expect("le serveur devrait servir ce qu'on a inséré dans sa base");

    // Mais le client le rejette, parce que l'attestation ne vérifie pas.
    let claim = attest::DeviceClaim {
        handle: &bob.handle,
        device_id: &fantome,
        auth_key: &BASE64_STANDARD.decode(servi["auth_key"].as_str().unwrap()).unwrap(),
        mls_key: &BASE64_STANDARD.decode(servi["mls_key"].as_str().unwrap()).unwrap(),
    };
    let attestation = BASE64_STANDARD.decode(servi["attestation"].as_str().unwrap()).unwrap();
    let identity_key = BASE64_STANDARD.decode(body["identity_key"].as_str().unwrap()).unwrap();

    assert!(
        attest::verify(&identity_key, &claim, &attestation).is_err(),
        "un appareil fantôme a passé la vérification : tout le multi-appareils est compromis",
    );
}

/// La révocation exige la clé du compte. La signature de requête HTTP ne prouve que la
/// détention d'un appareil — or un appareil volé se révoquerait alors les autres pour rester
/// seul en place.
#[tokio::test]
async fn revoquer_sans_la_cle_du_compte_est_refuse() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, &unique("portable")).await;
    let tablette = alice.device(&server, &unique("tablette")).await;

    let response = portable
        .post(
            &format!("/v1/devices/{}/revoke", tablette.id),
            serde_json::json!({
                "revocation": BASE64_STANDARD.encode([0u8; 64]),
                "revoked_at": common::now(),
            }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

/// **Le certificat est ce qui empêche le serveur d'inventer une révocation.** Un compte tiers
/// qui pourrait signer à la place d'Alice ferait évincer ses appareils de tous ses groupes :
/// de la censure ciblée, durable, et impossible à distinguer d'une révocation légitime.
#[tokio::test]
async fn un_certificat_signe_par_un_autre_compte_est_refuse() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, &unique("portable")).await;
    let tablette = alice.device(&server, &unique("tablette")).await;

    // Mallory possède un compte parfaitement valide, mais pas celui d'Alice.
    let mallory = TestAccount::create(&server, &unique("mallory")).await;
    let revoked_at = common::now();
    let certificat = mallory.account.revoke(&alice.handle, &tablette.id, revoked_at).unwrap();

    let response = portable
        .post(
            &format!("/v1/devices/{}/revoke", tablette.id),
            serde_json::json!({
                "revocation": BASE64_STANDARD.encode(certificat),
                "revoked_at": revoked_at,
            }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

/// **Le test qui fige la limite des routes ouvertes.**
///
/// La création de compte n'est pas authentifiable — on ne peut pas signer avec une clé que le
/// serveur ne connaît pas encore — et elle écrit dans le journal de transparence, dont les
/// entrées ne se reprennent pas sans casser les preuves de consistance. Sans limite, un tiers
/// sans identité fait grossir indéfiniment la seule table du schéma qu'on ne sait pas nettoyer.
#[tokio::test]
async fn les_routes_ouvertes_refusent_au_dela_du_quota() {
    let server = common::start_with_throttle(2).await;

    for tour in 1..=2 {
        let reponse = reqwest::Client::new()
            .post(format!("{}/v1/accounts", server.base_url))
            .json(&serde_json::json!({
                "handle": unique("quota"),
                "identity_key": BASE64_STANDARD.encode([7u8; 32]),
            }))
            .send()
            .await
            .unwrap();

        assert!(reponse.status().is_success(), "la création {tour} devait passer");
    }

    let refusee = reqwest::Client::new()
        .post(format!("{}/v1/accounts", server.base_url))
        .json(&serde_json::json!({
            "handle": unique("quota"),
            "identity_key": BASE64_STANDARD.encode([7u8; 32]),
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(refusee.status(), 429, "le quota n'a pas été appliqué");
}

/// La limite ne déborde pas sur les routes authentifiées.
///
/// Elle y serait nuisible : la signature identifie déjà l'appelant, et pénaliser une adresse
/// punirait tous ceux qui la partagent — un NAT, un campus — pour l'abus d'un seul.
#[tokio::test]
async fn la_limite_ne_touche_pas_les_routes_signees() {
    // Deux, et pas moins : préparer un appareil consomme exactement deux routes ouvertes — la
    // création du compte puis l'enregistrement de l'appareil. C'est aussi ce qui rend le défaut
    // de soixante par minute confortable, un utilisateur réel n'en consommant que quelques-unes.
    let server = common::start_with_throttle(2).await;
    let alice = Device::register(&server, &unique("alice")).await;

    for tour in 1..=5 {
        let reponse = alice.get("/v1/groups").await;
        assert!(reponse.status().is_success(), "la requête signée {tour} a été limitée");
    }
}

/// **Le test qui fige l'anti-rejeu.**
///
/// La même requête, aux octets près, ne doit passer qu'une fois. Sans cette garantie, un
/// observateur du réseau peut faire rejouer n'importe quelle requête signée pendant toute la
/// fenêtre de tolérance d'horloge — soixante secondes.
#[tokio::test]
async fn une_requete_signee_ne_passe_qu_une_fois() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    // Tout est figé — horodatage, corps **et nonce** : les deux envois sont donc identiques à
    // l'octet près, ce qui est exactement ce qu'un observateur du réseau peut reproduire.
    let instant = common::now();
    let nonce = [3u8; 16];
    let corps = serde_json::to_vec(&serde_json::json!({ "handles": [] })).unwrap();

    let envoyer = async |corps: Vec<u8>| {
        alice
            .forge_with_nonce(
                "POST",
                "/v1/presence",
                corps.clone(),
                corps,
                instant,
                "/v1/presence",
                nonce,
            )
            .await
    };

    assert!(envoyer(corps.clone()).await.status().is_success(), "la première doit passer");
    assert_eq!(envoyer(corps).await.status(), 401, "la requête a été acceptée deux fois");
}

/// Le nonce est propre à chaque appareil.
///
/// Il est tiré au hasard, sans coordination entre clients : si l'unicité était globale, deux
/// appareils qui tirent le même nonce se couperaient mutuellement, et le refus paraîtrait
/// aléatoire.
#[tokio::test]
async fn deux_appareils_peuvent_tirer_le_meme_nonce() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let instant = common::now();
    let nonce = [7u8; 16];
    let corps = serde_json::to_vec(&serde_json::json!({ "handles": [] })).unwrap();

    for appareil in [&alice, &bob] {
        let reponse = appareil
            .forge_with_nonce(
                "POST",
                "/v1/presence",
                corps.clone(),
                corps.clone(),
                instant,
                "/v1/presence",
                nonce,
            )
            .await;

        assert!(reponse.status().is_success(), "le nonce d'un appareil a bloqué l'autre");
    }
}

/// L'horodatage est dans le message signé : le présenter décalé invalide la signature. Sans
/// cette borne, un certificat fabriqué à l'avance resterait exploitable après un vol de base.
#[tokio::test]
async fn un_horodatage_hors_fenetre_est_refuse() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, &unique("portable")).await;
    let tablette = alice.device(&server, &unique("tablette")).await;

    let futur = common::now() + 3600;
    let certificat = alice.account.revoke(&alice.handle, &tablette.id, futur).unwrap();

    let response = portable
        .post(
            &format!("/v1/devices/{}/revoke", tablette.id),
            serde_json::json!({
                "revocation": BASE64_STANDARD.encode(certificat),
                "revoked_at": futur,
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn un_appareil_revoque_ne_peut_plus_etre_ajoute_a_un_groupe() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, &unique("portable")).await;
    let tablette = alice.device(&server, &unique("tablette")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    tablette
        .post("/v1/key-packages", serde_json::json!({ "packages": [BASE64_STANDARD.encode(b"kp")] }))
        .await;

    let response = alice.revoke(&portable, &tablette.id).await;
    assert!(response.status().is_success(), "révocation légitime refusée");

    // Plus aucun KeyPackage disponible : personne ne peut plus ouvrir de conversation avec
    // cet appareil, ce qui est tout l'objet de la révocation.
    let response =
        bob.post(&format!("/v1/key-packages/{}/claim", tablette.id), serde_json::json!({})).await;
    assert_eq!(response.status(), 404);

    // Il reste dans la liste servie aux correspondants, mais marqué révoqué et accompagné de
    // son certificat. Le faire disparaître rendrait la révocation indiscernable d'une
    // omission par le serveur — et c'est ce certificat qui permet à Bob de commiter le retrait
    // MLS sans nous croire sur parole.
    let body: serde_json::Value =
        bob.get(&format!("/v1/accounts/{}/devices", alice.handle)).await.json().await.unwrap();
    let devices = body["devices"].as_array().unwrap();

    let servi = devices
        .iter()
        .find(|d| d["id"] == tablette.id)
        .expect("l'appareil révoqué doit rester listé, avec sa révocation");

    let revoked_at = servi["revoked_at"].as_u64().expect("horodatage de révocation absent");
    let certificat =
        BASE64_STANDARD.decode(servi["revocation"].as_str().expect("certificat absent")).unwrap();
    let identity_key = BASE64_STANDARD.decode(body["identity_key"].as_str().unwrap()).unwrap();

    let claim = attest::RevocationClaim {
        handle: &alice.handle,
        device_id: &tablette.id,
        revoked_at,
    };
    assert!(
        attest::verify_revocation(&identity_key, &claim, &certificat).is_ok(),
        "le certificat servi ne vérifie pas : un tiers ne peut pas constater la révocation",
    );

    // L'appareil actif, lui, ne porte aucune de ces deux clés.
    let actif = devices.iter().find(|d| d["id"] == portable.id).unwrap();
    assert!(actif.get("revoked_at").is_none());
    assert!(actif.get("revocation").is_none());
}

/// La fuite immédiate : entre la révocation et le commit MLS qui l'évince réellement, le
/// serveur cesse de servir les enveloppes à l'appareil révoqué.
///
/// Défense en profondeur seulement. L'appareil détient encore les secrets du groupe et
/// déchiffrerait tout ce qu'il obtiendrait par un autre chemin — c'est le `Remove` MLS qui le
/// prive de la suite, pas ce filtre.
#[tokio::test]
async fn un_appareil_revoque_ne_recoit_plus_les_enveloppes() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, &unique("portable")).await;
    let tablette = alice.device(&server, &unique("tablette")).await;

    let group_id = hex::encode(unique("groupe").as_bytes());
    portable
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({ "device_ids": [portable.id, tablette.id] }),
        )
        .await;

    // Avant révocation, la tablette lit la boîte du groupe.
    assert!(
        tablette.get(&format!("/v1/groups/{group_id}/envelopes?after=0")).await.status().is_success()
    );

    assert!(alice.revoke(&portable, &tablette.id).await.status().is_success());

    assert_eq!(
        tablette.get(&format!("/v1/groups/{group_id}/envelopes?after=0")).await.status(),
        403,
    );
    // Le portable, lui, n'est pas affecté.
    assert!(
        portable.get(&format!("/v1/groups/{group_id}/envelopes?after=0")).await.status().is_success()
    );
}

/// Le pendant d'`add_members` : un membre retire un appareil de la liste de diffusion.
#[tokio::test]
async fn un_membre_peut_retirer_un_appareil_de_la_diffusion() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let group_id = hex::encode(unique("groupe").as_bytes());
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

/// Un non-membre ne retire personne : sinon n'importe qui viderait la liste de diffusion de
/// n'importe quel groupe dont il devine l'identifiant.
#[tokio::test]
async fn un_non_membre_ne_peut_retirer_personne() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let intrus = Device::register(&server, &unique("intrus")).await;

    let group_id = hex::encode(unique("groupe").as_bytes());
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    let response = intrus
        .post(
            &format!("/v1/groups/{group_id}/members/remove"),
            serde_json::json!({ "device_ids": [bob.id] }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

// ---------------------------------------------------------------- authentification

#[tokio::test]
async fn requete_non_signee_refusee() {
    let server = start().await;
    let response = reqwest::Client::new()
        .get(format!("{}/v1/key-packages/stock", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn appareil_inconnu_refuse() {
    let server = start().await;
    // Signature parfaitement valide, mais le serveur ne connaît pas cette clé.
    let inconnu = Device::new(&server, &unique("fantome"));
    assert_eq!(inconnu.get("/v1/key-packages/stock").await.status(), 401);
}

#[tokio::test]
async fn horodatage_perime_refuse() {
    let server = start().await;
    let device = Device::register(&server, &unique("device")).await;

    // La fenêtre de tolérance est de 60 s ; deux heures dans le passé doit être rejeté,
    // sans quoi une requête capturée reste rejouable indéfiniment.
    let response = device
        .signed_at("GET", "/v1/key-packages/stock", Vec::new(), now() - 7200, "/v1/key-packages/stock")
        .await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn signature_valide_pour_un_autre_chemin_refusee() {
    let server = start().await;
    let device = Device::register(&server, &unique("device")).await;

    // Le chemin fait partie du message signé : une signature capturée sur un endpoint
    // anodin ne doit pas être rejouable sur un endpoint sensible.
    let response = device
        .signed_at(
            "GET",
            "/v1/key-packages/stock",
            Vec::new(),
            now(),
            "/v1/un/autre/chemin",
        )
        .await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn corps_altere_apres_signature_refuse() {
    let server = start().await;
    let device = Device::register(&server, &unique("device")).await;

    let signe = serde_json::to_vec(&serde_json::json!({ "packages": ["AAAA"] })).unwrap();
    let mut altere = signe.clone();
    let dernier = altere.len() - 3;
    altere[dernier] ^= 0x01;

    // L'empreinte du corps fait partie du message signé : intercepter une requête et en
    // modifier le contenu en transit doit invalider la signature.
    let response = device
        .forge(
            "POST",
            "/v1/key-packages",
            altere,
            signe,
            now(),
            "/v1/key-packages",
        )
        .await;
    assert_eq!(response.status(), 401);
}

// ---------------------------------------------------------------- key packages

#[tokio::test]
async fn key_package_consomme_une_seule_fois() {
    let server = start().await;
    let bob = Device::register(&server, &unique("bob")).await;
    let alice = Device::register(&server, &unique("alice")).await;

    let paquets = vec![BASE64_STANDARD.encode(b"kp-1"), BASE64_STANDARD.encode(b"kp-2")];
    let response = bob
        .post("/v1/key-packages", serde_json::json!({ "packages": paquets }))
        .await;
    assert!(response.status().is_success());

    let stock: serde_json::Value =
        bob.get("/v1/key-packages/stock").await.json().await.unwrap();
    assert_eq!(stock["remaining"], 2);

    // Deux consommations doivent rendre deux KeyPackages *différents*. Resservir le même
    // ferait partager la même clé d'initialisation à deux groupes : la forward secrecy de
    // l'ajout tombe. OpenMLS ne l'empêche pas — c'est la responsabilité du serveur.
    let claim = format!("/v1/key-packages/{}/claim", bob.id);
    let premier: serde_json::Value = alice.post(&claim, serde_json::json!({})).await.json().await.unwrap();
    let second: serde_json::Value = alice.post(&claim, serde_json::json!({})).await.json().await.unwrap();

    assert_ne!(premier["package"], second["package"]);
    assert_eq!(premier["remaining"], 1);
    assert_eq!(second["remaining"], 0);

    // Stock épuisé : le serveur doit le dire clairement pour que le client réapprovisionne.
    assert_eq!(alice.post(&claim, serde_json::json!({})).await.status(), 404);
}

#[tokio::test]
async fn consommations_concurrentes_ne_partagent_jamais_un_key_package() {
    let server = start().await;
    let bob = Device::register(&server, &unique("bob")).await;

    const STOCK: usize = 20;
    let paquets: Vec<String> = (0..STOCK)
        .map(|i| BASE64_STANDARD.encode(format!("kp-{i}")))
        .collect();
    bob.post("/v1/key-packages", serde_json::json!({ "packages": paquets })).await;

    // Le retrait passe par DELETE ... RETURNING sur FOR UPDATE SKIP LOCKED. Sous
    // concurrence réelle, deux appelants ne doivent jamais obtenir le même paquet.
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

    let mut obtenus = Vec::new();
    for handle in handles {
        if let Some(package) = handle.await.unwrap() {
            obtenus.push(package);
        }
    }

    let uniques: std::collections::HashSet<_> = obtenus.iter().collect();
    assert_eq!(obtenus.len(), STOCK, "des consommations ont échoué");
    assert_eq!(uniques.len(), STOCK, "un key package a été servi deux fois");
}

// ---------------------------------------------------------------- contrôle d'accès

#[tokio::test]
async fn non_membre_ne_peut_ni_lire_ni_ecrire() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let intrus = Device::register(&server, &unique("intrus")).await;

    let group_id = unique("groupe").into_bytes();
    alice
        .post(&group_path(&group_id, "/members"), serde_json::json!({ "device_ids": [alice.id] }))
        .await;

    // Un identifiant de groupe n'est pas un secret : le connaître ne doit rien ouvrir.
    let ecriture = intrus
        .post(
            &group_path(&group_id, "/envelopes"),
            serde_json::json!({ "payload": BASE64_STANDARD.encode(b"coucou") }),
        )
        .await;
    assert_eq!(ecriture.status(), 403);

    let lecture = intrus.get(&group_path(&group_id, "/envelopes")).await;
    assert_eq!(lecture.status(), 403);

    // Et il ne doit pas pouvoir s'ajouter lui-même.
    let auto_ajout = intrus
        .post(&group_path(&group_id, "/members"), serde_json::json!({ "device_ids": [intrus.id] }))
        .await;
    assert_eq!(auto_ajout.status(), 403);
}

// ---------------------------------------------------------------- enveloppes

#[tokio::test]
async fn les_enveloppes_sont_ordonnees_et_paginees() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let group_id = unique("groupe").into_bytes();
    alice
        .post(
            &group_path(&group_id, "/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    // MLS exige un ordre total : deux membres qui appliquent les commits dans des ordres
    // différents divergent d'epoch et ne peuvent plus se lire du tout.
    for i in 0..5u8 {
        let response = alice
            .post(
                &group_path(&group_id, "/envelopes"),
                serde_json::json!({ "payload": BASE64_STANDARD.encode([i]) }),
            )
            .await;
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["seq"], i as i64 + 1, "séquence non monotone");
    }

    let toutes: Vec<serde_json::Value> =
        bob.get(&group_path(&group_id, "/envelopes")).await.json().await.unwrap();
    assert_eq!(toutes.len(), 5);

    // Curseur : ne re-livrer que ce qui suit.
    let suite: Vec<serde_json::Value> = bob
        .get(&group_path(&group_id, "/envelopes?after=3"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(suite.len(), 2);
    assert_eq!(suite[0]["seq"], 4);
}

#[tokio::test]
async fn enveloppe_vide_refusee() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let group_id = unique("groupe").into_bytes();
    alice
        .post(&group_path(&group_id, "/members"), serde_json::json!({ "device_ids": [alice.id] }))
        .await;

    let response = alice
        .post(&group_path(&group_id, "/envelopes"), serde_json::json!({ "payload": "" }))
        .await;
    assert_eq!(response.status(), 400);
}

// ---------------------------------------------------------------- le test qui compte

/// Chiffre un vrai message avec `crypto-core`, le fait transiter par le serveur, puis lit la
/// table `envelopes` **directement en SQL** pour vérifier que rien n'en transparaît.
///
/// C'est la seule preuve qui compte. Tout le reste du projet — protocole, tests unitaires,
/// revue — ne vaut que si celui-ci passe. Il est automatisé précisément pour que personne
/// n'ait à s'en remettre à une inspection manuelle ponctuelle.
#[tokio::test]
async fn le_serveur_ne_voit_que_du_chiffre() {
    let server = start().await;

    // Vraies identités MLS, vrai groupe, vrai chiffrement.
    let alice_mls = Identity::create("alice@device-1").unwrap();
    let bob_mls = Identity::create("bob@device-1").unwrap();

    let mut alice_group = Conversation::create(&alice_mls).unwrap();
    let invitation = alice_group
        .invite(&alice_mls, &bob_mls.publish_key_package().unwrap())
        .unwrap();
    let arbre = alice_group.apply_pending(&alice_mls).unwrap();
    let mut bob_group =
        Conversation::join(&bob_mls, &invitation.welcome, &arbre).unwrap();

    const SECRET: &[u8] = b"le code du coffre est 4815162342";
    let ciphertext = alice_group.encrypt(&alice_mls, SECRET).unwrap();

    // Transit par le serveur.
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

    // Lecture directe de la base, comme le ferait un administrateur, une sauvegarde volée
    // ou une réquisition judiciaire.
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT payload FROM envelopes WHERE group_id = $1")
        .bind(&group_id)
        .fetch_all(&server.pool)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    let stored = &rows[0].0;

    assert!(
        !stored.windows(SECRET.len()).any(|w| w == SECRET),
        "le clair est lisible dans la base"
    );
    assert!(
        !stored.windows(5).any(|w| w == b"alice"),
        "l'identité de l'expéditeur est lisible dans la base"
    );

    // Et le destinataire légitime, lui, doit bien pouvoir le lire.
    let recus: Vec<serde_json::Value> =
        bob.get(&group_path(&group_id, "/envelopes")).await.json().await.unwrap();
    let payload = BASE64_STANDARD
        .decode(recus[0]["payload"].as_str().unwrap())
        .unwrap();

    match bob_group.process(&bob_mls, &payload, &Default::default()).unwrap() {
        crypto_core::Incoming::Application { plaintext, sender } => {
            assert_eq!(plaintext, SECRET);
            assert_eq!(sender.as_deref(), Some("alice@device-1"));
        }
        other => panic!("attendu un message applicatif, reçu {other:?}"),
    }
}

#[tokio::test]
async fn un_appareil_decouvre_les_groupes_ou_il_a_ete_ajoute() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let bob = Device::register(&server, &unique("bob")).await;
    let etranger = Device::register(&server, &unique("etranger")).await;

    let group_id = unique("groupe").into_bytes();
    alice
        .post(
            &group_path(&group_id, "/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    // Bob était hors ligne pendant l'ajout : c'est son seul moyen d'apprendre que ce
    // groupe existe et de venir y chercher son Welcome.
    let groupes: Vec<String> = bob.get("/v1/groups").await.json().await.unwrap();
    assert!(groupes.contains(&hex::encode(&group_id)));

    // Et un appareil non membre ne doit rien voir de ce groupe.
    let aucun: Vec<String> = etranger.get("/v1/groups").await.json().await.unwrap();
    assert!(!aucun.contains(&hex::encode(&group_id)));
}

/// Le Welcome d'ajout expose les identités des membres — mais jamais le contenu.
///
/// L'arbre de ratchet MLS est **public par construction** : il contient les LeafNodes, donc
/// les credentials, donc les noms des membres. Il transite ici en clair du point de vue du
/// serveur, qui connaît déjà ces identités par `devices` et `group_members` — la fuite
/// n'ajoute donc rien à ce qu'il sait. Mais elle est réelle, et un déploiement qui viserait
/// à masquer les métadonnées (identifiants de groupe anonymes, credentials à divulgation
/// nulle) devrait la traiter.
///
/// Ce test fige les deux moitiés du constat : le **contenu** est protégé, l'**identité** ne
/// l'est pas. Si un jour le contenu apparaît, la CI casse.
#[tokio::test]
async fn le_welcome_expose_les_identites_mais_jamais_le_contenu() {
    let server = start().await;

    let alice_mls = Identity::create("alice-canari@device").unwrap();
    let bob_mls = Identity::create("bob-canari@device").unwrap();

    let mut alice_group = Conversation::create(&alice_mls).unwrap();
    let invitation = alice_group
        .invite(&alice_mls, &bob_mls.publish_key_package().unwrap())
        .unwrap();
    let arbre = alice_group.apply_pending(&alice_mls).unwrap();

    const SECRET: &[u8] = b"canari-du-contenu-4815162342";
    let ciphertext = alice_group.encrypt(&alice_mls, SECRET).unwrap();

    let alice = Device::register(&server, &unique("alice")).await;
    let group_id = alice_group.id();
    alice
        .post(&group_path(&group_id, "/members"), serde_json::json!({ "device_ids": [alice.id] }))
        .await;

    // Le Welcome et l'arbre de ratchet passent par le même transport que les messages.
    for blob in [&invitation.welcome, &arbre, &ciphertext] {
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

    let contient = |motif: &[u8]| {
        rows.iter()
            .any(|(payload,)| payload.windows(motif.len()).any(|w| w == motif))
    };

    // Ce qui doit tenir, quoi qu'il arrive.
    assert!(!contient(SECRET), "le contenu du message est lisible en base");

    // Ce qui fuit, et qu'on documente plutôt que de prétendre l'inverse.
    assert!(
        contient(b"alice-canari"),
        "l'identité n'apparaît plus dans l'arbre de ratchet : mettre à jour cette note"
    );
}

// ---------------------------------------------------------------- pièces jointes

/// Prépare un groupe à deux membres et retourne (propriétaire, autre membre, group_id).
async fn groupe_avec_deux_membres(server: &TestServer) -> (Device, Device, Vec<u8>) {
    let alice = Device::register(server, &unique("alice")).await;
    let bob = Device::register(server, &unique("bob")).await;
    let group_id = unique("groupe").into_bytes();

    alice
        .post(
            &group_path(&group_id, "/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    (alice, bob, group_id)
}

#[tokio::test]
async fn une_piece_jointe_transite_sans_etre_lisible() {
    let server = start().await;
    let (alice, bob, group_id) = groupe_avec_deux_membres(&server).await;

    // Le client chiffre avant d'envoyer ; le serveur ne voit que ces octets-là.
    const CHIFFRE: &[u8] = b"\x00\x01ceci-est-deja-chiffre\xff\xfe";

    let response = alice
        .forge(
            "POST",
            &group_path(&group_id, "/attachments"),
            CHIFFRE.to_vec(),
            CHIFFRE.to_vec(),
            now(),
            &group_path(&group_id, "/attachments"),
        )
        .await;
    assert!(response.status().is_success());

    let id = response.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Un autre membre du groupe récupère exactement les mêmes octets.
    let recu = bob
        .get(&group_path(&group_id, &format!("/attachments/{id}")))
        .await;
    assert!(recu.status().is_success());

    // Le type annoncé doit rester opaque : laisser le navigateur deviner permettrait à un
    // SVG ou un HTML d'être rendu inline, donc d'exécuter du script sur cette origine.
    assert_eq!(
        recu.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
    assert_eq!(recu.headers().get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(recu.headers().get("content-disposition").unwrap(), "attachment");

    assert_eq!(recu.bytes().await.unwrap().as_ref(), CHIFFRE);

    // Et rien du fichier n'est conservé en clair côté serveur : ni nom, ni type, ni clé.
    let colonnes: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name::text FROM information_schema.columns WHERE table_name = 'attachments'",
    )
    .fetch_all(&server.pool)
    .await
    .unwrap();
    let noms: Vec<String> = colonnes.into_iter().map(|(c,)| c).collect();
    assert_eq!(noms.len(), 4, "colonnes inattendues sur attachments : {noms:?}");
    for interdit in ["name", "filename", "mime", "content_type", "key"] {
        assert!(!noms.iter().any(|c| c == interdit), "{interdit} ne doit pas être stocké");
    }
}

#[tokio::test]
async fn un_non_membre_ne_peut_ni_deposer_ni_recuperer() {
    let server = start().await;
    let (alice, _bob, group_id) = groupe_avec_deux_membres(&server).await;
    let intrus = Device::register(&server, &unique("intrus")).await;

    let chiffre = b"blob".to_vec();
    let path = group_path(&group_id, "/attachments");
    let id = alice
        .forge("POST", &path, chiffre.clone(), chiffre.clone(), now(), &path)
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let depot = intrus
        .forge("POST", &path, chiffre.clone(), chiffre, now(), &path)
        .await;
    assert_eq!(depot.status(), 403);

    let lecture = intrus
        .get(&group_path(&group_id, &format!("/attachments/{id}")))
        .await;
    assert_eq!(lecture.status(), 403);
}

#[tokio::test]
async fn une_piece_jointe_n_est_pas_accessible_depuis_un_autre_groupe() {
    let server = start().await;
    let (alice, _bob, group_id) = groupe_avec_deux_membres(&server).await;

    let chiffre = b"secret-du-groupe-1".to_vec();
    let path = group_path(&group_id, "/attachments");
    let id = alice
        .forge("POST", &path, chiffre.clone(), chiffre, now(), &path)
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Alice crée un second groupe dont elle est aussi membre, puis tente d'y lire la pièce
    // jointe du premier. Le `group_id` fait partie de la clause SQL : sans lui, un membre
    // pourrait aspirer les fichiers d'autres groupes en devinant des identifiants.
    let autre_groupe = unique("autre").into_bytes();
    alice
        .post(
            &group_path(&autre_groupe, "/members"),
            serde_json::json!({ "device_ids": [alice.id] }),
        )
        .await;

    let vol = alice
        .get(&group_path(&autre_groupe, &format!("/attachments/{id}")))
        .await;
    assert_eq!(vol.status(), 404);
}

#[tokio::test]
async fn piece_jointe_vide_refusee() {
    let server = start().await;
    let (alice, _bob, group_id) = groupe_avec_deux_membres(&server).await;
    let path = group_path(&group_id, "/attachments");

    let response = alice
        .forge("POST", &path, Vec::new(), Vec::new(), now(), &path)
        .await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn identifiant_de_piece_jointe_malforme_refuse() {
    let server = start().await;
    let (alice, _bob, group_id) = groupe_avec_deux_membres(&server).await;

    // L'identifiant vient de l'URL : il doit être validé comme un UUID avant d'atteindre la
    // base, et une valeur absurde doit produire une erreur claire, pas une erreur SQL.
    let response = alice
        .get(&group_path(&group_id, "/attachments/pas-un-uuid"))
        .await;
    assert_eq!(response.status(), 400);
}

// ---------------------------------------------------------------- appairage

#[tokio::test]
async fn le_paquet_d_appairage_se_releve_une_seule_fois() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, "desktop").await;

    // Identifiant unique : la base persiste entre les exécutions, et un identifiant fixe
    // serait déjà pris au second `cargo test`.
    let id = hex::encode(&sha2::Sha256::digest(unique("pairing").as_bytes())[..16]);
    let paquet = BASE64_STANDARD.encode(b"paquet scelle, opaque pour le serveur");

    let response = portable
        .post(&format!("/v1/pairings/{id}"), serde_json::json!({ "payload": paquet }))
        .await;
    assert!(response.status().is_success());

    // La relève est non signée : le nouvel appareil n'a pas encore d'identité. La sécurité
    // tient au chiffrement du paquet, pas à l'authentification de la requête.
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/v1/pairings/{id}", server.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["payload"], paquet);

    // Une seconde relève qui réussirait signalerait qu'un tiers a pu récupérer le paquet.
    let response = reqwest::Client::new()
        .get(format!("{}/v1/pairings/{id}", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
}

/// Un identifiant déjà pris ne doit pas être écrasé : sinon un appareil malveillant remplace
/// le paquet légitime pendant que l'utilisateur regarde son QR code.
#[tokio::test]
async fn un_identifiant_d_appairage_ne_peut_pas_etre_ecrase() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, "desktop").await;
    let id = hex::encode(&sha2::Sha256::digest(unique("pairing").as_bytes())[..16]);

    let first = serde_json::json!({ "payload": BASE64_STANDARD.encode(b"legitime") });
    assert!(portable.post(&format!("/v1/pairings/{id}"), first).await.status().is_success());

    let second = serde_json::json!({ "payload": BASE64_STANDARD.encode(b"hostile") });
    assert_eq!(portable.post(&format!("/v1/pairings/{id}"), second).await.status(), 409);
}

#[tokio::test]
async fn deposer_un_appairage_exige_une_signature() {
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

/// Le paquet stocké doit être opaque : il contient la graine du compte, et un serveur qui
/// pourrait la lire tiendrait tous les comptes.
#[tokio::test]
async fn le_serveur_ne_voit_qu_un_blob_d_appairage() {
    use crypto_core::pairing::{PairingOffer, seal};

    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, "desktop").await;

    let offre = PairingOffer::generate();
    let secret = b"GRAINE-DE-COMPTE-4815162342";
    let (paquet, code) = seal(&offre.public_key(), &offre.id(), secret).unwrap();

    let id = hex::encode(offre.id());
    portable
        .post(
            &format!("/v1/pairings/{id}"),
            serde_json::json!({ "payload": BASE64_STANDARD.encode(&paquet) }),
        )
        .await;

    let (stored,): (Vec<u8>,) = sqlx::query_as("SELECT payload FROM pairings WHERE id = $1")
        .bind(offre.id().as_slice())
        .fetch_one(&server.pool)
        .await
        .unwrap();

    assert!(
        !stored.windows(secret.len()).any(|w| w == secret),
        "la graine du compte apparaît en clair dans la base",
    );

    // Et le destinataire légitime, lui, l'ouvre.
    let ouvert = offre.open(&stored).unwrap();
    assert_eq!(ouvert.plaintext, secret);
    assert_eq!(ouvert.confirmation, code);
}

// ---------------------------------------------------------------- coffre d'historique

#[tokio::test]
async fn le_coffre_est_prive_a_son_compte() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let bob = TestAccount::create(&server, &unique("bob")).await;
    let poste_alice = alice.device(&server, "desktop").await;
    let poste_bob = bob.device(&server, "desktop").await;

    // Un groupe partagé : les deux y sont membres.
    let group = hex::encode(unique("g").as_bytes());
    poste_alice
        .post(
            &format!("/v1/groups/{group}/members"),
            serde_json::json!({ "device_ids": [poste_bob.id] }),
        )
        .await;

    let secret = BASE64_STANDARD.encode(b"archive chiffree d'alice");
    let response = poste_alice
        .post(
            &format!("/v1/vault/{group}"),
            serde_json::json!({ "entries": [{ "seq": 1, "payload": secret }] }),
        )
        .await;
    assert!(response.status().is_success(), "dépôt refusé");

    // Alice retrouve son entrée.
    let mien: serde_json::Value =
        poste_alice.get(&format!("/v1/vault/{group}")).await.json().await.unwrap();
    assert_eq!(mien.as_array().unwrap().len(), 1);
    assert_eq!(mien[0]["payload"], secret);

    // Bob, membre du **même groupe**, ne voit rien : le coffre est indexé par compte. Sans
    // cela, un correspondant lirait les sauvegardes de l'autre longtemps après la conversation.
    let sien: serde_json::Value =
        poste_bob.get(&format!("/v1/vault/{group}")).await.json().await.unwrap();
    assert!(sien.as_array().unwrap().is_empty(), "bob a lu le coffre d'alice");
}

/// Deux appareils d'un même compte archivent la même conversation : les dépôts doivent se
/// superposer sans conflit, et l'historique rester lisible depuis les deux.
#[tokio::test]
async fn le_depot_dans_le_coffre_est_idempotent() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let poste = alice.device(&server, "desktop").await;
    let tablette = alice.device(&server, "mobile").await;

    let group = hex::encode(unique("g").as_bytes());
    poste
        .post(
            &format!("/v1/groups/{group}/members"),
            serde_json::json!({ "device_ids": [tablette.id] }),
        )
        .await;

    let entree = serde_json::json!({ "entries": [{ "seq": 7, "payload": BASE64_STANDARD.encode(b"m") }] });
    assert!(poste.post(&format!("/v1/vault/{group}"), entree.clone()).await.status().is_success());
    assert!(tablette.post(&format!("/v1/vault/{group}"), entree).await.status().is_success());

    let rows: serde_json::Value =
        tablette.get(&format!("/v1/vault/{group}")).await.json().await.unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "l'entrée a été dupliquée");
}

/// Le coffre n'est pas un stockage gratuit : il faut être membre du groupe qu'on archive.
#[tokio::test]
async fn archiver_un_groupe_dont_on_n_est_pas_membre_est_refuse() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let poste = alice.device(&server, "desktop").await;

    let response = poste
        .post(
            &format!("/v1/vault/{}", hex::encode(unique("etranger").as_bytes())),
            serde_json::json!({ "entries": [{ "seq": 1, "payload": BASE64_STANDARD.encode(b"x") }] }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

/// Le serveur ne doit rien pouvoir lire du coffre : il ne détient pas la phrase de
/// récupération dont la clé est dérivée.
#[tokio::test]
async fn le_serveur_ne_voit_que_du_chiffre_dans_le_coffre() {
    use crypto_core::Account;

    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let poste = alice.device(&server, "desktop").await;

    let group = hex::encode(unique("g").as_bytes());
    poste
        .post(
            &format!("/v1/groups/{group}/members"),
            serde_json::json!({ "device_ids": [poste.id] }),
        )
        .await;

    // Chiffrement sous la clé de coffre, exactement comme le fait le client.
    let (compte, _phrase) = Account::generate().unwrap();
    let cle = compte.vault_key();
    const SECRET: &[u8] = b"archive-canari-4815162342";

    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let cipher = Aes256Gcm::new_from_slice(&cle).unwrap();
    let chiffre = cipher.encrypt(Nonce::from_slice(&[0u8; 12]), SECRET).unwrap();

    poste
        .post(
            &format!("/v1/vault/{group}"),
            serde_json::json!({ "entries": [{ "seq": 1, "payload": BASE64_STANDARD.encode(&chiffre) }] }),
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
        "le contenu archivé apparaît en clair dans la base",
    );
}

// ---------------------------------------------------------------- rotation de compte

/// **Le test qui compte pour la rotation.**
///
/// Tous les appareils d'un compte détiennent la graine — c'est la parité. Un appareil volé
/// détient donc le compte, et le révoquer ne sert à rien : son porteur en atteste un nouveau.
///
/// La rotation, elle, a un effet mécanique : en changeant la clé du compte, elle rend
/// **invérifiables toutes les attestations existantes**. La révocation totale n'est pas un
/// mécanisme séparé, c'est une conséquence — et c'est ce que ce test établit.
#[tokio::test]
async fn une_rotation_invalide_toutes_les_attestations_existantes() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, &unique("portable")).await;
    let _vole = alice.device(&server, &unique("vole")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    // Avant rotation : les deux appareils passent la vérification que fait tout client.
    let avant: serde_json::Value =
        bob.get(&format!("/v1/accounts/{}/devices", alice.handle)).await.json().await.unwrap();
    assert_eq!(verifiables(&avant), 2);

    // Alice tourne depuis son portable.
    let (nouveau, _phrase) = crypto_core::Account::generate().unwrap();
    let rotated_at = common::now();
    let signature = alice
        .account
        .rotate(&alice.handle, &nouveau.identity_key(), rotated_at)
        .unwrap();

    let response = portable
        .post(
            &format!("/v1/accounts/{}/rotate", alice.handle),
            serde_json::json!({
                "new_identity_key": BASE64_STANDARD.encode(nouveau.identity_key()),
                "rotation": BASE64_STANDARD.encode(signature),
                "rotated_at": rotated_at,
            }),
        )
        .await;
    assert!(response.status().is_success(), "rotation légitime refusée");

    // Plus AUCUNE attestation ne vérifie : ni celle de l'appareil volé, ni même celle du
    // portable, qui doit se ré-attester.
    let apres: serde_json::Value =
        bob.get(&format!("/v1/accounts/{}/devices", alice.handle)).await.json().await.unwrap();
    assert_eq!(
        verifiables(&apres),
        0,
        "une attestation survit à la rotation : l'appareil volé est encore reconnu",
    );

    // Le portable se ré-atteste sous la nouvelle clé, et lui seul y parvient — l'appareil volé
    // aussi le pourrait s'il détenait la nouvelle graine, ce qui n'est pas le cas.
    let auth_key = BASE64_STANDARD.decode(portable.public_key_b64()).unwrap();
    let reattestation = nouveau
        .attest(&alice.handle, &portable.id, &auth_key, portable.mls_key())
        .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/devices", server.base_url))
        .json(&serde_json::json!({
            "id": portable.id,
            "handle": alice.handle,
            "auth_key": BASE64_STANDARD.encode(&auth_key),
            "mls_key": BASE64_STANDARD.encode(portable.mls_key()),
            "attestation": BASE64_STANDARD.encode(reattestation),
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "ré-attestation refusée après rotation");

    let final_: serde_json::Value =
        bob.get(&format!("/v1/accounts/{}/devices", alice.handle)).await.json().await.unwrap();
    assert_eq!(verifiables(&final_), 1, "seul l'appareil ré-attesté doit être reconnu");
}

/// Compte les appareils dont l'attestation vérifie contre la clé courante du compte —
/// c'est-à-dire exactement ce que fait un client à chaque lecture.
fn verifiables(body: &serde_json::Value) -> usize {
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

/// Sans continuité prouvée, n'importe quel compte reprendrait le handle d'autrui.
#[tokio::test]
async fn un_tiers_ne_peut_pas_faire_tourner_un_compte() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, &unique("portable")).await;

    let mallory = TestAccount::create(&server, &unique("mallory")).await;
    let (cible, _) = crypto_core::Account::generate().unwrap();
    let rotated_at = common::now();
    let signature =
        mallory.account.rotate(&alice.handle, &cible.identity_key(), rotated_at).unwrap();

    let response = portable
        .post(
            &format!("/v1/accounts/{}/rotate", alice.handle),
            serde_json::json!({
                "new_identity_key": BASE64_STANDARD.encode(cible.identity_key()),
                "rotation": BASE64_STANDARD.encode(signature),
                "rotated_at": rotated_at,
            }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

/// Un appareil d'un autre compte n'a rien à faire ici, même muni d'une signature valide.
#[tokio::test]
async fn un_appareil_etranger_ne_peut_pas_declencher_la_rotation() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let _portable = alice.device(&server, &unique("portable")).await;
    let bob = Device::register(&server, &unique("bob")).await;

    let (nouveau, _) = crypto_core::Account::generate().unwrap();
    let rotated_at = common::now();
    let signature =
        alice.account.rotate(&alice.handle, &nouveau.identity_key(), rotated_at).unwrap();

    let response = bob
        .post(
            &format!("/v1/accounts/{}/rotate", alice.handle),
            serde_json::json!({
                "new_identity_key": BASE64_STANDARD.encode(nouveau.identity_key()),
                "rotation": BASE64_STANDARD.encode(signature),
                "rotated_at": rotated_at,
            }),
        )
        .await;

    assert_eq!(response.status(), 403);
}

// ---------------------------------------------------------------- journal de transparence

/// Une clé de compte servie doit être prouvable dans le journal, et le client doit pouvoir
/// le vérifier **seul** — c'est tout l'objet du dispositif.
#[tokio::test]
async fn une_cle_de_compte_est_prouvable_dans_le_journal() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let lecteur = Device::register(&server, &unique("lecteur")).await;

    let body: serde_json::Value = lecteur
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

    // La tête vient bien du journal.
    let sth = transparency::TreeHead { size, root, timestamp: head["timestamp"].as_u64().unwrap() };
    assert!(sth.verify(&log_key, &signature).is_ok(), "tête non signée par le journal");

    // Et la clé servie y figure, à l'indice annoncé.
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
        "la preuve d'inclusion servie ne vérifie pas",
    );
}

/// **Le test qui compte pour la transparence.**
///
/// Un serveur qui substitue la clé d'un compte au premier contact — l'attaque que les
/// attestations ne couvrent pas — ne peut pas en produire de preuve d'inclusion : elle n'est
/// pas dans l'arbre. Sans cette propriété, le journal serait décoratif.
#[tokio::test]
async fn une_cle_substituee_ne_figure_pas_dans_le_journal() {
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

    // Le serveur tente de faire passer sa propre clé pour celle de Bob, en réutilisant la
    // preuve légitime — la seule qu'il possède.
    let (imposteur, _) = crypto_core::Account::generate().unwrap();
    let feuille_forgee =
        transparency::leaf_hash(&transparency::entry(&bob.handle, &imposteur.identity_key()));

    assert!(
        transparency::verify_inclusion(
            &feuille_forgee,
            body["index"].as_u64().unwrap() as usize,
            head["size"].as_u64().unwrap() as usize,
            &proof,
            &root,
        )
        .is_err(),
        "une clé substituée a passé la vérification d'inclusion : le journal ne prouve rien",
    );
}

/// Une rotation **ajoute** au journal. L'ancienne clé y reste : c'est ce qui permet de
/// constater qu'une identité a changé plutôt que de la voir disparaître.
#[tokio::test]
async fn une_rotation_ajoute_au_journal_sans_rien_effacer() {
    let server = start().await;
    let alice = TestAccount::create(&server, &unique("alice")).await;
    let portable = alice.device(&server, &unique("portable")).await;

    let avant: serde_json::Value =
        portable.get("/v1/log/sth").await.json().await.unwrap();
    let taille_avant = avant["size"].as_u64().unwrap();

    let (nouveau, _) = crypto_core::Account::generate().unwrap();
    let rotated_at = common::now();
    let signature =
        alice.account.rotate(&alice.handle, &nouveau.identity_key(), rotated_at).unwrap();

    let response = portable
        .post(
            &format!("/v1/accounts/{}/rotate", alice.handle),
            serde_json::json!({
                "new_identity_key": BASE64_STANDARD.encode(nouveau.identity_key()),
                "rotation": BASE64_STANDARD.encode(signature),
                "rotated_at": rotated_at,
            }),
        )
        .await;
    assert!(response.status().is_success());

    let apres: serde_json::Value = portable.get("/v1/log/sth").await.json().await.unwrap();
    assert!(
        apres["size"].as_u64().unwrap() > taille_avant,
        "la rotation n'a rien ajouté au journal",
    );

    // Et c'est bien la NOUVELLE clé qui est désormais prouvée.
    let preuve: serde_json::Value =
        portable.get(&format!("/v1/log/proof/{}", alice.handle)).await.json().await.unwrap();
    assert_eq!(
        BASE64_STANDARD.decode(preuve["identity_key"].as_str().unwrap()).unwrap(),
        nouveau.identity_key(),
    );
}

/// Le journal doit prouver qu'il prolonge ce que le client a déjà vu, sans réécriture.
#[tokio::test]
async fn le_journal_prouve_sa_coherence_dans_le_temps() {
    let server = start().await;
    let lecteur = Device::register(&server, &unique("lecteur")).await;

    let avant: serde_json::Value = lecteur.get("/v1/log/sth").await.json().await.unwrap();
    let taille_avant = avant["size"].as_u64().unwrap() as usize;
    let racine_avant: [u8; 32] =
        BASE64_STANDARD.decode(avant["root"].as_str().unwrap()).unwrap().try_into().unwrap();

    // Le journal grandit.
    for _ in 0..3 {
        TestAccount::create(&server, &unique("nouveau")).await;
    }

    let body: serde_json::Value = lecteur
        .get(&format!("/v1/log/consistency?from={taille_avant}"))
        .await
        .json()
        .await
        .unwrap();

    let head = &body["head"];
    let racine_apres: [u8; 32] =
        BASE64_STANDARD.decode(head["root"].as_str().unwrap()).unwrap().try_into().unwrap();
    let proof: Vec<[u8; 32]> = body["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| BASE64_STANDARD.decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
        .collect();

    assert_eq!(
        transparency::verify_consistency(
            taille_avant,
            &racine_avant,
            head["size"].as_u64().unwrap() as usize,
            &racine_apres,
            &proof,
        ),
        Ok(()),
        "le journal ne prouve pas qu'il prolonge la tête précédente",
    );
}

// ---------------------------------------------------------------- dépôt anonyme

/// Dépose une enveloppe sans signature d'appareil, avec le MAC du groupe.
async fn post_anonyme(
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

/// **Le test qui compte pour le sealed sender.**
///
/// Le dépôt aboutit **sans aucune signature d'appareil** : ni `x-device-id`, ni `x-signature`,
/// ni horodatage. Le serveur ne peut pas dire lequel des membres a écrit — il sait seulement
/// que le déposant détient la clé du groupe, ce qui est tout ce dont il a besoin.
#[tokio::test]
async fn un_depot_anonyme_aboutit_sans_identifier_l_expediteur() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let group_id = hex::encode(unique("groupe").as_bytes());
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
        post_anonyme(&server, &group_id, &posting_key, b"enveloppe", [1u8; 16]).await;
    assert!(response.status().is_success(), "dépôt anonyme refusé : {:?}", response.status());

    // Et l'enveloppe est bien là, lisible par les membres.
    let envelopes: serde_json::Value = alice
        .get(&format!("/v1/groups/{group_id}/envelopes?after=0"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(envelopes.as_array().unwrap().len(), 1);
}

/// Sans la clé, le dépôt anonyme est refusé : le serveur n'est pas une boîte aux lettres
/// ouverte. C'est la seule chose que le MAC doit garantir, et il doit la garantir.
#[tokio::test]
async fn un_depot_anonyme_sans_la_cle_est_refuse() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let group_id = hex::encode(unique("groupe").as_bytes());
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
        post_anonyme(&server, &group_id, &[7u8; 32], b"intrusion", [2u8; 16]).await;
    assert_eq!(response.status(), 403);
}

/// **Anti-rejeu.** Le MAC ne dépend d'aucun horodatage : sans unicité du nonce, quiconque
/// intercepte un dépôt le rejoue indéfiniment.
#[tokio::test]
async fn un_depot_anonyme_ne_peut_pas_etre_rejoue() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let group_id = hex::encode(unique("groupe").as_bytes());
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
        post_anonyme(&server, &group_id, &posting_key, b"une fois", nonce)
            .await
            .status()
            .is_success()
    );

    assert_eq!(
        post_anonyme(&server, &group_id, &posting_key, b"une fois", nonce).await.status(),
        403,
        "un dépôt rejoué a été accepté",
    );
}

/// Le `group_id` entre dans le MAC : sans cela, un dépôt intercepté se rejouerait dans
/// n'importe quel autre groupe partageant la clé.
#[tokio::test]
async fn un_mac_ne_vaut_que_pour_son_groupe() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let posting_key = [42u8; 32];
    let premier = hex::encode(unique("groupe-a").as_bytes());
    let second = hex::encode(unique("groupe-b").as_bytes());

    for group_id in [&premier, &second] {
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

    // MAC calculé pour le premier groupe, présenté au second.
    use hmac::{Hmac, Mac};
    let body =
        serde_json::to_vec(&serde_json::json!({ "payload": BASE64_STANDARD.encode(b"x") })).unwrap();
    let nonce = [4u8; 16];
    let message = attest::post_message(
        &hex::decode(&premier).unwrap(),
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

/// Un groupe sans clé de dépôt refuse l'anonyme plutôt que de basculer silencieusement sur le
/// chemin signé : un client qui se croit anonyme sans l'être est pire qu'un client qui échoue.
#[tokio::test]
async fn un_groupe_sans_cle_refuse_le_depot_anonyme() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let group_id = hex::encode(unique("groupe").as_bytes());
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({ "device_ids": [alice.id] }),
        )
        .await;

    let response = post_anonyme(&server, &group_id, &[9u8; 32], b"x", [5u8; 16]).await;
    assert_eq!(response.status(), 403);
}

// ---------------------------------------------------------------- signaux éphémères

/// Dépose un signal éphémère, avec le MAC du groupe et sans signature d'appareil.
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

/// Prépare un groupe muni d'une clé de dépôt, et rend son identifiant.
async fn groupe_avec_cle(alice: &Device, posting_key: &[u8]) -> String {
    let group_id = hex::encode(unique("groupe").as_bytes());
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

/// **Le test qui compte pour les signaux : rien n'atteint le disque.**
///
/// C'est la propriété qui justifie l'existence d'une route séparée. La table `envelopes` n'est
/// jamais purgée — et ne peut pas l'être sans trouer le ratchet applicatif — donc un indicateur
/// de frappe qui y entrerait n'en sortirait plus jamais.
#[tokio::test]
async fn un_signal_ne_laisse_aucune_trace_en_base() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let posting_key = [42u8; 32];
    let group_id = groupe_avec_cle(&alice, &posting_key).await;

    let response = post_signal(&server, &group_id, &posting_key, b"signal", [7u8; 16]).await;
    assert_eq!(response.status(), 204, "le signal a été refusé");

    let group = hex::decode(&group_id).unwrap();

    let (enveloppes,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM envelopes WHERE group_id = $1")
            .bind(&group)
            .fetch_one(&server.pool)
            .await
            .unwrap();
    assert_eq!(enveloppes, 0, "un signal a été conservé comme une enveloppe");

    // Pas de nonce consommé non plus : l'anti-rejeu est volontairement absent de ce chemin,
    // et l'y ajouter par mégarde ferait grossir une table toutes les trois secondes.
    let (nonces,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM posting_nonces WHERE group_id = $1")
            .bind(&group)
            .fetch_one(&server.pool)
            .await
            .unwrap();
    assert_eq!(nonces, 0, "le canal éphémère ne doit rien écrire, pas même un nonce");
}

/// Sans le MAC du groupe, le serveur n'est pas un relais ouvert : n'importe qui pourrait
/// sinon faire croire à une conversation entière que quelqu'un écrit.
#[tokio::test]
async fn un_signal_au_mac_invalide_est_refuse() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let group_id = groupe_avec_cle(&alice, &[42u8; 32]).await;

    let response = post_signal(&server, &group_id, &[9u8; 32], b"signal", [7u8; 16]).await;
    assert_eq!(response.status(), 403);
}

/// Un MAC de dépôt d'enveloppe ne vaut pas comme MAC de signal.
///
/// Les deux partagent la même clé ; seul le domaine du message canonique les sépare. Sans
/// cette séparation, un signal capté — qui n'a pas d'anti-rejeu — serait rejouable en dépôt.
#[tokio::test]
async fn le_mac_d_un_depot_ne_vaut_pas_pour_un_signal() {
    use hmac::{Hmac, Mac};

    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let posting_key = [42u8; 32];
    let group_id = groupe_avec_cle(&alice, &posting_key).await;

    let group = hex::decode(&group_id).unwrap();
    let nonce = [7u8; 16];
    let corps = b"signal";

    // Le MAC est calculé dans le domaine du dépôt, pas dans celui du signal.
    let message = attest::post_message(&group, &nonce, &sha2::Sha256::digest(corps)).unwrap();
    let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(&posting_key).unwrap();
    mac.update(&message);

    let response = reqwest::Client::new()
        .post(format!("{}/v1/groups/{group_id}/signals", server.base_url))
        .header("x-group-nonce", BASE64_STANDARD.encode(nonce))
        .header("x-group-mac", BASE64_STANDARD.encode(mac.finalize().into_bytes()))
        .body(corps.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
}

// ---------------------------------------------------------------- présence

/// Met un appareil en ligne, puis attend que la base l'enregistre.
///
/// # Pourquoi une session, et non plus une requête
///
/// La présence était autrefois un effet de bord de l'extracteur `Signed` : n'importe quelle
/// requête signée suffisait. Elle est maintenant alimentée par le battement de la gateway, ce
/// qui est un signal plus juste — une session ouverte dit qu'un client est là, là où une requête
/// peut venir d'un onglet oublié.
///
/// La socket est **gardée ouverte** pendant l'attente : la fermer aussitôt ne changerait rien à
/// la valeur écrite, mais ferait courir le test contre la fermeture côté serveur.
async fn mettre_en_ligne(server: &TestServer, device: &Device) -> Option<i64> {
    let mut socket = common::session(server, device, serde_json::json!([])).await;
    assert_eq!(common::lire(&mut socket).await.unwrap()["op"], "ready");

    let vu = attendre_presence(&server.pool, &device.id).await;
    drop(socket);
    vu
}

/// Attend qu'une présence spawnée atteigne la base, ou renonce.
///
/// La touche est détachée — elle ne doit pas ralentir ce qui la déclenche — donc un test qui lit
/// la colonne aussitôt après course avec elle. Sonder est plus honnête qu'un `sleep` arbitraire :
/// le test réussit dès que la valeur arrive, et échoue franchement sinon.
async fn attendre_presence(pool: &sqlx::PgPool, device_id: &str) -> Option<i64> {
    for _ in 0..40 {
        let row: Option<(Option<i64>,)> = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM last_seen_at)::BIGINT FROM devices WHERE id = $1",
        )
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .unwrap();

        if let Some((Some(vu),)) = row {
            return Some(vu);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    None
}

async fn derniere_presence(pool: &sqlx::PgPool, device_id: &str) -> Option<i64> {
    let (vu,): (Option<i64>,) = sqlx::query_as(
        "SELECT EXTRACT(EPOCH FROM last_seen_at)::BIGINT FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await
    .unwrap();
    vu
}

async fn oublier_presence(pool: &sqlx::PgPool, device_id: &str) {
    sqlx::query("UPDATE devices SET last_seen_at = NULL WHERE id = $1")
        .bind(device_id)
        .execute(pool)
        .await
        .unwrap();
}

/// **Le test qui protège le sealed sender.**
///
/// Les dépôts anonymes et les signaux de frappe prouvent l'appartenance à un groupe par un MAC,
/// pas l'identité : le serveur ne sait pas qui dépose. En dériver une présence reviendrait à le
/// lui apprendre — c'est-à-dire à défaire ce que la migration 0007 a mis en place.
///
/// La protection tient aujourd'hui à une seule ligne : dans `post_envelope`, l'extracteur
/// `Signed` n'est construit que dans la branche signée. C'est correct, et gratuit ; ce test
/// existe pour que ça le reste.
#[tokio::test]
async fn un_depot_anonyme_ne_met_jamais_a_jour_la_presence() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;
    let posting_key = [42u8; 32];
    let group_id = groupe_avec_cle(&alice, &posting_key).await;

    // On met d'abord l'appareil en ligne pour de bon, puis on efface : sans ce passage, un
    // `last_seen_at` resté nul rendrait le test vert quoi qu'il arrive, y compris si la présence
    // avait cessé de fonctionner entièrement.
    mettre_en_ligne(&server, &alice).await.expect("la session n'a rien marqué");
    oublier_presence(&server.pool, &alice.id).await;

    let depot = post_anonyme(&server, &group_id, &posting_key, b"chiffre", [1u8; 16]).await;
    assert!(depot.status().is_success(), "le dépôt anonyme a été refusé");

    let signal = post_signal(&server, &group_id, &posting_key, b"frappe", [2u8; 16]).await;
    assert_eq!(signal.status(), 204, "le signal a été refusé");

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(
        derniere_presence(&server.pool, &alice.id).await,
        None,
        "un chemin anonyme a marqué la présence : le sealed sender ne tient plus",
    );
}

/// **Le test qui fige le nouveau déclencheur de présence.**
///
/// Une session ouverte met en ligne ; une requête signée, non. C'est un changement de
/// comportement assumé — voir l'en-tête de `server::auth` — et non une optimisation invisible :
/// un client qui interroge le serveur sans jamais ouvrir de session reste hors ligne.
#[tokio::test]
async fn seule_une_session_marque_l_appareil_en_ligne() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    // L'enregistrement n'est pas signé : cet appareil n'a encore jamais été vu.
    assert_eq!(derniere_presence(&server.pool, &alice.id).await, None);

    // Des requêtes signées, en nombre, sans session : la colonne doit rester vide.
    for _ in 0..3 {
        alice.get("/v1/groups").await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(
        derniere_presence(&server.pool, &alice.id).await,
        None,
        "la présence est repartie sur le chemin de latence des requêtes",
    );

    assert!(mettre_en_ligne(&server, &alice).await.is_some());
}

/// Fige la décision de coût : une écriture par appareil et par minute, pas une par battement.
///
/// Le test appelle `touch` directement plutôt que de battre par la socket : le rythme réel du
/// battement se compte en dizaines de secondes, et l'attendre ferait de ce test le plus lent de
/// la suite pour vérifier une garde qui, elle, est purement locale.
#[tokio::test]
async fn la_presence_n_est_pas_reecrite_a_chaque_battement() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let premier = mettre_en_ligne(&server, &alice).await.unwrap();

    // Une valeur artificiellement ancienne : seule la garde en mémoire peut encore retenir
    // l'écriture, et c'est précisément ce qu'on vérifie.
    sqlx::query("UPDATE devices SET last_seen_at = now() - interval '1 hour' WHERE id = $1")
        .bind(&alice.id)
        .execute(&server.pool)
        .await
        .unwrap();
    let recule = derniere_presence(&server.pool, &alice.id).await.unwrap();
    assert!(recule < premier);

    for _ in 0..5 {
        server::presence::touch(&server.pool, &alice.id).await.unwrap();
    }

    assert_eq!(derniere_presence(&server.pool, &alice.id).await, Some(recule));
}

/// Prépare deux comptes membres d'un même groupe, plus un troisième à l'écart.
async fn trio(server: &TestServer) -> (TestAccount, Device, TestAccount, Device, TestAccount, Device)
{
    let a = TestAccount::create(server, &unique("alice")).await;
    let alice = a.device(server, "tel").await;
    let b = TestAccount::create(server, &unique("bob")).await;
    let bob = b.device(server, "tel").await;
    let c = TestAccount::create(server, &unique("carol")).await;
    let carol = c.device(server, "tel").await;

    let group_id = hex::encode(unique("groupe").as_bytes());
    alice
        .post(
            &format!("/v1/groups/{group_id}/members"),
            serde_json::json!({ "device_ids": [alice.id, bob.id] }),
        )
        .await;

    (a, alice, b, bob, c, carol)
}

async fn presence_de(appelant: &Device, handles: &[&str]) -> serde_json::Value {
    let response = appelant
        .post("/v1/presence", serde_json::json!({ "handles": handles }))
        .await;
    assert!(response.status().is_success(), "présence refusée : {:?}", response.status());
    response.json().await.unwrap()
}

/// Sans cette clause, la route serait un oracle d'activité sur n'importe quel pseudonyme.
#[tokio::test]
async fn la_presence_n_est_visible_que_dans_un_groupe_commun() {
    let server = start().await;
    let (a, alice, b, bob, _c, carol) = trio(&server).await;

    alice.get("/v1/groups").await;
    bob.get("/v1/groups").await;
    mettre_en_ligne(&server, &alice).await.unwrap();
    mettre_en_ligne(&server, &bob).await.unwrap();

    let vu = presence_de(&bob, &[&a.handle]).await;
    assert_eq!(vu["accounts"].as_array().unwrap().len(), 1, "bob partage un groupe avec alice");

    let rien = presence_de(&carol, &[&a.handle, &b.handle]).await;
    assert!(
        rien["accounts"].as_array().unwrap().is_empty(),
        "carol n'a aucun groupe commun et voit pourtant quelque chose",
    );
}

/// Les distinguer ferait de la route un oracle d'existence de compte.
#[tokio::test]
async fn un_handle_inconnu_et_un_handle_sans_groupe_commun_sont_indistinguables() {
    let server = start().await;
    let (a, alice, _b, _bob, _c, carol) = trio(&server).await;

    alice.get("/v1/groups").await;
    mettre_en_ligne(&server, &alice).await.unwrap();

    let etranger = presence_de(&carol, &[&a.handle]).await;
    let inexistant = presence_de(&carol, &["personne-de-ce-nom"]).await;

    assert_eq!(etranger["accounts"], inexistant["accounts"]);
}

/// Un compte est en ligne dès qu'un seul de ses appareils l'est — et seul ce maximum sort.
///
/// Servir le détail par appareil dirait combien d'appareils une personne possède et lequel elle
/// utilise à quelle heure : une fuite distincte de « en ligne ».
#[tokio::test]
async fn un_compte_est_en_ligne_des_qu_un_seul_de_ses_appareils_l_est() {
    let server = start().await;
    let a = TestAccount::create(&server, &unique("alice")).await;
    let tel = a.device(&server, "tel").await;
    let portable = a.device(&server, "portable").await;
    let b = TestAccount::create(&server, &unique("bob")).await;
    let bob = b.device(&server, "tel").await;

    let group_id = hex::encode(unique("groupe").as_bytes());
    tel.post(
        &format!("/v1/groups/{group_id}/members"),
        serde_json::json!({ "device_ids": [tel.id, portable.id, bob.id] }),
    )
    .await;

    // Seul le portable s'est manifesté ; le téléphone est resté éteint.
    oublier_presence(&server.pool, &tel.id).await;
    portable.get("/v1/groups").await;
    let vu_portable = mettre_en_ligne(&server, &portable).await.unwrap();

    let reponse = presence_de(&bob, &[&a.handle]).await;
    let comptes = reponse["accounts"].as_array().unwrap();

    assert_eq!(comptes.len(), 1, "un compte, une entrée — jamais une par appareil");
    assert_eq!(comptes[0]["handle"], a.handle);
    assert_eq!(comptes[0]["last_seen"].as_i64(), Some(vu_portable));
}

/// Un appareil volé puis révoqué ne doit plus maintenir son propriétaire éveillé.
#[tokio::test]
async fn un_appareil_revoque_ne_maintient_plus_son_compte_en_ligne() {
    let server = start().await;
    let a = TestAccount::create(&server, &unique("alice")).await;
    let tel = a.device(&server, "tel").await;
    let vole = a.device(&server, "vole").await;
    let b = TestAccount::create(&server, &unique("bob")).await;
    let bob = b.device(&server, "tel").await;

    let group_id = hex::encode(unique("groupe").as_bytes());
    tel.post(
        &format!("/v1/groups/{group_id}/members"),
        serde_json::json!({ "device_ids": [tel.id, vole.id, bob.id] }),
    )
    .await;

    vole.get("/v1/groups").await;
    mettre_en_ligne(&server, &vole).await.unwrap();
    oublier_presence(&server.pool, &tel.id).await;

    assert_eq!(presence_de(&bob, &[&a.handle]).await["accounts"].as_array().unwrap().len(), 1);

    let revocation = a.revoke(&tel, &vole.id).await;
    assert!(revocation.status().is_success(), "révocation refusée");

    let apres = presence_de(&bob, &[&a.handle]).await;
    assert!(
        apres["accounts"].as_array().unwrap().is_empty(),
        "un appareil révoqué maintient encore son compte en ligne",
    );
}

/// Le refus est honoré **à l'écriture** : rien n'est enregistré, et le passé est effacé.
///
/// Un réglage qui se contenterait de filtrer en lecture laisserait le serveur tenir le registre
/// quand même — c'est-à-dire ne réglerait rien.
#[tokio::test]
async fn le_refus_de_presence_empeche_l_enregistrement() {
    let server = start().await;
    let a = TestAccount::create(&server, &unique("alice")).await;
    let alice = a.device(&server, "tel").await;

    alice.get("/v1/groups").await;
    mettre_en_ligne(&server, &alice).await.unwrap();

    let response = alice.post("/v1/presence/optout", serde_json::json!({ "optout": true })).await;
    assert!(response.status().is_success());

    assert_eq!(
        derniere_presence(&server.pool, &alice.id).await,
        None,
        "le passé enregistré survit au refus",
    );

    // La garde en mémoire ne doit pas masquer le résultat : on la contourne en repartant d'une
    // valeur ancienne, comme dans le test d'amortissement.
    sqlx::query("UPDATE devices SET last_seen_at = NULL WHERE id = $1")
        .bind(&alice.id)
        .execute(&server.pool)
        .await
        .unwrap();

    for _ in 0..5 {
        alice.get("/v1/groups").await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(derniere_presence(&server.pool, &alice.id).await, None);
}

/// Réciprocité : ne plus diffuser sa présence, c'est aussi cesser de voir celle des autres.
///
/// Sans cette symétrie, le réglage permettrait de voir sans être vu — exactement ce qu'il
/// prétend empêcher. La même règle vaut pour les accusés de lecture.
#[tokio::test]
async fn refuser_de_diffuser_sa_presence_coupe_aussi_la_lecture() {
    let server = start().await;
    let (a, alice, _b, bob, _c, _carol) = trio(&server).await;

    alice.get("/v1/groups").await;
    mettre_en_ligne(&server, &alice).await.unwrap();

    assert_eq!(presence_de(&bob, &[&a.handle]).await["accounts"].as_array().unwrap().len(), 1);

    bob.post("/v1/presence/optout", serde_json::json!({ "optout": true })).await;

    assert!(
        presence_de(&bob, &[&a.handle]).await["accounts"].as_array().unwrap().is_empty(),
        "bob a coupé sa présence et voit encore celle des autres",
    );
}

#[tokio::test]
async fn demander_la_presence_sans_signature_est_refuse() {
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
async fn trop_de_handles_en_une_requete_est_refuse() {
    let server = start().await;
    let alice = Device::register(&server, &unique("alice")).await;

    let handles: Vec<String> = (0..65).map(|i| format!("compte{i}")).collect();
    let response = alice.post("/v1/presence", serde_json::json!({ "handles": handles })).await;

    assert_eq!(response.status(), 400);
}

/// Le détail par appareil ne sort jamais vers un tiers.
///
/// Il dirait combien d'appareils une personne possède et lequel elle utilise à quelle heure :
/// une fuite distincte de « en ligne », et que le maximum par compte suffit à éviter.
#[tokio::test]
async fn le_detail_par_appareil_n_est_servi_qu_a_son_proprietaire() {
    let server = start().await;
    let a = TestAccount::create(&server, &unique("alice")).await;
    let alice = a.device(&server, "tel").await;
    let b = TestAccount::create(&server, &unique("bob")).await;
    let bob = b.device(&server, "tel").await;

    alice.get("/v1/groups").await;
    mettre_en_ligne(&server, &alice).await.unwrap();

    let sien: serde_json::Value = alice
        .get(&format!("/v1/accounts/{}/devices", a.handle))
        .await
        .json()
        .await
        .unwrap();
    assert!(sien["devices"][0]["last_seen"].is_i64(), "le propriétaire ne voit pas ses appareils");

    let tiers: serde_json::Value = bob
        .get(&format!("/v1/accounts/{}/devices", a.handle))
        .await
        .json()
        .await
        .unwrap();
    assert!(
        tiers["devices"][0]["last_seen"].is_null(),
        "un tiers obtient l'activité appareil par appareil",
    );
}
