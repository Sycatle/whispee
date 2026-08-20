//! Harnais de test : serveur réel, base réelle, requêtes signées réelles.
//!
//! Rien n'est simulé. Un test de delivery service qui court-circuite l'authentification ou
//! la base ne teste que sa propre maquette.
//!
//! Ce module est compilé une fois par binaire de test, et aucun n'utilise tout le harnais :
//! `dead_code` y signalerait donc, à chaque compilation, ce qui sert seulement aux autres.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use crypto_core::Account;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

/// Distingue les données de chaque test.
///
/// Le compteur seul ne suffit pas : la base **persiste entre les exécutions**, donc
/// `alice-0` existerait déjà au deuxième `cargo test`, avec une autre clé — et
/// l'enregistrement serait refusé (409), à juste titre. Le préfixe aléatoire par processus
/// isole chaque exécution sans avoir à purger la base.
static COUNTER: AtomicU64 = AtomicU64::new(0);
static RUN_ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    use rand_core::RngCore;
    format!("{:08x}", rand_core::OsRng.next_u32())
});

pub fn unique(prefix: &str) -> String {
    format!("{prefix}-{}-{}", *RUN_ID, COUNTER.fetch_add(1, Ordering::Relaxed))
}

pub struct TestServer {
    pub base_url: String,
    pub pool: PgPool,
}

pub async fn start() -> TestServer {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://whatsapp_clone:dev_only_not_a_secret@localhost:55432/whatsapp_clone".into()
    });

    let pool = server::connect(&database_url).await.unwrap_or_else(|e| {
        panic!("base injoignable ({e}) — lancer `docker compose up -d`");
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = server::app(pool.clone());

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer { base_url: format!("http://{addr}"), pool }
}

/// Un appareil client : sa clé d'authentification et de quoi signer ses requêtes.
///
/// Cette clé est distincte de la clé de signature MLS. Voir `server::auth`.
pub struct Device {
    pub id: String,
    signing_key: SigningKey,
    /// Clé de signature MLS. Distincte de `signing_key` : réutiliser une clé pour deux
    /// protocoles est une erreur classique. Attestée en même temps qu'elle, pour interdire de
    /// recombiner l'attestation d'un appareil avec la clé MLS d'un autre.
    mls_key: [u8; 32],
    http: reqwest::Client,
    base_url: String,
}

/// Un compte pseudonyme et sa clé racine.
///
/// Les tests passent par un compte réel plutôt que par une insertion directe : c'est la seule
/// façon de vérifier que les attestations produites côté client sont bien celles que le
/// serveur accepte.
pub struct TestAccount {
    pub handle: String,
    pub account: Account,
}

impl TestAccount {
    pub async fn create(server: &TestServer, handle: &str) -> Self {
        let (account, _phrase) = Account::generate().unwrap();

        let response = reqwest::Client::new()
            .post(format!("{}/v1/accounts", server.base_url))
            .json(&serde_json::json!({
                "handle": handle,
                "identity_key": BASE64_STANDARD.encode(account.identity_key()),
            }))
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success(), "création de compte refusée");
        Self { handle: handle.to_owned(), account }
    }

    /// Crée un appareil rattaché à ce compte et l'enregistre.
    ///
    /// L'identifiant est qualifié par le handle, comme l'exige le serveur : l'espace de noms
    /// des appareils est local au compte.
    pub async fn device(&self, server: &TestServer, id: &str) -> Device {
        let device = Device::new(server, &format!("{}:{id}", self.handle));
        let response = device.register_under(self).await;
        assert!(response.status().is_success(), "enregistrement refusé : {:?}", response.status());
        device
    }

    /// Révoque un appareil du compte, certificat signé à l'appui.
    ///
    /// Passe par la vraie route et le vrai format signé : un raccourci en SQL ne testerait
    /// que sa propre maquette, et c'est précisément la vérification du certificat qu'on veut
    /// exercer.
    pub async fn revoke(
        &self,
        caller: &Device,
        device_id: &str,
    ) -> reqwest::Response {
        let revoked_at = now();
        let certificat = self.account.revoke(&self.handle, device_id, revoked_at).unwrap();

        caller
            .post(
                &format!("/v1/devices/{device_id}/revoke"),
                serde_json::json!({
                    "revocation": BASE64_STANDARD.encode(certificat),
                    "revoked_at": revoked_at,
                }),
            )
            .await
    }

    pub fn identity_key_b64(&self) -> String {
        BASE64_STANDARD.encode(self.account.identity_key())
    }
}

impl Device {
    /// Enregistre cet appareil sous un compte, avec l'attestation correspondante.
    pub async fn register_under(&self, owner: &TestAccount) -> reqwest::Response {
        let auth_key = self.signing_key.verifying_key().to_bytes();
        let attestation = owner
            .account
            .attest(&owner.handle, &self.id, &auth_key, &self.mls_key)
            .unwrap();

        self.http
            .post(format!("{}/v1/devices", self.base_url))
            .json(&serde_json::json!({
                "id": self.id,
                "handle": owner.handle,
                "auth_key": BASE64_STANDARD.encode(auth_key),
                "mls_key": BASE64_STANDARD.encode(self.mls_key),
                "attestation": BASE64_STANDARD.encode(attestation),
            }))
            .send()
            .await
            .unwrap()
    }

    /// Tente un enregistrement avec une attestation quelconque. Sert aux tests d'attaque.
    pub async fn register_with(&self, handle: &str, attestation: &[u8]) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/devices", self.base_url))
            .json(&serde_json::json!({
                "id": self.id,
                "handle": handle,
                "auth_key": self.public_key_b64(),
                "mls_key": BASE64_STANDARD.encode(self.mls_key),
                "attestation": BASE64_STANDARD.encode(attestation),
            }))
            .send()
            .await
            .unwrap()
    }

    pub fn mls_key(&self) -> &[u8] {
        &self.mls_key
    }

    /// Crée un appareil et son propre compte jetable.
    ///
    /// Raccourci pour les tests qui ne s'intéressent pas au regroupement multi-appareils :
    /// un appareil, un compte. Les tests de comptes passent par [`TestAccount`].
    pub async fn register(server: &TestServer, id: &str) -> Self {
        let owner = TestAccount::create(server, &unique("compte")).await;
        owner.device(server, id).await
    }

    /// Crée un appareil sans l'enregistrer : le serveur ne connaît pas sa clé.
    pub fn new(server: &TestServer, id: &str) -> Self {
        Self {
            id: id.to_owned(),
            signing_key: SigningKey::generate(&mut OsRng),
            mls_key: SigningKey::generate(&mut OsRng).verifying_key().to_bytes(),
            http: reqwest::Client::new(),
            base_url: server.base_url.clone(),
        }
    }

    pub fn public_key_b64(&self) -> String {
        BASE64_STANDARD.encode(self.signing_key.verifying_key().as_bytes())
    }

    /// Signe un défi de gateway, comme le ferait un vrai client.
    ///
    /// Passe par `attest::gateway_message` plutôt que de réécrire le format : une seconde
    /// définition dans les tests validerait la maquette, pas le serveur.
    pub fn sign_challenge(&self, challenge: &[u8]) -> String {
        let message = attest::gateway_message(&self.id, challenge).unwrap();
        BASE64_STANDARD.encode(self.signing_key.sign(&message).to_bytes())
    }

    /// Signe un défi **avec le format d'une requête HTTP**.
    ///
    /// Sert au test qui vérifie qu'une signature captée sur le chemin HTTP n'ouvre pas de
    /// session : c'est la séparation de domaine qui doit la rejeter, pas un hasard de format.
    pub fn sign_challenge_as_http(&self, challenge: &[u8]) -> String {
        let payload = server::auth::signing_payload("GET", "/v1/gateway", now(), challenge);
        BASE64_STANDARD.encode(self.signing_key.sign(&payload).to_bytes())
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.signed("GET", path, Vec::new()).await
    }

    pub async fn post(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        self.signed("POST", path, serde_json::to_vec(&body).unwrap()).await
    }

    async fn signed(&self, method: &str, path: &str, body: Vec<u8>) -> reqwest::Response {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.signed_at(method, path, body, timestamp, path).await
    }

    /// Variante brute pour les tests d'attaque : permet de signer un chemin, un horodatage
    /// ou un corps différents de ceux réellement envoyés.
    pub async fn signed_at(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        timestamp: u64,
        signed_path: &str,
    ) -> reqwest::Response {
        let signed_body = body.clone();
        self.forge(method, path, body, signed_body, timestamp, signed_path).await
    }

    /// Envoie `sent_body` en signant `signed_body`. Sert à vérifier que le serveur détecte
    /// une altération du corps après signature.
    pub async fn forge(
        &self,
        method: &str,
        path: &str,
        sent_body: Vec<u8>,
        signed_body: Vec<u8>,
        timestamp: u64,
        signed_path: &str,
    ) -> reqwest::Response {
        let mut payload = Vec::new();
        payload.extend_from_slice(method.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(signed_path.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(timestamp.to_string().as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(&Sha256::digest(&signed_body));

        let signature = BASE64_STANDARD.encode(self.signing_key.sign(&payload).to_bytes());

        self.http
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{}{path}", self.base_url),
            )
            .header("x-device-id", &self.id)
            .header("x-timestamp", timestamp.to_string())
            .header("x-signature", signature)
            .header("content-type", "application/json")
            .body(sent_body)
            .send()
            .await
            .unwrap()
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
