//! Authentification des requêtes par signature Ed25519.
//!
//! Chaque appareil enregistre une clé publique d'authentification, **distincte de sa clé de
//! signature MLS**. Réutiliser une même clé pour deux protocoles est une erreur classique :
//! si les formats de message se recouvrent, une signature produite dans l'un devient une
//! signature valide dans l'autre.
//!
//! Il n'y a donc ni mot de passe, ni jeton de session à voler côté serveur : la base ne
//! contient que des clés publiques.
//!
//! # Limite connue : anti-rejeu par fenêtre temporelle
//!
//! Une requête signée peut être rejouée pendant [`MAX_CLOCK_SKEW`]. Un vrai anti-rejeu
//! demanderait un cache de nonces déjà vus, avec sa purge. Conséquence réelle : un
//! observateur du réseau peut faire redéposer une enveloppe déjà envoyée. Le doublon est
//! rejeté par le client MLS (la clé de message a été consommée), donc l'impact se limite à
//! du bruit — mais la limite doit être levée avant tout usage sérieux.
//!
//! # Ce que cet extracteur ne fait plus
//!
//! Noter l'appareil comme éveillé. La présence se lisait ici de toute requête signée, ce qui
//! plaçait une écriture SQL potentielle sur le chemin de latence de tout le serveur — pour un
//! point de couleur. Elle est désormais alimentée par le battement de [`crate::gateway`], qui
//! est un signal plus juste : une session ouverte dit qu'un client est là, là où une requête
//! peut venir d'un onglet oublié.
//!
//! Conséquence à assumer : un client qui n'ouvre jamais de session n'apparaît jamais en ligne,
//! même s'il interroge le serveur. C'est cohérent — sans session, il n'est de toute façon pas
//! joignable en temps réel — mais c'est un changement de comportement, pas une optimisation
//! transparente.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::error::{ApiError, ApiResult};

/// Tolérance d'horloge acceptée entre le client et le serveur.
pub const MAX_CLOCK_SKEW: u64 = 60;

pub const HEADER_DEVICE: &str = "x-device-id";
pub const HEADER_TIMESTAMP: &str = "x-timestamp";
pub const HEADER_SIGNATURE: &str = "x-signature";

/// Requête authentifiée : l'appelant a prouvé la possession de la clé privée de `device_id`.
pub struct Signed {
    pub device_id: String,
    pub body: Bytes,
}

/// Message effectivement signé.
///
/// La méthode et le chemin en font partie : sans eux, une signature valide pour
/// `GET /stock` serait rejouable sur `POST /envelopes`. Le corps est inclus par son
/// empreinte, ce qui évite de le garder deux fois en mémoire.
pub fn signing_payload(method: &str, path: &str, timestamp: u64, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(method.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(path.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(timestamp.to_string().as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(&Sha256::digest(body));
    payload
}

impl<S> FromRequest<S> for Signed
where
    S: Send + Sync,
    PgPool: axum::extract::FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        use axum::extract::FromRef;

        // Tout ce qui vient de la requête est extrait en valeurs possédées avant le
        // premier `await` : garder un emprunt sur `request` à travers un point de suspension
        // rendrait le futur non-`Send`, et axum exige des handlers `Send`.
        let (device_id, timestamp, signature, method, path) = {
            let headers = request.headers();
            let header = |name: &str| -> Option<String> {
                headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
            };

            let device_id = header(HEADER_DEVICE).ok_or(ApiError::Unauthorized)?;
            let timestamp: u64 = header(HEADER_TIMESTAMP)
                .and_then(|t| t.parse().ok())
                .ok_or(ApiError::Unauthorized)?;
            let signature = header(HEADER_SIGNATURE).ok_or(ApiError::Unauthorized)?;

            let method = request.method().as_str().to_owned();
            let path = request
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_else(|| request.uri().path().to_owned());

            (device_id, timestamp, signature, method, path)
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApiError::Unauthorized)?
            .as_secs();
        if now.abs_diff(timestamp) > MAX_CLOCK_SKEW {
            return Err(ApiError::Unauthorized);
        }

        let pool = PgPool::from_ref(state);
        let body = Bytes::from_request(request, state)
            .await
            .map_err(|_| ApiError::BadRequest("corps illisible"))?;

        let auth_key: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT auth_key FROM devices WHERE id = $1")
                .bind(&device_id)
                .fetch_optional(&pool)
                .await?;

        // Appareil inconnu et signature invalide renvoient la même erreur : les distinguer
        // permettrait d'énumérer les appareils enregistrés.
        let (auth_key,) = auth_key.ok_or(ApiError::Unauthorized)?;

        let verifying_key: [u8; 32] = auth_key.try_into().map_err(|_| ApiError::Unauthorized)?;
        let verifying_key =
            VerifyingKey::from_bytes(&verifying_key).map_err(|_| ApiError::Unauthorized)?;

        let signature = BASE64_STANDARD
            .decode(signature)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .map(|bytes| Signature::from_bytes(&bytes))
            .ok_or(ApiError::Unauthorized)?;

        verifying_key
            .verify_strict(&signing_payload(&method, &path, timestamp, &body), &signature)
            .map_err(|_| ApiError::Unauthorized)?;

        Ok(Self { device_id, body })
    }
}

impl Signed {
    /// Désérialise le corps signé. La signature couvre les octets exacts reçus, donc la
    /// désérialisation n'a lieu qu'après vérification.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> ApiResult<T> {
        serde_json::from_slice(&self.body).map_err(|_| ApiError::BadRequest("JSON invalide"))
    }
}
