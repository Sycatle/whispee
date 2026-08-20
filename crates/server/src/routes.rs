//! Endpoints HTTP.
//!
//! Le serveur est une boîte aux lettres aveugle : il route des blobs opaques, tient l'ordre
//! total des messages par groupe, et ne peut rien déchiffrer.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::AppState;
use crate::auth::Signed;
use crate::error::{ApiError, ApiResult};
use crate::presence;
use crate::stream::{Hub, Notice};

/// Plafond du nombre de KeyPackages déposés en une requête. Sans plafond, un appareil peut
/// remplir la base à lui seul.
const MAX_KEY_PACKAGES_PER_REQUEST: usize = 100;

/// Ligne d'appareil telle que servie : identifiant, clé d'authentification, clé MLS,
/// attestation. Nommée pour que la signature des requêtes reste lisible.
type DeviceRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

/// Un appareil et l'état de sa révocation, tel que servi aux clients.
type RevocableDeviceRow =
    (String, Vec<u8>, Vec<u8>, Vec<u8>, Option<i64>, Option<Vec<u8>>, Option<i64>);

/// Plafond du corps d'un dépôt, aligné sur la limite de la couche HTTP.
///
/// Défini ici parce que le chemin anonyme lit le corps lui-même, hors de l'extracteur `Signed`
/// et donc hors de la limite posée par la couche. Sans plafond explicite, ce chemin serait le
/// seul non borné du serveur.
const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Plafond d'enveloppes retournées par appel. Le client pagine avec le curseur `after`.
const MAX_ENVELOPES_PER_PAGE: i64 = 200;

/// Routes aux corps petits : messages MLS, KeyPackages, gestion de groupe.
///
/// Séparées des pièces jointes pour que chaque famille porte sa propre limite de taille.
/// Un plafond unique obligerait soit à interdire les fichiers, soit à autoriser des
/// mégaoctets sur des endpoints qui n'en ont aucun besoin.
/// Routes **ouvertes**, c'est-à-dire sans authentification possible.
///
/// Elles précèdent l'existence d'une identité : on ne peut pas signer une création de compte avec
/// une clé que le serveur ne connaît pas encore. Elles sont donc isolées ici pour porter la seule
/// borne qui leur reste — une limite de débit par adresse.
///
/// Séparées comme l'est déjà [`attachment_router`], et pour la même raison : une famille de
/// routes qui a besoin d'une couche particulière la porte seule, plutôt que de l'imposer à
/// toutes.
///
/// **La création de compte est celle qui justifie le dispositif.** Elle écrit dans le journal de
/// transparence, dont les entrées ne se reprennent pas sans casser les preuves de consistance.
/// Voir `crate::throttle` pour ce que la limite ferme, et pour ce qu'elle ne ferme pas.
pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/accounts", post(create_account))
        .route("/v1/devices", post(register_device))
        .route("/v1/pairings/{pairing_id}", post(deposit_pairing).get(claim_pairing))
        .with_state(state)
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/gateway", get(crate::gateway::handler))
        .route("/v1/presence", post(read_presence))
        .route("/v1/presence/optout", post(set_presence_optout))
        .route("/v1/push/token", post(set_push_token))
        .route("/v1/push/forget", post(forget_push_token))
        .route("/v1/accounts/{handle}/devices", get(list_account_devices))
        .route("/v1/accounts/{handle}/rotate", post(rotate_account))
        .route("/v1/log/sth", get(log_head))
        .route("/v1/log/proof/{handle}", get(log_proof))
        .route("/v1/log/consistency", get(log_consistency))
        .route("/v1/devices/{device_id}/revoke", post(revoke_device))
        .route("/v1/vault/{group_id}", post(store_vault).get(fetch_vault))
        .route("/v1/key-packages", post(publish_key_packages))
        .route("/v1/key-packages/stock", get(key_package_stock))
        .route("/v1/key-packages/{device_id}/claim", post(claim_key_package))
        .route("/v1/groups", get(list_groups))
        .route("/v1/groups/{group_id}/members", post(add_members))
        .route("/v1/groups/{group_id}/members/remove", post(remove_members))
        .route("/v1/groups/{group_id}/signals", post(post_signal))
        .route(
            "/v1/groups/{group_id}/envelopes",
            post(post_envelope).get(fetch_envelopes),
        )
        .with_state(state)
}

/// Routes des pièces jointes, isolées pour porter une limite de corps plus élevée.
pub fn attachment_router(pool: PgPool) -> Router {
    Router::new()
        .route("/v1/groups/{group_id}/attachments", post(upload_attachment))
        .route(
            "/v1/groups/{group_id}/attachments/{attachment_id}",
            get(download_attachment),
        )
        .with_state(pool)
}

fn decode_b64(value: &str) -> ApiResult<Vec<u8>> {
    BASE64_STANDARD
        .decode(value)
        .map_err(|_| ApiError::BadRequest("base64 invalide"))
}

pub(crate) fn decode_group_id(value: &str) -> ApiResult<Vec<u8>> {
    let bytes = hex::decode(value).map_err(|_| ApiError::BadRequest("group_id invalide"))?;
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(ApiError::BadRequest("longueur de group_id invalide"));
    }
    Ok(bytes)
}

/// Plafond d'un signal éphémère.
///
/// Un indicateur de frappe chiffré tient en quelques dizaines d'octets ; ce plafond n'est pas
/// une contrainte de format mais la borne qui empêche ce chemin — qui lit le corps lui-même,
/// hors de la couche HTTP — d'être le seul non borné du serveur.
pub(crate) const MAX_SIGNAL_BYTES: usize = 4096;

/// Vérifie un MAC d'appartenance sur un message canonique déjà construit.
///
/// Extrait pour que le dépôt d'enveloppe et le dépôt de signal partagent exactement la même
/// vérification : deux copies divergeraient, et c'est la copie oubliée qui devient la faille.
fn verify_group_mac(posting_key: &[u8], message: &[u8], mac: &[u8]) -> ApiResult<()> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut hmac = <Hmac<Sha256>>::new_from_slice(posting_key)
        .expect("HMAC-SHA256 accepte toute longueur de clé");
    hmac.update(message);
    hmac.verify_slice(mac).map_err(|_| ApiError::Forbidden)
}

/// Relaie un signal éphémère aux membres connectés, **sans rien écrire**.
///
/// # Pourquoi une route séparée du dépôt d'enveloppe
///
/// Parce que `envelopes` n'est jamais purgée, et ne peut pas l'être : chaque enveloppe consomme
/// une génération du ratchet applicatif MLS, et un trou trop large empêcherait le déchiffrement
/// de la suite. Faire passer un indicateur de frappe par ce chemin conserverait pour toujours
/// la trace de qui a hésité à répondre.
///
/// Ce chemin-ci n'a pas de table. Le signal existe le temps d'un relais, puis n'existe plus.
///
/// # Pas d'anti-rejeu, délibérément
///
/// Contrairement au dépôt d'enveloppe, aucun nonce n'est consommé : rejouer un signal périmé
/// n'a aucun effet observable au-delà de son expiration côté client, et enregistrer un nonce
/// toutes les trois secondes et par conversation ferait grossir une table pour rien —
/// c'est-à-dire écrire sur disque ce que cette route existe précisément pour ne pas écrire.
///
/// L'abus reste borné par ce qui compte : il faut détenir la clé du groupe, donc en être
/// membre, et un membre dispose déjà d'un moyen plus nuisible — déposer des enveloppes, qui,
/// elles, sont conservées.
async fn post_signal(
    State(pool): State<PgPool>,
    State(hub): State<Arc<Hub>>,
    Path(group_id): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<axum::http::StatusCode> {
    let group_id = decode_group_id(&group_id)?;

    // Extraction possédée avant le premier `await` : voir la note d'`anonymous_body`.
    let (nonce, mac) = {
        let headers = request.headers();
        let header = |name: &str| -> ApiResult<Vec<u8>> {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| BASE64_STANDARD.decode(value).ok())
                .ok_or(ApiError::BadRequest("en-tête de signal manquant ou illisible"))
        };

        (header(HEADER_NONCE)?, header(HEADER_MAC)?)
    };

    let body = axum::body::to_bytes(request.into_body(), MAX_SIGNAL_BYTES)
        .await
        .map_err(|_| ApiError::BadRequest("corps illisible"))?;

    verify_signal(&pool, &group_id, &nonce, &mac, &body).await?;

    hub.publish(Notice::Signal { group_id, payload: body.to_vec() });

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Vérifie qu'un signal éphémère émane d'un membre du groupe, sans apprendre lequel.
///
/// Extraite pour que le chemin HTTP et la trame `signal` de la gateway partagent **exactement**
/// la même vérification. C'est le même argument que celui qui a fait extraire
/// [`verify_group_mac`] : deux copies divergent, et c'est celle qu'on a oublié de corriger qui
/// devient la faille.
///
/// Ne publie rien : l'appelant décide de la diffusion, parce que la gateway et la route HTTP
/// n'ont pas la même façon de tenir le hub.
pub(crate) async fn verify_signal(
    pool: &PgPool,
    group_id: &[u8],
    nonce: &[u8],
    mac: &[u8],
    body: &[u8],
) -> ApiResult<()> {
    use sha2::{Digest, Sha256};

    if nonce.len() != 16 {
        return Err(ApiError::BadRequest("nonce de signal invalide"));
    }

    if body.len() > MAX_SIGNAL_BYTES {
        return Err(ApiError::BadRequest("signal trop volumineux"));
    }

    let (posting_key,): (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT posting_key FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_optional(pool)
            .await?
            .ok_or(ApiError::NotFound)?;

    // Un groupe sans clé de dépôt n'a pas encore migré vers le chemin anonyme : refuser plutôt
    // que de retomber sur une vérification par identité, qui ferait de la gateway le seul
    // endroit du serveur où un signal révèle son auteur.
    let posting_key = posting_key.ok_or(ApiError::Forbidden)?;

    let message = attest::signal_message(group_id, nonce, &Sha256::digest(body))
        .map_err(|_| ApiError::BadRequest("signal mal formé"))?;

    verify_group_mac(&posting_key, &message, mac)
}

/// Vérifie que l'appelant est membre du groupe.
///
/// Un identifiant de groupe aléatoire n'est **pas** un contrôle d'accès : sans cette
/// vérification, quiconque devine ou intercepte un identifiant lit toute la boîte.
async fn require_membership(pool: &PgPool, group_id: &[u8], device_id: &str) -> ApiResult<()> {
    // La jointure sur `devices` est ce qui coupe un appareil révoqué du flux, sans attendre
    // que le groupe ait commité son retrait.
    //
    // **C'est de la défense en profondeur, pas la protection réelle.** Un appareil révoqué
    // détient encore les secrets du groupe : il déchiffre tout ce qu'il intercepte par un
    // autre chemin, et rien ici ne l'en empêche. Seul le `Remove` MLS — qui re-clé l'arbre —
    // le prive effectivement de la suite. Ce filtre ferme la fuite immédiate pendant les
    // secondes ou les heures qui séparent la révocation du commit.
    let member: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM group_members m
         JOIN devices d ON d.id = m.device_id
         WHERE m.group_id = $1 AND m.device_id = $2 AND d.revoked_at IS NULL",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await?;

    member.map(|_| ()).ok_or(ApiError::Forbidden)
}

/// Même question, posée par un appelant qui n'échoue pas sur un refus.
///
/// La gateway répond à un `subscribe` refusé par une trame d'erreur et garde la session
/// ouverte, là où une route HTTP renvoie un statut et s'arrête. Le contrôle reste celui de
/// [`require_membership`] — une seule requête, une seule définition de « membre ».
pub(crate) async fn is_member(
    pool: &PgPool,
    group_id: &[u8],
    device_id: &str,
) -> ApiResult<bool> {
    match require_membership(pool, group_id, device_id).await {
        Ok(()) => Ok(true),
        Err(ApiError::Forbidden) => Ok(false),
        Err(other) => Err(other),
    }
}

#[derive(Deserialize)]
struct CreateAccount {
    handle: String,
    /// Clé Ed25519 publique du compte (AIK), en base64.
    identity_key: String,
}

/// Crée un compte pseudonyme. Non signé — il n'existe encore aucune clé connue.
///
/// C'est du **trust on first use** : le serveur croit le premier qui réclame un handle.
/// Réclamer le même handle avec la même clé est idempotent (réinstallation) ; avec une autre
/// clé, c'est refusé, ce qui empêche la reprise silencieuse d'un pseudonyme.
///
/// Ce que le TOFU ne prouve pas : que le premier arrivé était légitime. Il n'existe pas de
/// réponse à cela sans autorité extérieure ou key transparency — hors périmètre, documenté
/// dans le README.
async fn create_account(
    State(pool): State<PgPool>,
    Json(payload): Json<CreateAccount>,
) -> ApiResult<Json<serde_json::Value>> {
    if payload.handle.is_empty() || payload.handle.len() > 64 {
        return Err(ApiError::BadRequest("handle invalide"));
    }

    let identity_key = decode_b64(&payload.identity_key)?;
    if identity_key.len() != 32 {
        return Err(ApiError::BadRequest("clé Ed25519 attendue (32 octets)"));
    }

    let mut tx = pool.begin().await?;

    let inserted = sqlx::query(
        "INSERT INTO accounts (handle, identity_key) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&payload.handle)
    .bind(&identity_key)
    .execute(&mut *tx)
    .await?;

    // Le compte et son entrée de journal dans la **même** transaction. Une clé publiée sans
    // preuve d'inclusion serait rejetée par tous les clients : le compte existerait sans être
    // joignable, et rien n'indiquerait pourquoi.
    if inserted.rows_affected() > 0 {
        crate::log::append(&mut tx, &payload.handle, &identity_key).await?;
    }

    tx.commit().await?;

    if inserted.rows_affected() == 0 {
        let existing: (Vec<u8>,) =
            sqlx::query_as("SELECT identity_key FROM accounts WHERE handle = $1")
                .bind(&payload.handle)
                .fetch_one(&pool)
                .await?;

        if existing.0 != identity_key {
            return Err(ApiError::Conflict("handle déjà pris par un autre compte"));
        }
    }

    Ok(Json(serde_json::json!({ "handle": payload.handle })))
}

#[derive(Deserialize)]
struct RegisterDevice {
    id: String,
    handle: String,
    /// Clé Ed25519 publique servant à authentifier les requêtes HTTP, en base64.
    auth_key: String,
    /// Clé publique de signature MLS de cet appareil, en base64.
    mls_key: String,
    /// Signature du compte sur l'ensemble des champs ci-dessus, en base64.
    attestation: String,
}

/// Enregistre un appareil et son rattachement attesté à un compte.
///
/// Non signé par l'appareil — il n'a pas encore de clé connue — mais **l'attestation est
/// vérifiée**. C'est le seul endroit du serveur qui fait de la cryptographie, et c'est du
/// contrôle d'accès : sans elle, n'importe qui déclarerait un appareil dans le compte de
/// n'importe qui, ce qui reviendrait à donner au serveur (et à tout le monde) le pouvoir de
/// se faire inviter dans les conversations d'autrui.
///
/// Cette vérification n'est **pas** la garantie sur laquelle les clients s'appuient : ils
/// revérifient chacun pour eux-mêmes à la lecture. Un serveur qui mentirait ici ne tromperait
/// que lui-même.
async fn register_device(
    State(pool): State<PgPool>,
    Json(payload): Json<RegisterDevice>,
) -> ApiResult<Json<serde_json::Value>> {
    if payload.id.is_empty() || payload.id.len() > 128 {
        return Err(ApiError::BadRequest("identifiant d'appareil invalide"));
    }

    // L'identifiant d'appareil est qualifié par le handle : `alice:portable`.
    //
    // Sans cela l'espace des identifiants est global, et le premier arrivé accapare les noms
    // courants — le deuxième utilisateur à vouloir nommer son téléphone « portable » se voit
    // refuser l'enregistrement, alors même qu'il détient un compte parfaitement légitime.
    // Le préfixe rend l'espace de noms local au compte ; l'attestation garantit que personne
    // ne peut réclamer le préfixe d'autrui.
    if !payload.id.starts_with(&format!("{}:", payload.handle)) {
        return Err(ApiError::BadRequest(
            "l'identifiant d'appareil doit être préfixé par le handle du compte",
        ));
    }

    let auth_key = decode_b64(&payload.auth_key)?;
    if auth_key.len() != 32 {
        return Err(ApiError::BadRequest("clé Ed25519 attendue (32 octets)"));
    }

    let mls_key = decode_b64(&payload.mls_key)?;
    if mls_key.is_empty() || mls_key.len() > 128 {
        return Err(ApiError::BadRequest("clé de signature MLS invalide"));
    }

    let attestation = decode_b64(&payload.attestation)?;

    let account: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT identity_key FROM accounts WHERE handle = $1")
            .bind(&payload.handle)
            .fetch_optional(&pool)
            .await?;
    let (identity_key,) = account.ok_or(ApiError::NotFound)?;

    let claim = attest::DeviceClaim {
        handle: &payload.handle,
        device_id: &payload.id,
        auth_key: &auth_key,
        mls_key: &mls_key,
    };
    attest::verify(&identity_key, &claim, &attestation)
        .map_err(|_| ApiError::BadRequest("attestation invalide"))?;

    // `DO UPDATE` sur la seule attestation, et seulement si les clés sont inchangées.
    //
    // C'est ce qui permet à un appareil de se **ré-attester après une rotation de compte** :
    // son attestation d'origine, signée par la clé morte, ne vérifie plus chez personne. Sans
    // cette mise à jour, l'appareil qui a lui-même déclenché la rotation serait rejeté par
    // tous les clients, y compris les siens.
    //
    // L'opération ne peut pas installer une attestation douteuse : celle-ci vient d'être
    // vérifiée contre la clé courante du compte, quelques lignes plus haut. La clause `WHERE`
    // interdit en revanche de changer les clés d'un appareil existant — ce serait un autre
    // appareil sous le même nom.
    let inserted = sqlx::query(
        "INSERT INTO devices (id, handle, auth_key, mls_key, attestation)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO UPDATE SET attestation = EXCLUDED.attestation
         WHERE devices.auth_key = EXCLUDED.auth_key AND devices.mls_key = EXCLUDED.mls_key",
    )
    .bind(&payload.id)
    .bind(&payload.handle)
    .bind(&auth_key)
    .bind(&mls_key)
    .bind(&attestation)
    .execute(&pool)
    .await?;

    if inserted.rows_affected() == 0 {
        // Réenregistrement idempotent après réinstallation, refusé si un champ diffère : un
        // appareil ne change ni de clés ni de compte, il s'en crée un nouveau.
        let existing: (String, Vec<u8>, Vec<u8>) =
            sqlx::query_as("SELECT handle, auth_key, mls_key FROM devices WHERE id = $1")
                .bind(&payload.id)
                .fetch_one(&pool)
                .await?;

        if existing != (payload.handle.clone(), auth_key, mls_key) {
            return Err(ApiError::Conflict("identifiant déjà pris par un autre appareil"));
        }
    }

    Ok(Json(serde_json::json!({ "id": payload.id })))
}

#[derive(Serialize)]
struct AccountDevice {
    id: String,
    auth_key: String,
    mls_key: String,
    attestation: String,
    /// Horodatage de révocation en secondes Unix, `None` si l'appareil est actif.
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<u64>,
    /// Certificat correspondant, en base64. Présent exactement quand `revoked_at` l'est —
    /// la base l'impose (`revocation_accompagne_revoked_at`, migration 0005).
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation: Option<String>,
    /// Dernière activité de cet appareil, **servie au seul propriétaire du compte**.
    ///
    /// Le détail par appareil ne sort jamais vers un tiers : il dirait combien d'appareils une
    /// personne possède et lequel elle utilise à quelle heure, ce qui est une fuite distincte
    /// de « en ligne ». Pour son propriétaire, en revanche, c'est ce qui rend visible un
    /// appareil fantôme réellement actif.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<i64>,
}

#[derive(Serialize)]
struct AccountDevices {
    handle: String,
    identity_key: String,
    devices: Vec<AccountDevice>,
}

/// Liste les appareils actifs d'un compte, avec leurs attestations.
///
/// **L'appelant doit revérifier chaque attestation lui-même.** Cet endpoint est la surface
/// exacte par laquelle un serveur malveillant tenterait d'introduire un appareil fantôme ;
/// tout ce qui en sort est une revendication, pas un fait. Le test
/// `un_appareil_fantome_injecte_en_sql_ne_passe_pas_la_verification_du_client` le figent.
///
/// Ce que le serveur peut encore faire : omettre un appareil légitime. La victime constate
/// alors qu'un de ses appareils ne reçoit rien — bruyant, et sans intérêt pour un espion.
async fn list_account_devices(
    State(pool): State<PgPool>,
    Path(handle): Path<String>,
    signed: Signed,
) -> ApiResult<Json<AccountDevices>> {
    let account: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT identity_key FROM accounts WHERE handle = $1")
            .bind(&handle)
            .fetch_optional(&pool)
            .await?;
    let (identity_key,) = account.ok_or(ApiError::NotFound)?;

    // Les appareils révoqués sont servis EUX AUSSI, avec leur certificat. Les taire
    // laisserait le client incapable de distinguer une révocation d'une omission — et
    // l'omission est précisément ce que ce serveur peut encore faire. Un appareil qui
    // disparaît sans certificat est donc un signal, pas un événement normal.
    let rows: Vec<RevocableDeviceRow> = sqlx::query_as(
        "SELECT id, auth_key, mls_key, attestation,
                EXTRACT(EPOCH FROM revoked_at)::BIGINT, revocation,
                EXTRACT(EPOCH FROM last_seen_at)::BIGINT
         FROM devices
         WHERE handle = $1
         ORDER BY id",
    )
    .bind(&handle)
    .fetch_all(&pool)
    .await?;

    // Le détail par appareil n'est servi qu'au propriétaire du compte.
    let proprietaire = caller_handle(&pool, &signed.device_id).await? == handle;

    Ok(Json(AccountDevices {
        handle,
        identity_key: BASE64_STANDARD.encode(identity_key),
        devices: rows
            .into_iter()
            .map(
                |(id, auth_key, mls_key, attestation, revoked_at, revocation, last_seen)| {
                    AccountDevice {
                        id,
                        auth_key: BASE64_STANDARD.encode(auth_key),
                        mls_key: BASE64_STANDARD.encode(mls_key),
                        attestation: BASE64_STANDARD.encode(attestation),
                        revoked_at: revoked_at.map(|t| t as u64),
                        revocation: revocation.map(|r| BASE64_STANDARD.encode(r)),
                        last_seen: if proprietaire { last_seen } else { None },
                    }
                },
            )
            .collect(),
    }))
}

// ---------------------------------------------------------------- journal de transparence

#[derive(Serialize)]
struct SignedHead {
    size: u64,
    root: String,
    timestamp: u64,
    signature: String,
    /// Clé publique du journal, pour que le client puisse vérifier la signature.
    ///
    /// La servir ici est un pis-aller **assumé** : un client qui la découvre auprès du serveur
    /// qu'elle est censée surveiller ne gagne rien contre un serveur malveillant dès le premier
    /// contact. Elle devrait être livrée avec l'application, ou attestée par un opérateur
    /// distinct. Le gossip entre clients est ce qui rattrape partiellement ce défaut.
    log_key: String,
}

async fn signed_head(pool: &PgPool) -> ApiResult<(SignedHead, Vec<transparency::Hash>)> {
    let key = crate::log::signing_key(pool).await?;
    let leaves = crate::log::leaves(pool).await?;
    let (head, signature) = crate::log::head(&leaves, &key);

    Ok((
        SignedHead {
            size: head.size,
            root: BASE64_STANDARD.encode(head.root),
            timestamp: head.timestamp,
            signature: BASE64_STANDARD.encode(signature),
            log_key: BASE64_STANDARD.encode(key.verifying_key().to_bytes()),
        },
        leaves,
    ))
}

/// Tête courante du journal.
///
/// C'est ce que les clients s'échangent entre eux, dans leurs conversations chiffrées, pour
/// détecter un serveur qui tiendrait deux journaux. Chacun voit un journal cohérent ; seule la
/// comparaison des têtes révèle la bifurcation.
async fn log_head(State(pool): State<PgPool>, _signed: Signed) -> ApiResult<Json<SignedHead>> {
    let (head, _) = signed_head(&pool).await?;
    Ok(Json(head))
}

#[derive(Serialize)]
struct InclusionProof {
    handle: String,
    identity_key: String,
    index: usize,
    proof: Vec<String>,
    head: SignedHead,
}

/// Preuve que la clé servie pour ce compte figure bien dans le journal.
///
/// **Le client doit revérifier.** Cette route ne prouve rien par elle-même : elle fournit les
/// éléments qui permettent au client de conclure seul, avec la même crate `transparency`, sans
/// nous faire confiance. C'est tout l'objet du dispositif.
async fn log_proof(
    State(pool): State<PgPool>,
    Path(handle): Path<String>,
    _signed: Signed,
) -> ApiResult<Json<InclusionProof>> {
    let (head, leaves) = signed_head(&pool).await?;

    let (seq, identity_key) =
        crate::log::latest(&pool, &handle).await?.ok_or(ApiError::NotFound)?;
    let index = crate::log::index_of(&pool, seq).await?;

    let proof = transparency::inclusion_proof(&leaves, index)
        .map_err(|_| ApiError::BadRequest("indice hors du journal"))?;

    Ok(Json(InclusionProof {
        handle,
        identity_key: BASE64_STANDARD.encode(identity_key),
        index,
        proof: proof.iter().map(|h| BASE64_STANDARD.encode(h)).collect(),
        head,
    }))
}

#[derive(Deserialize)]
struct ConsistencyQuery {
    /// Taille du journal telle que le client l'a vue la dernière fois.
    from: usize,
}

#[derive(Serialize)]
struct ConsistencyProof {
    proof: Vec<String>,
    head: SignedHead,
}

/// Preuve que le journal d'aujourd'hui prolonge celui que le client a déjà vu.
///
/// C'est la propriété qui distingue un journal auditable d'une base de données : le serveur ne
/// peut pas revenir en arrière et remplacer une clé déjà publiée sans que tous ceux qui ont vu
/// l'ancienne tête le constatent.
async fn log_consistency(
    State(pool): State<PgPool>,
    Query(query): Query<ConsistencyQuery>,
    _signed: Signed,
) -> ApiResult<Json<ConsistencyProof>> {
    let (head, leaves) = signed_head(&pool).await?;

    let proof = transparency::consistency_proof(&leaves, query.from)
        .map_err(|_| ApiError::BadRequest("taille de journal invalide"))?;

    Ok(Json(ConsistencyProof {
        proof: proof.iter().map(|h| BASE64_STANDARD.encode(h)).collect(),
        head,
    }))
}

#[derive(Deserialize)]
struct RotateAccount {
    /// Nouvelle clé Ed25519 publique du compte, en base64.
    new_identity_key: String,
    /// Signature de la rotation par l'**ancienne** clé, en base64.
    rotation: String,
    rotated_at: u64,
}

/// Change la clé d'identité d'un compte.
///
/// # Pourquoi cette route existe
///
/// Tous les appareils d'un compte détiennent la graine : c'est la condition de leur parité,
/// chacun pouvant attester et révoquer comme les autres. La contrepartie est qu'un appareil
/// volé détient le compte entier, et que le révoquer ne sert à rien — son porteur en atteste
/// un nouveau dans la seconde.
///
/// La rotation est la seule réponse. Son effet principal est **mécanique et gratuit** : en
/// changeant `identity_key`, elle rend invérifiables toutes les attestations existantes, que
/// les clients recalculent contre la clé courante. L'appareil qui tourne se ré-atteste
/// aussitôt ; les autres devront être ré-appairés.
///
/// # Ce que le serveur ne peut pas arbitrer
///
/// Le voleur détient la même clé et peut tourner le premier. Le serveur n'a aucun moyen de
/// distinguer les deux : il applique la première rotation valide qui se présente. Le seul
/// recours est l'alerte de changement d'empreinte chez les correspondants — d'où l'importance
/// de ne pas la banaliser.
async fn rotate_account(
    State(pool): State<PgPool>,
    Path(handle): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let payload: RotateAccount = signed.json()?;
    let new_identity_key = decode_b64(&payload.new_identity_key)?;
    let rotation = decode_b64(&payload.rotation)?;

    if new_identity_key.len() != 32 {
        return Err(ApiError::BadRequest("clé d'identité de taille invalide"));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(payload.rotated_at) > crate::auth::MAX_CLOCK_SKEW {
        return Err(ApiError::BadRequest("horodatage de rotation hors fenêtre"));
    }

    // L'appelant doit être un appareil du compte : la signature de rotation le prouve déjà,
    // mais l'exiger ici évite de traiter une requête d'un tiers jusqu'à la vérification.
    let caller: Option<(String,)> = sqlx::query_as("SELECT handle FROM devices WHERE id = $1")
        .bind(&signed.device_id)
        .fetch_optional(&pool)
        .await?;
    if caller.map(|(h,)| h).as_deref() != Some(handle.as_str()) {
        return Err(ApiError::Forbidden);
    }

    let current: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT identity_key FROM accounts WHERE handle = $1")
            .bind(&handle)
            .fetch_optional(&pool)
            .await?;
    let (previous_identity_key,) = current.ok_or(ApiError::NotFound)?;

    let claim = attest::RotationClaim {
        handle: &handle,
        new_identity_key: &new_identity_key,
        rotated_at: payload.rotated_at,
    };
    attest::verify_rotation(&previous_identity_key, &claim, &rotation)
        .map_err(|_| ApiError::Forbidden)?;

    let mut tx = pool.begin().await?;

    sqlx::query("UPDATE accounts SET identity_key = $2 WHERE handle = $1")
        .bind(&handle)
        .bind(&new_identity_key)
        .execute(&mut *tx)
        .await?;

    // Une rotation **ajoute** au journal, elle n'y remplace rien : c'est ce qui permet à un
    // client de constater qu'une clé a changé plutôt que de la voir disparaître, et ce qui
    // interdit au serveur de réécrire discrètement une identité.
    crate::log::append(&mut tx, &handle, &new_identity_key).await?;

    // Les KeyPackages des autres appareils partent avec l'ancienne clé : ils portent des
    // credentials que plus personne ne peut relier au compte, et serviraient à les ajouter à
    // de nouveaux groupes. Ceux de l'appelant restent — il va se ré-attester.
    sqlx::query(
        "DELETE FROM key_packages WHERE device_id IN
         (SELECT id FROM devices WHERE handle = $1 AND id <> $2)",
    )
    .bind(&handle)
    .bind(&signed.device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Les attestations en base ne sont pas effacées : elles deviennent simplement
    // invérifiables, et c'est ce qu'on veut donner à voir. Un client qui reçoit une
    // attestation qui ne vérifie pas la rejette — le même chemin que pour un appareil
    // fantôme, et le même test le couvre.
    Ok(Json(serde_json::json!({ "handle": handle, "rotated_at": payload.rotated_at })))
}

#[derive(Deserialize)]
struct RevokeDevice {
    /// Certificat de révocation signé par le compte (domaine `wac-revoke-v1`), en base64.
    ///
    /// Ce n'est plus l'attestation de l'appareil qui sert de preuve. Elle prouvait la
    /// détention de l'AIK, ce qui suffisait au serveur — mais elle ne dit rien d'une
    /// révocation, et le serveur restait donc la seule source pour les autres clients. Un
    /// certificat distinct est vérifiable par n'importe quel membre du groupe, ce qui est la
    /// condition pour qu'il puisse commiter le retrait MLS sans nous croire sur parole.
    revocation: String,
    /// Horodatage couvert par la signature, en secondes Unix.
    revoked_at: u64,
}

/// Révoque un appareil. Exige la détention de la clé du compte.
///
/// La signature de requête HTTP ne suffirait pas : elle prouve qu'on détient *un* appareil du
/// compte, or un appareil compromis se révoquerait alors lui-même hors de danger, ou
/// révoquerait les autres pour rester seul en place.
async fn revoke_device(
    State(pool): State<PgPool>,
    Path(device_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let payload: RevokeDevice = signed.json()?;
    let revocation = decode_b64(&payload.revocation)?;

    // Même fenêtre que la signature de requête. Sans elle, un compte pourrait fabriquer à
    // l'avance des certificats datés du futur, et un vol de base les rendrait exploitables
    // plus tard ; antidater servirait à prétendre qu'un appareil était déjà écarté au moment
    // où il a légitimement reçu un message.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(payload.revoked_at) > crate::auth::MAX_CLOCK_SKEW {
        return Err(ApiError::BadRequest("horodatage de révocation hors fenêtre"));
    }

    let row: Option<DeviceRow> = sqlx::query_as(
        "SELECT d.handle, d.auth_key, d.mls_key, a.identity_key
         FROM devices d JOIN accounts a ON a.handle = d.handle
         WHERE d.id = $1",
    )
    .bind(&device_id)
    .fetch_optional(&pool)
    .await?;
    let (handle, _auth_key, _mls_key, identity_key) = row.ok_or(ApiError::NotFound)?;

    // L'appelant doit appartenir au même compte que sa cible : sans cette vérification,
    // n'importe quel compte pourrait révoquer les appareils d'un autre.
    let caller: Option<(String,)> = sqlx::query_as("SELECT handle FROM devices WHERE id = $1")
        .bind(&signed.device_id)
        .fetch_optional(&pool)
        .await?;
    if caller.map(|(h,)| h) != Some(handle.clone()) {
        return Err(ApiError::Forbidden);
    }

    let claim = attest::RevocationClaim {
        handle: &handle,
        device_id: &device_id,
        revoked_at: payload.revoked_at,
    };
    attest::verify_revocation(&identity_key, &claim, &revocation)
        .map_err(|_| ApiError::Forbidden)?;

    // `revoked_at` prend la valeur signée et non `now()` : les deux doivent coïncider, sinon
    // le certificat servi aux autres clients ne correspondrait pas à la ligne, et leur
    // vérification échouerait. La fenêtre ci-dessus borne déjà l'écart.
    //
    // Idempotent : une seconde révocation du même appareil ne remplace pas le certificat en
    // place. Sans ce garde-fou, un appareil compromis mais toujours détenteur de l'AIK
    // pourrait réécrire l'horodatage à volonté.
    sqlx::query(
        "UPDATE devices SET revoked_at = to_timestamp($2), revocation = $3
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(&device_id)
    .bind(payload.revoked_at as f64)
    .bind(&revocation)
    .execute(&pool)
    .await?;

    // Le stock de KeyPackages part avec l'appareil : ils ne doivent plus pouvoir servir à
    // l'ajouter à un nouveau groupe.
    sqlx::query("DELETE FROM key_packages WHERE device_id = $1")
        .bind(&device_id)
        .execute(&pool)
        .await?;

    Ok(Json(serde_json::json!({ "revoked": device_id })))
}

/// Durée de vie d'un paquet d'appairage.
///
/// Il contient de quoi prendre le contrôle d'un compte. Une fenêtre courte limite la valeur
/// d'un vol de base : au-delà, le paquet ne vaut plus rien même s'il n'a jamais été relevé.
const PAIRING_TTL_SECONDS: i64 = 300;

#[derive(Deserialize)]
struct DepositPairing {
    /// Paquet déjà scellé, en base64.
    payload: String,
}

/// Dépose un paquet d'appairage scellé.
///
/// Signé par l'appareil d'origine : sans cela n'importe qui remplirait la table, et surtout
/// écraserait le paquet légitime par le sien pendant que l'utilisateur regarde son QR code.
///
/// Le serveur ne voit qu'un blob. Les deux moitiés publiques X25519 ont transité par le QR,
/// hors de sa portée ; il ne peut donc ni l'ouvrir ni en fabriquer un que le nouvel appareil
/// accepterait.
async fn deposit_pairing(
    State(pool): State<PgPool>,
    Path(pairing_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let pairing_id = hex::decode(&pairing_id)
        .map_err(|_| ApiError::BadRequest("identifiant d'appairage invalide"))?;
    if pairing_id.len() != 16 {
        return Err(ApiError::BadRequest("identifiant d'appairage de taille invalide"));
    }

    let payload: DepositPairing = signed.json()?;
    let blob = decode_b64(&payload.payload)?;
    if blob.is_empty() || blob.len() > 64 * 1024 {
        return Err(ApiError::BadRequest("paquet d'appairage de taille invalide"));
    }

    // `ON CONFLICT DO NOTHING` : un identifiant déjà utilisé n'est pas réécrit. Autrement, un
    // appareil malveillant qui devinerait l'identifiant remplacerait le paquet légitime.
    let inserted = sqlx::query(
        "INSERT INTO pairings (id, payload, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3))
         ON CONFLICT DO NOTHING",
    )
    .bind(&pairing_id)
    .bind(&blob)
    .bind(PAIRING_TTL_SECONDS as f64)
    .execute(&pool)
    .await?;

    if inserted.rows_affected() == 0 {
        return Err(ApiError::Conflict("appairage déjà en cours pour cet identifiant"));
    }

    Ok(Json(serde_json::json!({ "deposited": true })))
}

/// Relève le paquet d'appairage. **Non signé** : le nouvel appareil n'a pas encore d'identité
/// connue du serveur — c'est précisément ce que l'appairage va lui donner.
///
/// La sécurité ne tient donc pas à l'authentification mais au chiffrement : sans la clé privée
/// éphémère, le paquet est illisible. L'identifiant seul ne sert à rien.
///
/// La lecture est **unique**. Une seconde relève qui réussirait signifierait qu'un tiers a
/// pu récupérer le paquet ; mieux vaut un appairage qui échoue qu'un appairage silencieusement
/// partagé.
async fn claim_pairing(
    State(pool): State<PgPool>,
    Path(pairing_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let pairing_id = hex::decode(&pairing_id)
        .map_err(|_| ApiError::BadRequest("identifiant d'appairage invalide"))?;

    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "UPDATE pairings SET claimed_at = now()
         WHERE id = $1 AND claimed_at IS NULL AND expires_at > now()
         RETURNING payload",
    )
    .bind(&pairing_id)
    .fetch_optional(&pool)
    .await?;

    let (payload,) = row.ok_or(ApiError::NotFound)?;

    Ok(Json(serde_json::json!({ "payload": BASE64_STANDARD.encode(payload) })))
}

#[derive(Deserialize)]
struct PublishKeyPackages {
    /// KeyPackages sérialisés, en base64.
    packages: Vec<String>,
}

/// Réapprovisionne le stock de KeyPackages de l'appelant.
///
/// Le client doit surveiller son stock et le recharger : à zéro, plus personne ne peut
/// ouvrir de conversation avec cet appareil.
async fn publish_key_packages(
    State(pool): State<PgPool>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let payload: PublishKeyPackages = signed.json()?;

    if payload.packages.is_empty() {
        return Err(ApiError::BadRequest("aucun key package fourni"));
    }
    if payload.packages.len() > MAX_KEY_PACKAGES_PER_REQUEST {
        return Err(ApiError::BadRequest("trop de key packages en une requête"));
    }

    let packages: Vec<Vec<u8>> = payload
        .packages
        .iter()
        .map(|p| decode_b64(p))
        .collect::<ApiResult<_>>()?;

    // Le serveur ne valide pas le contenu des KeyPackages : il ne parle pas MLS. C'est le
    // client qui les valide à la réception — et cette validation ne prouve de toute façon
    // rien sur l'identité derrière (voir `crypto_core::identity::parse_key_package`).
    sqlx::query(
        "INSERT INTO key_packages (device_id, payload)
         SELECT $1, * FROM UNNEST($2::bytea[])",
    )
    .bind(&signed.device_id)
    .bind(&packages)
    .execute(&pool)
    .await?;

    Ok(Json(serde_json::json!({ "published": packages.len() })))
}

#[derive(Serialize)]
struct Stock {
    remaining: i64,
}

async fn key_package_stock(State(pool): State<PgPool>, signed: Signed) -> ApiResult<Json<Stock>> {
    let (remaining,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM key_packages WHERE device_id = $1")
            .bind(&signed.device_id)
            .fetch_one(&pool)
            .await?;

    Ok(Json(Stock { remaining }))
}

#[derive(Serialize)]
struct ClaimedKeyPackage {
    package: String,
    /// Stock restant de l'appareil visé, pour que le client puisse l'avertir.
    remaining: i64,
}

/// Consomme un KeyPackage de l'appareil visé.
///
/// `DELETE ... RETURNING` sur une sous-requête `FOR UPDATE SKIP LOCKED` : le retrait est
/// atomique et deux appels concurrents ne peuvent pas obtenir le même KeyPackage. C'est le
/// point critique de tout le serveur — la clé d'initialisation d'un KeyPackage est à usage
/// unique, et OpenMLS n'empêche pas sa réutilisation.
async fn claim_key_package(
    State(pool): State<PgPool>,
    State(claims): State<Arc<crate::throttle::Claims>>,
    Path(device_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<ClaimedKeyPackage>> {
    // **Quota par couple appelant-cible.**
    //
    // Cette route consomme irréversiblement un KeyPackage de la cible, et n'importe quel
    // appareil authentifié peut la viser — l'appelant n'a aucun lien à prouver avec elle. Sans
    // borne, un compte quelconque vide le stock de qui il veut, et le rend **injoignable pour
    // toute nouvelle conversation** : c'est ce que dit déjà le client à propos de son propre
    // stock, « à zéro, plus personne ne peut ouvrir de conversation avec cet appareil ».
    //
    // Le réapprovisionnement automatique du client atténue sans supprimer : il ne tourne qu'à la
    // relève, et une victime hors ligne ne réapprovisionne pas du tout.
    //
    // Le quota porte sur le couple et non sur l'appelant seul : ouvrir des conversations avec
    // beaucoup de correspondants est légitime, s'acharner sur un seul ne l'est pas. Un appelant
    // honnête n'a besoin que d'un KeyPackage par appareil visé ; la marge couvre les reprises
    // après échec réseau.
    //
    // Ce que cela ne ferme pas : le compteur vit en mémoire, donc par instance, et plusieurs
    // comptes complices contournent la borne. Voir `crate::throttle`.
    let quota = format!("{}:{}", signed.device_id, device_id);
    if !claims.autorise(&quota) {
        return Err(ApiError::TooManyRequests);
    }

    // Un appareil révoqué ne doit plus pouvoir être ajouté à un groupe. Le stock est déjà
    // purgé à la révocation ; cette clause ferme la fenêtre entre les deux requêtes et
    // protège d'un stock républié par un appareil volé.
    let revoked: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM devices WHERE id = $1 AND revoked_at IS NOT NULL")
            .bind(&device_id)
            .fetch_optional(&pool)
            .await?;
    if revoked.is_some() {
        return Err(ApiError::NotFound);
    }

    let claimed: Option<(Vec<u8>,)> = sqlx::query_as(
        "DELETE FROM key_packages
         WHERE id = (
             SELECT id FROM key_packages
             WHERE device_id = $1
             ORDER BY id
             FOR UPDATE SKIP LOCKED
             LIMIT 1
         )
         RETURNING payload",
    )
    .bind(&device_id)
    .fetch_optional(&pool)
    .await?;

    let (package,) = claimed.ok_or(ApiError::NotFound)?;

    let (remaining,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM key_packages WHERE device_id = $1")
            .bind(&device_id)
            .fetch_one(&pool)
            .await?;

    Ok(Json(ClaimedKeyPackage {
        package: BASE64_STANDARD.encode(package),
        remaining,
    }))
}

/// Liste les groupes où l'appelant est déclaré membre.
///
/// C'est ainsi qu'un appareil découvre qu'on l'a ajouté à une conversation pendant qu'il
/// était hors ligne : il n'a aucun autre moyen d'apprendre l'identifiant du groupe.
///
/// L'endpoint ne fait que refléter une métadonnée que le serveur détient déjà
/// (`group_members`). Il ne divulgue donc rien de neuf — mais il rappelle que le serveur
/// sait qui parle avec qui.
async fn list_groups(State(pool): State<PgPool>, signed: Signed) -> ApiResult<Json<Vec<String>>> {
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT group_id FROM group_members WHERE device_id = $1 ORDER BY group_id")
            .bind(&signed.device_id)
            .fetch_all(&pool)
            .await?;

    Ok(Json(rows.into_iter().map(|(id,)| hex::encode(id)).collect()))
}

#[derive(Deserialize)]
struct AddMembers {
    device_ids: Vec<String>,
    /// Clé de dépôt du groupe, en base64. Fournie **uniquement à la création**.
    ///
    /// Elle ne peut pas être changée ensuite : un membre qui la remplacerait rendrait muets
    /// tous les autres, sans qu'aucune erreur ne l'explique. Une rotation demanderait de la
    /// redistribuer d'abord par MLS, ce qui n'est pas fait ici.
    #[serde(default)]
    posting_key: Option<String>,
}

/// Déclare qui peut lire la boîte d'un groupe.
///
/// Le serveur ne connaît pas la composition réelle du groupe — elle est dans l'arbre MLS,
/// chiffré. Cette liste est un contrôle d'accès au transport, distinct et potentiellement
/// divergent de l'appartenance cryptographique. La vérité reste l'arbre MLS : un appareil
/// listé ici sans être dans l'arbre récupère des blobs qu'il ne peut pas déchiffrer.
async fn add_members(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let group_id = decode_group_id(&group_id)?;
    let payload: AddMembers = signed.json()?;

    if payload.device_ids.is_empty() {
        return Err(ApiError::BadRequest("aucun appareil fourni"));
    }

    let mut tx = pool.begin().await?;

    // Crée le groupe s'il n'existe pas. `RETURNING` ne renvoie rien en cas de conflit, d'où
    // le `fetch_optional` : la présence d'une ligne indique que l'appelant vient de créer
    // le groupe et en devient donc légitimement le premier membre.
    let posting_key = match &payload.posting_key {
        Some(encoded) => {
            let key = decode_b64(encoded)?;
            if key.len() != 32 {
                return Err(ApiError::BadRequest("clé de dépôt de taille invalide"));
            }
            Some(key)
        }
        None => None,
    };

    let created: Option<(Vec<u8>,)> = sqlx::query_as(
        "INSERT INTO groups (id, posting_key) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(&group_id)
    .bind(&posting_key)
    .fetch_optional(&mut *tx)
    .await?;

    if created.is_some() {
        sqlx::query("INSERT INTO group_members (group_id, device_id) VALUES ($1, $2)")
            .bind(&group_id)
            .bind(&signed.device_id)
            .execute(&mut *tx)
            .await?;
    } else {
        // Groupe existant : seul un membre peut en ajouter d'autres.
        let member: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2")
                .bind(&group_id)
                .bind(&signed.device_id)
                .fetch_optional(&mut *tx)
                .await?;
        if member.is_none() {
            return Err(ApiError::Forbidden);
        }
    }

    sqlx::query(
        "INSERT INTO group_members (group_id, device_id)
         SELECT $1, * FROM UNNEST($2::text[])
         ON CONFLICT DO NOTHING",
    )
    .bind(&group_id)
    .bind(&payload.device_ids)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(serde_json::json!({ "added": payload.device_ids.len() })))
}

#[derive(Deserialize)]
struct RemoveMembers {
    device_ids: Vec<String>,
}

/// Retire des appareils de la liste de diffusion d'un groupe.
///
/// Pendant symétrique d'[`add_members`], et soumis à la même règle : seul un membre agit. Le
/// serveur n'en sait pas plus ici qu'ailleurs — il ignore le contenu du groupe et **n'applique
/// aucune politique d'administration**.
///
/// # Pourquoi le serveur n'arbitre pas les rôles
///
/// Les rôles d'admin vivent dans une extension du group context MLS, donc dans l'état chiffré.
/// Le serveur ne peut pas les lire, et les lui confier en clair reviendrait à lui rendre le
/// pouvoir que tout le reste lui retire. Ce sont les **clients** qui refusent un commit non
/// autorisé, chacun de son côté. Cet endpoint ne fait que du contrôle d'accès au transport.
///
/// Conséquence assumée : un membre peut retirer n'importe qui de la liste de diffusion sans
/// que le serveur s'y oppose. Il ne gagne rien à le faire — les autres continuent de recevoir
/// le commit MLS par leur propre lecture, et la victime constate qu'elle ne reçoit plus rien.
/// C'est de la censure bruyante, le même registre que l'omission d'appareil.
async fn remove_members(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let group_id = decode_group_id(&group_id)?;
    let payload: RemoveMembers = signed.json()?;

    if payload.device_ids.is_empty() {
        return Err(ApiError::BadRequest("aucun appareil fourni"));
    }

    // On ne passe pas par `require_membership` : un appareil révoqué doit pouvoir être retiré
    // par un membre, et c'est bien l'appelant qu'on vérifie ici, pas la cible.
    require_membership(&pool, &group_id, &signed.device_id).await?;

    let removed = sqlx::query(
        "DELETE FROM group_members
         WHERE group_id = $1 AND device_id = ANY($2::text[])",
    )
    .bind(&group_id)
    .bind(&payload.device_ids)
    .execute(&pool)
    .await?
    .rows_affected();

    Ok(Json(serde_json::json!({ "removed": removed })))
}

/// Plafond d'entrées de coffre par requête et par page.
const MAX_VAULT_ENTRIES: usize = 200;

#[derive(Deserialize)]
struct VaultEntry {
    seq: i64,
    /// Message déjà chiffré sous la clé du coffre, en base64.
    payload: String,
}

#[derive(Deserialize)]
struct StoreVault {
    entries: Vec<VaultEntry>,
}

/// Retourne le compte de l'appareil signataire.
///
/// Le coffre est indexé par compte, jamais par appareil : c'est ce qui permet à un appareil
/// neuf de retrouver l'historique déposé par un autre.
async fn caller_handle(pool: &PgPool, device_id: &str) -> ApiResult<String> {
    let row: Option<(String,)> = sqlx::query_as("SELECT handle FROM devices WHERE id = $1")
        .bind(device_id)
        .fetch_optional(pool)
        .await?;

    row.map(|(handle,)| handle).ok_or(ApiError::Forbidden)
}

/// Dépose des entrées dans le coffre de l'appelant.
///
/// Le serveur ne voit que des blobs : la clé est dérivée de la phrase de récupération, qu'il
/// ne détient pas. `ON CONFLICT DO NOTHING` rend le dépôt idempotent — deux appareils du même
/// compte archivent la même conversation sans se marcher dessus.
async fn store_vault(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<serde_json::Value>> {
    let group_id = decode_group_id(&group_id)?;
    let payload: StoreVault = signed.json()?;

    if payload.entries.is_empty() {
        return Err(ApiError::BadRequest("aucune entrée fournie"));
    }
    if payload.entries.len() > MAX_VAULT_ENTRIES {
        return Err(ApiError::BadRequest("trop d'entrées en une requête"));
    }

    // L'appartenance au groupe est exigée : sans cela, un compte archiverait n'importe quel
    // identifiant de groupe et s'en servirait comme d'un stockage gratuit.
    require_membership(&pool, &group_id, &signed.device_id).await?;
    let handle = caller_handle(&pool, &signed.device_id).await?;

    let seqs: Vec<i64> = payload.entries.iter().map(|e| e.seq).collect();
    let blobs: Vec<Vec<u8>> =
        payload.entries.iter().map(|e| decode_b64(&e.payload)).collect::<ApiResult<_>>()?;

    sqlx::query(
        "INSERT INTO vault_entries (handle, group_id, seq, payload)
         SELECT $1, $2, * FROM UNNEST($3::bigint[], $4::bytea[])
         ON CONFLICT DO NOTHING",
    )
    .bind(&handle)
    .bind(&group_id)
    .bind(&seqs)
    .bind(&blobs)
    .execute(&pool)
    .await?;

    Ok(Json(serde_json::json!({ "stored": seqs.len() })))
}

#[derive(Serialize)]
struct VaultRow {
    seq: i64,
    payload: String,
}

/// Restitue le coffre de l'appelant pour un groupe.
///
/// Seul le compte propriétaire y accède : le `handle` vient de l'appareil signataire, jamais
/// d'un paramètre. C'est ce qui empêche de lire le coffre d'un autre en connaissant son
/// pseudonyme.
async fn fetch_vault(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    Query(query): Query<FetchQuery>,
    signed: Signed,
) -> ApiResult<Json<Vec<VaultRow>>> {
    let group_id = decode_group_id(&group_id)?;
    let handle = caller_handle(&pool, &signed.device_id).await?;

    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, payload FROM vault_entries
         WHERE handle = $1 AND group_id = $2 AND seq > $3
         ORDER BY seq
         LIMIT $4",
    )
    .bind(&handle)
    .bind(&group_id)
    .bind(query.after)
    .bind(MAX_VAULT_ENTRIES as i64)
    .fetch_all(&pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(seq, payload)| VaultRow { seq, payload: BASE64_STANDARD.encode(payload) })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct PostEnvelope {
    /// Blob MLS opaque, en base64.
    payload: String,
}

#[derive(Serialize)]
struct EnvelopePosted {
    seq: i64,
}

/// Dépose une enveloppe et lui attribue son numéro de séquence.
///
/// L'incrément et l'insertion sont dans la même transaction, et l'`UPDATE` verrouille la
/// ligne du groupe : deux envois concurrents sont sérialisés. MLS exige que tous les membres
/// appliquent les commits dans le même ordre — deux membres qui divergent d'epoch ne peuvent
/// plus se lire du tout.
/// Vérifie un dépôt anonyme et retourne l'enveloppe.
///
/// # Ce qui est authentifié
///
/// `HMAC(clé du groupe, "wac-post-v1" ‖ group_id ‖ nonce ‖ SHA256(corps))`.
///
/// Le `group_id` empêche de rejouer un MAC dans un autre groupe. Le nonce le rend unique, et
/// son unicité est imposée **par la base**, pas par une lecture suivie d'une écriture — un
/// contrôle applicatif laisserait une fenêtre de concurrence entre les deux.
///
/// L'empreinte du corps est incluse plutôt que le corps lui-même : sans elle, un intermédiaire
/// substituerait l'enveloppe sous un MAC légitime.
async fn anonymous_body(
    pool: &PgPool,
    group_id: &[u8],
    request: axum::extract::Request,
) -> ApiResult<Vec<u8>> {
    use sha2::{Digest, Sha256};

    // Les en-têtes sont extraits en valeurs possédées **avant** le premier `await`. Garder un
    // emprunt sur `request` à travers un point de suspension rendrait le futur non-`Send`, et
    // axum exige des handlers `Send` — l'erreur qui en résulte ne désigne pas la cause. Voir
    // la même précaution dans `auth::Signed`.
    let (nonce, mac) = {
        let headers = request.headers();
        let header = |name: &str| -> ApiResult<Vec<u8>> {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| BASE64_STANDARD.decode(value).ok())
                .ok_or(ApiError::BadRequest("en-tête de dépôt anonyme manquant ou illisible"))
        };

        (header(HEADER_NONCE)?, header(HEADER_MAC)?)
    };

    if nonce.len() != 16 {
        return Err(ApiError::BadRequest("nonce de dépôt invalide"));
    }

    let (posting_key,): (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT posting_key FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_optional(pool)
            .await?
            .ok_or(ApiError::NotFound)?;

    // Un groupe sans clé de dépôt n'accepte pas l'anonyme. Répondre 403 plutôt que de basculer
    // silencieusement sur le chemin signé : un client qui se croit anonyme et ne l'est pas est
    // pire qu'un client qui échoue.
    let posting_key = posting_key.ok_or(ApiError::Forbidden)?;

    let body = axum::body::to_bytes(request.into_body(), MAX_ENVELOPE_BYTES)
        .await
        .map_err(|_| ApiError::BadRequest("corps illisible"))?;

    let payload: PostEnvelope =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("corps invalide"))?;
    let blob = decode_b64(&payload.payload)?;

    let message = attest::post_message(group_id, &nonce, &Sha256::digest(&body))
        .map_err(|_| ApiError::BadRequest("dépôt mal formé"))?;

    verify_group_mac(&posting_key, &message, &mac)?;

    // L'unicité est une contrainte de clé primaire : un rejeu échoue à l'insertion, sans
    // fenêtre de concurrence possible.
    let inserted =
        sqlx::query("INSERT INTO posting_nonces (group_id, nonce) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(group_id)
            .bind(&nonce)
            .execute(pool)
            .await?;

    if inserted.rows_affected() == 0 {
        return Err(ApiError::Forbidden);
    }

    Ok(blob)
}

/// En-têtes du dépôt **anonyme**.
///
/// Leur présence bascule la route sur le chemin sealed sender : aucune signature d'appareil
/// n'est alors exigée ni acceptée, et le serveur n'apprend pas qui dépose.
const HEADER_NONCE: &str = "x-group-nonce";
const HEADER_MAC: &str = "x-group-mac";

/// Dépose une enveloppe dans un groupe.
///
/// # Deux chemins d'autorisation, un seul effet
///
/// **Signé** : l'appareil prouve son identité. Le serveur apprend qui écrit, quand, et dans
/// quel groupe. C'est le chemin historique, conservé pour les groupes créés avant le sealed
/// sender.
///
/// **Anonyme** : le déposant prouve seulement qu'il détient la clé du groupe, donc qu'il en est
/// membre. Le serveur ne peut pas dire lequel. C'est tout ce dont il a besoin pour ne pas
/// servir de boîte aux lettres ouverte.
///
/// Les deux aboutissent à la même enveloppe : l'expéditeur réel est authentifié **par MLS**, à
/// l'intérieur du chiffré, et les destinataires le lisent. Ce qui disparaît, c'est ce que le
/// serveur en sait.
#[derive(Deserialize)]
struct PushToken {
    provider: String,
    token: String,
}

/// Enregistre le jeton de réveil de l'appareil appelant.
///
/// Signé, donc rattaché à un appareil déjà connu : sans cela, n'importe qui pourrait faire
/// vibrer le téléphone d'autrui en devinant un identifiant.
///
/// Le fournisseur est repris tel quel et non vérifié contre une liste : le serveur n'a rien à
/// décider ici, et une liste fermée obligerait à le redéployer le jour où une plateforme change
/// de nom. Un jeton adressé à un fournisseur non branché est simplement ignoré à l'émission.
async fn set_push_token(State(pool): State<PgPool>, signed: Signed) -> ApiResult<()> {
    let payload: PushToken = signed.json()?;

    if payload.token.is_empty() || payload.provider.is_empty() {
        return Err(ApiError::BadRequest("jeton de réveil vide"));
    }

    crate::push::enregistrer(&pool, &signed.device_id, &payload.provider, &payload.token).await?;
    Ok(())
}

/// Retire le jeton. L'appareil cesse d'être réveillé, et le serveur cesse d'avoir une adresse.
///
/// Distinct d'un réglage « désactivé » qui garderait la ligne : ce qui n'est pas stocké ne peut
/// pas être exigé plus tard, ni fuiter avec une base.
async fn forget_push_token(State(pool): State<PgPool>, signed: Signed) -> ApiResult<()> {
    crate::push::oublier(&pool, &signed.device_id).await?;
    Ok(())
}

async fn post_envelope(
    State(pool): State<PgPool>,
    State(hub): State<Arc<Hub>>,
    State(reveil): State<Arc<dyn crate::push::Emetteur>>,
    Path(group_id): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<Json<EnvelopePosted>> {
    let group_id = decode_group_id(&group_id)?;

    let anonyme = request.headers().contains_key(HEADER_MAC);

    let mut expediteur = None;

    let blob = if anonyme {
        anonymous_body(&pool, &group_id, request).await?
    } else {
        let signed = <Signed as axum::extract::FromRequest<PgPool>>::from_request(request, &pool)
            .await?;
        let payload: PostEnvelope = signed.json()?;
        require_membership(&pool, &group_id, &signed.device_id).await?;
        expediteur = Some(signed.device_id.clone());
        decode_b64(&payload.payload)?
    };

    if blob.is_empty() {
        return Err(ApiError::BadRequest("enveloppe vide"));
    }

    let mut tx = pool.begin().await?;

    let (seq,): (i64,) =
        sqlx::query_as("UPDATE groups SET next_seq = next_seq + 1 WHERE id = $1 RETURNING next_seq")
            .bind(&group_id)
            .fetch_one(&mut *tx)
            .await?;

    sqlx::query("INSERT INTO envelopes (group_id, seq, payload) VALUES ($1, $2, $3)")
        .bind(&group_id)
        .bind(seq)
        .bind(&blob)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // Après le commit, jamais avant : annoncer une enveloppe qu'une transaction annulée aurait
    // fait disparaître enverrait les clients chercher un `seq` inexistant.
    hub.publish(Notice::Envelope { group_id: group_id.clone(), seq });

    // Le réveil ne concerne que les appareils **non connectés** : ceux qui le sont viennent
    // d'être servis par la ligne au-dessus. Le serveur ne sait pas lesquels le sont, donc il les
    // réveille tous — un réveil de trop coûte une notification silencieuse, un réveil manquant
    // coûte un message qui n'arrive pas.
    //
    // `expediteur` est `None` sur un dépôt anonyme : le sealed sender a retiré au serveur le
    // pouvoir de savoir qui dépose, et il n'est pas question de le lui rendre pour économiser
    // une notification.
    crate::push::reveiller_detache(pool.clone(), reveil, group_id, expediteur);

    Ok(Json(EnvelopePosted { seq }))
}

#[derive(Serialize)]
struct AttachmentUploaded {
    id: String,
}

/// Dépose une pièce jointe déjà chiffrée.
///
/// Le corps est le blob brut, sans encodage : le base64 coûterait un tiers de bande passante
/// pour rien. Le serveur ne l'inspecte pas et n'en connaît ni le nom, ni le type, ni la clé —
/// tout cela voyage chiffré dans le message MLS qui référencera cet identifiant.
async fn upload_attachment(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    signed: Signed,
) -> ApiResult<Json<AttachmentUploaded>> {
    let group_id = decode_group_id(&group_id)?;
    require_membership(&pool, &group_id, &signed.device_id).await?;

    if signed.body.is_empty() {
        return Err(ApiError::BadRequest("pièce jointe vide"));
    }

    let (id,): (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO attachments (group_id, payload) VALUES ($1, $2) RETURNING id",
    )
    .bind(&group_id)
    .bind(signed.body.as_ref())
    .fetch_one(&pool)
    .await?;

    Ok(Json(AttachmentUploaded { id: id.to_string() }))
}

/// Restitue une pièce jointe chiffrée.
///
/// Le blob est servi tel quel. S'il a été altéré ou substitué, l'AEAD du client échouera à
/// l'ouverture : c'est le client, et non le serveur, qui garantit l'intégrité du fichier.
///
/// Le type MIME renvoyé est volontairement `application/octet-stream` : ces octets sont
/// opaques pour le serveur, et annoncer un type deviné inviterait le navigateur à les
/// interpréter — un SVG ou un HTML rendu inline exécuterait du script sur cette origine.
async fn download_attachment(
    State(pool): State<PgPool>,
    Path((group_id, attachment_id)): Path<(String, String)>,
    signed: Signed,
) -> ApiResult<axum::response::Response> {
    use axum::http::header;
    use axum::response::IntoResponse;

    let group_id = decode_group_id(&group_id)?;
    require_membership(&pool, &group_id, &signed.device_id).await?;

    let attachment_id: uuid::Uuid = attachment_id
        .parse()
        .map_err(|_| ApiError::BadRequest("identifiant de pièce jointe invalide"))?;

    // Le `group_id` fait partie de la clause : sans lui, un membre d'un groupe pourrait
    // lire les pièces jointes d'un autre en devinant un identifiant.
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT payload FROM attachments WHERE id = $1 AND group_id = $2")
            .bind(attachment_id)
            .bind(&group_id)
            .fetch_optional(&pool)
            .await?;

    let (payload,) = row.ok_or(ApiError::NotFound)?;

    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_DISPOSITION, "attachment"),
        ],
        payload,
    )
        .into_response())
}

#[derive(Deserialize)]
struct FetchQuery {
    /// Curseur : ne retourne que les enveloppes strictement postérieures.
    #[serde(default)]
    after: i64,
}

#[derive(Serialize)]
struct Envelope {
    seq: i64,
    payload: String,
}

async fn fetch_envelopes(
    State(pool): State<PgPool>,
    Path(group_id): Path<String>,
    Query(query): Query<FetchQuery>,
    signed: Signed,
) -> ApiResult<Json<Vec<Envelope>>> {
    let group_id = decode_group_id(&group_id)?;
    require_membership(&pool, &group_id, &signed.device_id).await?;

    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, payload FROM envelopes
         WHERE group_id = $1 AND seq > $2
         ORDER BY seq
         LIMIT $3",
    )
    .bind(&group_id)
    .bind(query.after)
    .bind(MAX_ENVELOPES_PER_PAGE)
    .fetch_all(&pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(seq, payload)| Envelope { seq, payload: BASE64_STANDARD.encode(payload) })
            .collect(),
    ))
}

/// Plafond de handles par requête de présence.
///
/// Même raison que pour les KeyPackages : borner ce qu'une seule requête peut demander. Ici
/// s'ajoute une raison propre — sans plafond, la route deviendrait un moyen commode de balayer
/// tout le carnet d'un coup.
const MAX_PRESENCE_HANDLES: usize = 64;

#[derive(Deserialize)]
struct PresenceRequest {
    handles: Vec<String>,
}

#[derive(Serialize)]
struct PresenceEntry {
    handle: String,
    last_seen: i64,
}

#[derive(Serialize)]
struct PresenceResponse {
    /// Horloge du serveur, servie avec la réponse.
    ///
    /// Le client compare deux horloges pour décider si quelqu'un est en ligne. `MAX_CLOCK_SKEW`
    /// existe précisément parce qu'elles divergent : comparer un horodatage serveur à l'heure
    /// locale ferait clignoter le point chez tout utilisateur mal réglé.
    now: i64,
    accounts: Vec<PresenceEntry>,
}

/// Présence des correspondants demandés.
///
/// # Pourquoi POST plutôt que GET
///
/// Pour que les handles restent hors de l'URL, donc hors des journaux d'accès de tout proxy
/// traversé. C'est le même argument que celui qui a écarté `EventSource` pour le flux. Le corps
/// est déjà couvert par la signature, il n'y a rien à ajouter.
///
/// # Pourquoi pas une poussée par le flux
///
/// Le hub est indexé par groupe, la présence est un fait de compte : pousser demanderait une
/// diffusion par groupe et par battement, dans des canaux qui existent pour la correction. Et
/// surtout, le point vert dépendrait alors du flux — un flux bloqué afficherait tout le monde
/// hors ligne, ce qui est une interface *fausse*, pas seulement en retard.
async fn read_presence(State(pool): State<PgPool>, signed: Signed) -> ApiResult<Json<PresenceResponse>> {
    let payload: PresenceRequest = signed.json()?;

    if payload.handles.len() > MAX_PRESENCE_HANDLES {
        return Err(ApiError::BadRequest("trop de handles"));
    }

    let seen = presence::read(&pool, &signed.device_id, &payload.handles).await?;
    // `SystemTime` plutôt qu'une dépendance de date : on ne sert qu'un nombre de secondes.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(Json(PresenceResponse {
        now,
        accounts: seen
            .into_iter()
            .map(|s| PresenceEntry { handle: s.handle, last_seen: s.last_seen })
            .collect(),
    }))
}

#[derive(Deserialize)]
struct OptoutRequest {
    optout: bool,
}

/// Active ou lève le refus de diffuser sa présence.
///
/// Le refus est **réciproque** : il coupe aussi la lecture. Sans cette symétrie, le réglage
/// permettrait de voir sans être vu, c'est-à-dire exactement ce qu'il prétend empêcher. La même
/// règle vaut déjà pour les accusés de lecture.
///
/// Il est honoré à l'écriture, dans `presence::touch` : rien n'est enregistré. Un réglage qui se
/// contenterait de filtrer en lecture laisserait le serveur tenir le registre quand même.
async fn set_presence_optout(State(pool): State<PgPool>, signed: Signed) -> ApiResult<()> {
    let payload: OptoutRequest = signed.json()?;
    let handle = caller_handle(&pool, &signed.device_id).await?;

    sqlx::query("UPDATE accounts SET presence_optout = $2 WHERE handle = $1")
        .bind(&handle)
        .bind(payload.optout)
        .execute(&pool)
        .await?;

    // Le passé n'a pas à survivre au refus : ce qui a déjà été enregistré cesse d'être servi,
    // et cesse aussi d'exister. Le garder ferait mentir le réglage à l'instant même où il est
    // pris.
    if payload.optout {
        sqlx::query("UPDATE devices SET last_seen_at = NULL WHERE handle = $1")
            .bind(&handle)
            .execute(&pool)
            .await?;
    }

    Ok(())
}
