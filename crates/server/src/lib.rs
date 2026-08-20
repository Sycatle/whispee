//! Delivery service : le transport que MLS ne définit pas.
//!
//! # Ce que ce serveur peut voir
//!
//! Rien du contenu. Mais il voit, et c'est important de l'énoncer :
//!
//! * qui est enregistré, et depuis quand ;
//! * quel appareil appartient à quel groupe (table `group_members`) ;
//! * qui écrit dans quel groupe, quand, et la taille de chaque message ;
//! * qui réclame le KeyPackage de qui — donc qui ouvre une conversation avec qui ;
//! * quand chaque compte est éveillé, à la minute près (`devices.last_seen_at`).
//!
//! C'est le compromis de WhatsApp. Le réduire demande du sealed sender, du padding et des
//! credentials à divulgation nulle. Ce n'est pas fait ici, et le prétendre serait pire que
//! de ne pas le faire.

pub mod auth;
pub mod error;
pub mod gateway;
pub mod log;
pub mod presence;
pub mod routes;
pub mod stream;

use std::sync::Arc;

use axum::extract::FromRef;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// État partagé par les handlers : la base, et les auditeurs connectés.
///
/// `FromRef` est ce qui permet aux handlers existants de continuer à extraire `State<PgPool>`
/// sans être touchés — y compris l'extracteur [`auth::Signed`], qui exige seulement qu'un
/// `PgPool` soit dérivable de l'état.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub hub: Arc<stream::Hub>,
}

impl FromRef<AppState> for PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

impl FromRef<AppState> for Arc<stream::Hub> {
    fn from_ref(state: &AppState) -> Self {
        state.hub.clone()
    }
}

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    // Une connexion de plus qu'avant : l'écoute inter-instances (`stream::Hub::attach`) en
    // immobilise une en permanence sur son `LISTEN`. Ne pas ajuster ce chiffre reviendrait à
    // retirer une connexion au service des requêtes.
    let pool = PgPoolOptions::new()
        .max_connections(11)
        .connect(database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    // La clé du journal est créée au premier démarrage, jamais deux fois : deux clés
    // signeraient deux journaux, et les clients verraient une bifurcation causée par nous.
    log::ensure_signing_key(&pool).await?;

    // Les comptes antérieurs au journal doivent y entrer, sans quoi les clients rejetteraient
    // toutes leurs clés faute de preuve d'inclusion.
    log::backfill(&pool).await?;

    Ok(pool)
}

/// Plafond d'une pièce jointe, chiffré compris.
///
/// Le chiffrement AES-GCM n'ajoute que 16 octets de tag : la limite porte donc en pratique
/// sur la taille du fichier d'origine.
pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// Origines autorisées à appeler l'API depuis un navigateur.
///
/// Jamais de joker : `Access-Control-Allow-Origin: *` laisserait n'importe quel site
/// déclencher des requêtes vers ce serveur depuis le navigateur d'un utilisateur. Les
/// requêtes restent signées, donc un site tiers ne pourrait rien authentifier — mais
/// autoriser large sans raison est exactement ce qui transforme un défaut mineur en faille.
fn cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, Method, HeaderValue};
    use tower_http::cors::CorsLayer;

    // Les origines de l'application de bureau figurent dans le défaut, et pas seulement dans la
    // documentation : elles sont fixes — le système d'exploitation les impose, elles ne dépendent
    // d'aucun déploiement — et les oublier produit un « Failed to fetch » que le navigateur émet
    // avant d'envoyer quoi que ce soit, donc sans rien laisser dans les journaux du serveur.
    //
    // `tauri://localhost` sur Linux et macOS, `http://tauri.localhost` sur Windows et Android.
    let origins: Vec<HeaderValue> = std::env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| {
            "http://127.0.0.1:5173,http://localhost:5173,tauri://localhost,http://tauri.localhost"
                .into()
        })
        .split(',')
        .filter_map(|origin| origin.trim().parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        // Tout en-tête que le client envoie doit figurer ici, sinon le navigateur bloque la
        // requête **avant** qu'elle ne parte : le serveur ne voit rien, et le client ne reçoit
        // qu'un « Failed to fetch » qui ne désigne pas la cause. Les tests d'intégration ne
        // passent pas par le préflight et ne peuvent donc pas attraper l'oubli.
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("x-device-id"),
            HeaderName::from_static("x-timestamp"),
            HeaderName::from_static("x-signature"),
            // Dépôt anonyme (sealed sender), utilisé aussi par les signaux éphémères.
            HeaderName::from_static("x-group-nonce"),
            HeaderName::from_static("x-group-mac"),
        ])
}

pub fn app(pool: PgPool) -> axum::Router {
    use tower_http::limit::RequestBodyLimitLayer;
    use tower_http::trace::TraceLayer;

    // Les KeyPackages et les enveloppes MLS sont petits : un plafond serré empêche qu'une
    // requête unique épuise la mémoire du serveur. Les pièces jointes ont leur propre
    // plafond, nettement plus haut, appliqué à leurs seules routes.
    let state = AppState { pool: pool.clone(), hub: stream::Hub::new() };

    // Branche le hub sur Postgres, ce qui permet de faire tourner plusieurs instances sans que
    // leurs clients cessent de se voir. Détache des tâches : cette fonction doit donc être
    // appelée depuis un runtime tokio.
    state.hub.attach(pool.clone());

    let messages = routes::router(state).layer(RequestBodyLimitLayer::new(1024 * 1024));
    let attachments =
        routes::attachment_router(pool).layer(RequestBodyLimitLayer::new(MAX_ATTACHMENT_BYTES));

    messages
        .merge(attachments)
        .layer(cors_layer())
        .layer(TraceLayer::new_for_http())
}
