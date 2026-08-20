use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("requête mal formée : {0}")]
    BadRequest(&'static str),

    #[error("authentification refusée")]
    Unauthorized,

    #[error("accès refusé")]
    Forbidden,

    #[error("introuvable")]
    NotFound,

    #[error("conflit : {0}")]
    Conflict(&'static str),

    #[error("erreur de stockage")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // Les erreurs de base de données sont journalisées mais jamais renvoyées au client :
        // un message SQL divulgue le schéma, et parfois les données. Les autres variantes
        // sont rédigées pour être sûres à exposer.
        let body = match &self {
            ApiError::Database(err) => {
                tracing::error!(error = %err, "erreur de base de données");
                "erreur interne".to_owned()
            }
            other => other.to_string(),
        };

        // Volontairement indistinct entre « authentification invalide » et « appareil
        // inconnu » : distinguer les deux transforme l'endpoint en oracle permettant
        // d'énumérer les appareils enregistrés.
        (status, body).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
