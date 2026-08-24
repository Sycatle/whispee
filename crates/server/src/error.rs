use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("malformed request: {0}")]
    BadRequest(&'static str),

    #[error("authentication refused")]
    Unauthorized,

    #[error("access denied")]
    Forbidden,

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(&'static str),

    /// The thing existed and deliberately does not any more.
    ///
    /// Distinct from `NotFound`, and the distinction is the point: a handle nobody ever took may
    /// still be claimed, a handle that was given up never will be. Answering 404 to a tombstone
    /// would tell a client to try again later, which is not true and never becomes true.
    #[error("gone")]
    Gone,

    /// The caller did nothing forbidden; it only did too much of it.
    ///
    /// Distinct from `Forbidden` on purpose: an honest client that gets a 429 retries later,
    /// where a 403 would make it conclude it is banned and give up.
    #[error("too many requests")]
    TooManyRequests,

    /// The caller is within its rate, and out of room.
    ///
    /// Distinct from [`ApiError::TooManyRequests`] on purpose, and the distinction is the whole
    /// point: a 429 tells an honest client to come back later, which is true of a rate limit and
    /// never becomes true of a ceiling. A client told to retry a full vault retries forever, and
    /// its user believes their history is being archived while nothing is.
    #[error("storage quota reached")]
    InsufficientStorage,

    /// The deployment does not offer this, and no retry will change that.
    ///
    /// Distinct from `NotFound` for the reason `Gone` is: a 404 invites a client to look again
    /// somewhere else, where this says the feature is absent from this server. A deployment
    /// running no media server answers it to every call, and stays a working messenger.
    #[error("not configured")]
    Unavailable,

    #[error("storage error")]
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
            ApiError::Gone => StatusCode::GONE,
            ApiError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ApiError::InsufficientStorage => StatusCode::INSUFFICIENT_STORAGE,
            ApiError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // Database errors are logged but never returned to the client: an SQL message leaks the
        // schema, and sometimes the data. The other variants are worded to be safe to expose.
        let body = match &self {
            ApiError::Database(err) => {
                tracing::error!(error = %err, "database error");
                "internal error".to_owned()
            }
            other => other.to_string(),
        };

        // Deliberately indistinguishable between "invalid authentication" and "unknown device":
        // telling them apart turns the endpoint into an oracle for enumerating registered
        // devices.
        (status, body).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// 507, and above all not 429.
    ///
    /// The distinction is the one `Gone` already draws against `NotFound`: 429 means *retry
    /// later*, which is true of a rate limit and false of a full vault. A client told to retry a
    /// ceiling retries forever.
    #[test]
    fn a_full_account_is_not_a_client_going_too_fast() {
        let full = ApiError::InsufficientStorage.into_response().status();
        let fast = ApiError::TooManyRequests.into_response().status();

        assert_eq!(full.as_u16(), 507);
        assert_ne!(full, fast);
    }
}
