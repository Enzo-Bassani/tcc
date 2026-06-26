//! Unified application error type with an `IntoResponse` mapping to JSON.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Generic OAuth `invalid_request` (malformed/missing protocol parameters).
    #[error("{0}")]
    BadRequest(String),
    /// OAuth token-endpoint `invalid_grant` (bad/expired code, failed PKCE).
    #[error("{0}")]
    InvalidGrant(String),
    /// OAuth token-endpoint `unsupported_grant_type`.
    #[error("{0}")]
    UnsupportedGrantType(String),
    /// OID4VCI credential-endpoint `invalid_credential_request`.
    #[error("{0}")]
    InvalidCredentialRequest(String),
    /// OID4VCI credential-endpoint `unknown_credential_configuration`.
    #[error("{0}")]
    UnknownCredentialConfiguration(String),
    /// OID4VCI credential-endpoint `invalid_proof` (missing/invalid key proof).
    #[error("{0}")]
    InvalidProof(String),
    /// OID4VCI credential-endpoint `invalid_nonce` — the wallet MUST fetch a
    /// fresh `c_nonce` from the Nonce Endpoint and retry.
    #[error("{0}")]
    InvalidNonce(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("{0}")]
    NotFound(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type AppResult<T> = Result<T, AppError>;

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, msg) = match &self {
            AppError::BadRequest(m) => {
                (StatusCode::BAD_REQUEST, "invalid_request", m.clone())
            }
            AppError::InvalidGrant(m) => {
                (StatusCode::BAD_REQUEST, "invalid_grant", m.clone())
            }
            AppError::UnsupportedGrantType(m) => {
                (StatusCode::BAD_REQUEST, "unsupported_grant_type", m.clone())
            }
            AppError::InvalidCredentialRequest(m) => {
                (StatusCode::BAD_REQUEST, "invalid_credential_request", m.clone())
            }
            AppError::UnknownCredentialConfiguration(m) => {
                (StatusCode::BAD_REQUEST, "unknown_credential_configuration", m.clone())
            }
            AppError::InvalidProof(m) => {
                (StatusCode::BAD_REQUEST, "invalid_proof", m.clone())
            }
            AppError::InvalidNonce(m) => {
                (StatusCode::BAD_REQUEST, "invalid_nonce", m.clone())
            }
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "unauthorized".to_string(),
            ),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m.clone()),
            AppError::Internal(e) => {
                tracing::error!("internal error: {e:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "internal error".to_string(),
                )
            }
        };
        (
            status,
            Json(json!({ "error": code, "error_description": msg })),
        )
            .into_response()
    }
}
