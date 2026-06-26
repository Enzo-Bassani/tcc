//! HTTP handlers for `.well-known` metadata, the DID document, the status list,
//! and admin operations.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::{db, oid4vci, status};

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// `GET /.well-known/jwks.json` — the issuer's public signing key (EC P-256 /
/// ES256). Informational: verifiers resolve the signing key from the credential's
/// `x5c` certificate chain, not from here.
pub async fn jwks(State(st): State<AppState>) -> Json<Value> {
    let mut jwk = st.identity.public_jwk();
    if let Some(obj) = jwk.as_object_mut() {
        obj.insert("use".into(), json!("sig"));
        obj.insert("alg".into(), json!("ES256"));
    }
    Json(json!({ "keys": [jwk] }))
}

pub async fn issuer_metadata(State(st): State<AppState>) -> Json<Value> {
    let mut metadata = oid4vci::issuer_metadata(&st.config);
    // OID4VCI §11.2.3 / HAIP §4.1: also serve the metadata as a `signed_metadata`
    // JWT (ES256 + `x5c`), so a Wallet can authenticate the issuer beyond TLS.
    let signed = oid4vci::signed_metadata_jwt(st.identity.as_ref(), &metadata);
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("signed_metadata".into(), json!(signed));
    }
    Json(metadata)
}

pub async fn as_metadata(State(st): State<AppState>) -> Json<Value> {
    Json(oid4vci::as_metadata(&st.config))
}

/// `GET /status-lists/{id}` — the signed Token Status List JWT.
pub async fn status_list(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let bits = db::status_list_bits(&st.db, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("status list not found".into()))?;
    let bitstring = status::BitString::from_bytes(bits);
    let jwt = status::build_status_list_jwt(
        st.identity.as_ref(),
        st.config.issuer(),
        &id,
        &bitstring,
    )?;
    Ok((
        [(header::CONTENT_TYPE, "application/statuslist+jwt")],
        jwt,
    )
        .into_response())
}

/// `POST /admin/credentials/{jti}/revoke` — admin-only revocation.
pub async fn admin_revoke(
    State(st): State<AppState>,
    Path(jti): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&headers, &st.config)?;
    let jti = Uuid::parse_str(&jti)
        .map_err(|_| AppError::BadRequest("invalid credential id (jti)".into()))?;
    let cred = db::issued_credential_by_jti(&st.db, jti)
        .await?
        .ok_or_else(|| AppError::NotFound("credential not found".into()))?;
    db::revoke_status_index(&st.db, &cred.status_list_id, cred.status_index).await?;
    db::mark_revoked(&st.db, jti).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// HTTP Basic auth check for admin endpoints.
pub fn require_admin(headers: &HeaderMap, config: &AppConfig) -> AppResult<()> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let encoded = value.strip_prefix("Basic ").ok_or(AppError::Unauthorized)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
        .and_then(|d| String::from_utf8(d).ok())
        .ok_or(AppError::Unauthorized)?;
    let (user, pass) = decoded.split_once(':').ok_or(AppError::Unauthorized)?;
    if user == config.admin_user && pass == config.admin_password {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}
