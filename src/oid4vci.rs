//! OpenID for Verifiable Credential Issuance (OID4VCI 1.0) endpoints.
//! A thin, hand-rolled implementation.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::response::Redirect;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::crypto::{self, random_b64url};
use crate::error::{AppError, AppResult};
use crate::identity::IssuerIdentity;
use crate::state::AppState;
use crate::{db, diploma, handlers};

// ---------------------------------------------------------------------------
// Metadata (`/.well-known/*`)
// ---------------------------------------------------------------------------

/// Credential Issuer Metadata (`/.well-known/openid-credential-issuer`).
pub fn issuer_metadata(config: &AppConfig) -> Value {
    let issuer = config.issuer();
    json!({
        "credential_issuer": issuer,
        "credential_endpoint": format!("{issuer}/credential"),
        "nonce_endpoint": format!("{issuer}/nonce"),
        "authorization_servers": [issuer],
        "credential_configurations_supported": {
            diploma::CREDENTIAL_CONFIG_ID: {
                "format": "dc+sd-jwt",
                "vct": diploma::VCT,
                "scope": diploma::CREDENTIAL_CONFIG_ID,
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": { "proof_signing_alg_values_supported": ["ES256", "EdDSA"] }
                },
                "display": [{ "name": "University Diploma", "locale": "en-US" }]
            }
        }
    })
}

/// Build the OID4VCI §11.2.3 `signed_metadata` JWT for the Credential Issuer
/// Metadata document. Per HAIP §4.1 (VCI-8), this lets a Wallet authenticate the
/// Issuer beyond TLS: the metadata parameters are signed with the issuer's
/// `CertIdentity` (ES256 + the `x5c` chain header — exactly the same signing seam
/// used for SD-JWT VCs and the status-list JWT), so the Wallet can resolve the
/// signing key from `x5c`, validate the chain to a trust anchor (leaf-not-CA, no
/// self-signed cert in `x5c`), and bind the document to this issuer.
///
/// The payload carries all the plain metadata parameters as claims plus the
/// registered JWT claims §11.2.3 requires: `iss` (bound to the leaf certificate,
/// like every other JWS this issuer mints), `sub` = the Credential Issuer
/// Identifier (`credential_issuer`), and `iat`.
pub fn signed_metadata_jwt(identity: &dyn IssuerIdentity, metadata: &Value) -> String {
    let header = json!({ "alg": "ES256", "typ": "JWT" });
    let mut payload = metadata.clone();
    let obj = payload
        .as_object_mut()
        .expect("credential issuer metadata is a JSON object");
    let credential_issuer = obj.get("credential_issuer").cloned().unwrap_or(Value::Null);
    obj.insert("iss".into(), json!(identity.iss()));
    obj.insert("sub".into(), credential_issuer);
    obj.insert("iat".into(), json!(chrono::Utc::now().timestamp()));
    identity.sign(header, payload)
}

/// Authorization Server Metadata (`/.well-known/oauth-authorization-server`).
pub fn as_metadata(config: &AppConfig) -> Value {
    let issuer = config.issuer();
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        // `nonce_endpoint` is Credential Issuer metadata, not AS metadata, so it
        // lives only in `issuer_metadata`.
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"]
    })
}

// ---------------------------------------------------------------------------
// Credential Offer
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct OfferRequest {
    /// Required for the `pre_authorized` grant.
    pub student_number: Option<String>,
    /// `pre_authorized` (default) or `authorization_code`.
    pub grant: Option<String>,
}

/// `POST /credential-offer` — admin-only. Mints a Credential Offer.
pub async fn create_offer(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<OfferRequest>,
) -> AppResult<Json<Value>> {
    handlers::require_admin(&headers, &st.config)?;

    let grant = req.grant.as_deref().unwrap_or("pre_authorized");
    let grants = match grant {
        "pre_authorized" => {
            let number = req
                .student_number
                .ok_or_else(|| AppError::BadRequest("student_number required".into()))?;
            let student = db::student_by_number(&st.db, &number)
                .await?
                .ok_or_else(|| AppError::BadRequest("unknown student_number".into()))?;
            let code = random_b64url(24);
            db::insert_pre_auth_code(&st.db, &code, student.id, diploma::CREDENTIAL_CONFIG_ID)
                .await?;
            json!({
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": code
                }
            })
        }
        "authorization_code" => json!({ "authorization_code": {} }),
        other => return Err(AppError::BadRequest(format!("unsupported grant: {other}"))),
    };

    let offer_id = random_b64url(12);
    let offer = json!({
        "credential_issuer": st.config.issuer(),
        "credential_configuration_ids": [diploma::CREDENTIAL_CONFIG_ID],
        "grants": grants,
    });
    db::insert_credential_offer(&st.db, &offer_id, &offer).await?;

    let offer_uri = format!("{}/credential-offer/{}", st.config.issuer(), offer_id);
    Ok(Json(json!({
        "offer_id": offer_id,
        "credential_offer": offer,
        "credential_offer_uri": offer_uri,
        "openid_link": format!(
            "openid-credential-offer://?credential_offer_uri={}",
            pct_encode(&offer_uri)
        ),
    })))
}

/// `GET /credential-offer/{id}` — wallet fetches the offer object.
pub async fn get_offer(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let offer = db::get_credential_offer(&st.db, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("credential offer not found".into()))?;
    Ok(Json(offer))
}

// ---------------------------------------------------------------------------
// Authorization endpoint (auth-code flow)
// ---------------------------------------------------------------------------

/// `GET /authorize` — stores a pending session and redirects to the mock IdP.
pub async fn authorize(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> AppResult<Redirect> {
    let redirect_uri = q
        .get("redirect_uri")
        .ok_or_else(|| AppError::BadRequest("missing redirect_uri".into()))?;
    let code_challenge = q.get("code_challenge").cloned().unwrap_or_default();
    let code_challenge_method = q
        .get("code_challenge_method")
        .cloned()
        .unwrap_or_else(|| "plain".into());
    // HAIP §4.2/§4.3 (VCI-11/VCI-13): the wallet identifies the credential type via
    // the OAuth `scope` parameter; the scope value equals the credential
    // configuration id advertised in Credential Issuer Metadata. Prefer `scope`,
    // falling back to `authorization_details` for compatibility.
    let config_id = scope_to_config_id(q.get("scope"))
        .unwrap_or_else(|| extract_config_id(q.get("authorization_details")));

    let session_id = random_b64url(16);
    db::insert_auth_session(
        &st.db,
        &session_id,
        redirect_uri,
        &code_challenge,
        &code_challenge_method,
        &config_id,
        q.get("state").map(String::as_str),
    )
    .await?;

    Ok(Redirect::to(&format!("/mock-idp/login?session={session_id}")))
}

/// Pull `credential_configuration_id` out of an `authorization_details` array.
fn extract_config_id(authorization_details: Option<&String>) -> String {
    authorization_details
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| {
            v.get(0)
                .and_then(|d| d.get("credential_configuration_id"))
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| diploma::CREDENTIAL_CONFIG_ID.to_string())
}

/// Map an OAuth `scope` value to a `credential_configuration_id`. The scope value
/// equals the config id advertised in Credential Issuer Metadata (`"scope"`), so a
/// space-delimited scope is scanned for the known config id. Returns `None` when no
/// `scope` is present or none of its values match.
fn scope_to_config_id(scope: Option<&String>) -> Option<String> {
    scope?
        .split_whitespace()
        .find(|s| *s == diploma::CREDENTIAL_CONFIG_ID)
        .map(String::from)
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

/// `POST /token` — supports `authorization_code` and pre-authorized-code grants.
pub async fn token(
    State(st): State<AppState>,
    Form(f): Form<HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let grant = f.get("grant_type").map(String::as_str).unwrap_or_default();
    let (student_id, config_id) = match grant {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
            let code = f
                .get("pre-authorized_code")
                .ok_or_else(|| AppError::BadRequest("missing pre-authorized_code".into()))?;
            db::take_pre_auth_code(&st.db, code).await?.ok_or_else(|| {
                AppError::InvalidGrant("invalid or expired pre-authorized_code".into())
            })?
        }
        "authorization_code" => {
            let code = f
                .get("code")
                .ok_or_else(|| AppError::BadRequest("missing code".into()))?;
            let consumed = db::take_authorization_code(&st.db, code)
                .await?
                .ok_or_else(|| AppError::InvalidGrant("invalid or expired code".into()))?;
            let verifier = f.get("code_verifier").map(String::as_str).unwrap_or_default();
            verify_pkce(verifier, &consumed.code_challenge)?;
            (consumed.student_id, consumed.credential_config_id)
        }
        other => {
            return Err(AppError::UnsupportedGrantType(format!(
                "unsupported grant_type: {other}"
            )));
        }
    };

    let access_token = random_b64url(32);
    db::insert_access_token(&st.db, &access_token, student_id, &config_id).await?;
    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600
    })))
}

/// PKCE S256 check. An empty challenge means no PKCE was requested.
fn verify_pkce(verifier: &str, challenge: &str) -> AppResult<()> {
    if challenge.is_empty() {
        return Ok(());
    }
    let computed = crypto::b64url(&crypto::sha256(verifier.as_bytes()));
    if computed == challenge {
        Ok(())
    } else {
        Err(AppError::InvalidGrant("PKCE verification failed".into()))
    }
}

// ---------------------------------------------------------------------------
// Nonce endpoint
// ---------------------------------------------------------------------------

/// `POST /nonce` — issues a fresh `c_nonce` for credential-request proofs.
pub async fn nonce(State(st): State<AppState>) -> AppResult<Json<Value>> {
    let nonce = random_b64url(24);
    db::insert_nonce(&st.db, &nonce).await?;
    Ok(Json(json!({ "c_nonce": nonce, "c_nonce_expires_in": 300 })))
}

// ---------------------------------------------------------------------------
// Credential endpoint
// ---------------------------------------------------------------------------

/// `POST /credential` — issues the SD-JWT VC bound to the wallet's proof key.
pub async fn credential(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let token = bearer_token(&headers)?;
    let (student_id, config_id) = db::get_access_token(&st.db, &token)
        .await?
        .ok_or(AppError::Unauthorized)?;

    validate_credential_selector(&body, &config_id)?;
    let proof_jwt = extract_single_proof(&body)?;
    let holder_jwk = validate_proof(proof_jwt, &st).await?;

    let student = db::student_by_id(&st.db, student_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("unknown student".into()))?;

    let vct = diploma::VCT;
    let index = db::allocate_status_index(&st.db, diploma::STATUS_LIST_ID, vct).await?;
    let status_uri = format!(
        "{}/status-lists/{}",
        st.config.issuer(),
        diploma::STATUS_LIST_ID
    );
    let jti = Uuid::new_v4();
    let claims = diploma::build_claims(
        &student,
        st.identity.iss(),
        vct,
        &jti.to_string(),
        &holder_jwk,
        &status_uri,
        index,
    );
    db::insert_issued_credential(
        &st.db,
        jti,
        student.id,
        vct,
        diploma::STATUS_LIST_ID,
        index,
        &claims,
    )
    .await?;

    let sd_jwt = diploma::issue(st.identity.as_ref(), claims);
    // OID4VCI 1.0 Credential Response: a `credentials` array, one object per
    // issued instance. We never return `credential_identifiers` from the token
    // endpoint, so this is always a single-element array.
    Ok(Json(json!({ "credentials": [{ "credential": sd_jwt }] })))
}

/// Validate the Credential Request's credential selector. Since the token
/// response never returns `credential_identifiers`, the request MUST carry a
/// `credential_configuration_id` (matching the one the token was issued for)
/// and MUST NOT carry a `credential_identifier`.
fn validate_credential_selector(body: &Value, token_config_id: &str) -> AppResult<()> {
    if body.get("credential_identifier").is_some() {
        return Err(AppError::InvalidCredentialRequest(
            "credential_identifier is not supported; use credential_configuration_id".into(),
        ));
    }
    let requested = body
        .get("credential_configuration_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::InvalidCredentialRequest("missing credential_configuration_id".into())
        })?;
    if requested != diploma::CREDENTIAL_CONFIG_ID || requested != token_config_id {
        return Err(AppError::UnknownCredentialConfiguration(format!(
            "unknown or unauthorized credential_configuration_id: {requested}"
        )));
    }
    Ok(())
}

/// Pull the single key proof out of the 1.0 `proofs` object. We do not advertise
/// `batch_credential_issuance`, so exactly one `jwt` proof is required.
fn extract_single_proof(body: &Value) -> AppResult<&str> {
    let jwts = body
        .pointer("/proofs/jwt")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::InvalidProof("missing proofs.jwt array".into()))?;
    match jwts.as_slice() {
        [one] => one
            .as_str()
            .ok_or_else(|| AppError::InvalidProof("proofs.jwt entry must be a string".into())),
        [] => Err(AppError::InvalidProof("proofs.jwt must be non-empty".into())),
        _ => Err(AppError::InvalidProof(
            "batch issuance is not supported; send exactly one proof".into(),
        )),
    }
}

/// Validate a wallet proof JWT and return the holder's public JWK.
async fn validate_proof(jwt: &str, st: &AppState) -> AppResult<Value> {
    let (header, payload) = crypto::decode_jws_unverified(jwt)
        .map_err(|e| AppError::InvalidProof(format!("malformed proof jwt: {e}")))?;

    if header.get("typ").and_then(Value::as_str) != Some("openid4vci-proof+jwt") {
        return Err(AppError::InvalidProof(
            "proof typ must be openid4vci-proof+jwt".into(),
        ));
    }
    let jwk = header
        .get("jwk")
        .cloned()
        .ok_or_else(|| AppError::InvalidProof("proof header missing jwk".into()))?;
    // Verify against the embedded JWK, dispatching on the proof's `alg` (ES256 or
    // EdDSA) — see `proof_signing_alg_values_supported` above.
    crypto::verify_jws_with_jwk(jwt, &jwk)
        .map_err(|e| AppError::InvalidProof(format!("proof signature invalid: {e}")))?;

    if payload.get("aud").and_then(Value::as_str) != Some(st.config.issuer()) {
        return Err(AppError::InvalidProof("proof aud mismatch".into()));
    }
    // A proof lacking a `c_nonce` is `invalid_proof`; a stale/unknown nonce is
    // `invalid_nonce`, signalling the wallet to fetch a fresh one and retry.
    let nonce = payload
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::InvalidProof("proof missing nonce".into()))?;
    if !db::consume_nonce(&st.db, nonce).await? {
        return Err(AppError::InvalidNonce("proof nonce invalid or expired".into()));
    }
    Ok(jwk)
}

/// Extract a `Bearer` token from the `Authorization` header.
fn bearer_token(headers: &HeaderMap) -> AppResult<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string)
        .ok_or(AppError::Unauthorized)
}

/// Percent-encode a string for use in a query parameter.
fn pct_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod signed_metadata_tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::identity::CertIdentity;
    use ssi_core::x509;

    /// The `signed_metadata` JWT (OID4VCI §11.2.3 / HAIP §4.1) signs the issuer
    /// metadata with the issuer's ES256 leaf key, embeds the `x5c` chain, binds its
    /// `iss` to the leaf certificate, validates up to the trusted ICP-Brasil root,
    /// and carries the Credential Issuer Identifier as `sub` + `credential_issuer`.
    #[test]
    fn signed_metadata_is_verifiable_and_binds_the_issuer() {
        let config = AppConfig {
            bind_addr: "127.0.0.1:8080".into(),
            issuer_url: "https://diploma.ufsc.br".into(),
            database_url: String::new(),
            admin_user: "admin".into(),
            admin_password: "admin".into(),
        };
        let identity = CertIdentity::demo().unwrap();
        let metadata = issuer_metadata(&config);

        let jws = signed_metadata_jwt(&identity, &metadata);

        // Header: ES256 + an x5c chain resolving to the leaf signing key.
        let (header, payload) = crypto::decode_jws_unverified(&jws).unwrap();
        assert_eq!(header["alg"], "ES256");
        let chain = x509::parse_x5c(&header["x5c"]).unwrap();

        // The chain validates to a default (mock ICP-Brasil) trust anchor and the
        // JWS signature verifies under the leaf key.
        let store = ssi_core::trust::TrustStore::with_defaults();
        x509::validate_chain(&chain, store.anchor_certs(), chrono::Utc::now().timestamp())
            .unwrap();
        crypto::verify_jws_with_jwk(&jws, &chain[0].public_jwk().unwrap()).unwrap();

        // `iss` binds to the leaf certificate; `sub`/`credential_issuer` authenticate
        // the Credential Issuer Identifier the wallet is talking to.
        assert_eq!(payload["iss"], identity.iss());
        x509::iss_matches_leaf(payload["iss"].as_str().unwrap(), &chain[0]).unwrap();
        assert_eq!(payload["sub"], json!(config.issuer()));
        assert_eq!(payload["credential_issuer"], json!(config.issuer()));
        // The signed document still carries the plain metadata parameters.
        assert_eq!(
            payload["credential_endpoint"],
            metadata["credential_endpoint"]
        );
    }
}
