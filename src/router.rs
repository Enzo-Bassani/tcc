//! Axum router wiring every endpoint to its handler.

use axum::Router;
use axum::http::Method;
use axum::routing::{get, post};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::AppState;
use crate::{handlers, oid4vci, oidc_mock};

pub fn build(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        // Issuer signing key (the verifier resolves the key from the credential's
        // x5c chain; this endpoint is informational).
        .route("/.well-known/jwks.json", get(handlers::jwks))
        // OID4VCI / OAuth metadata
        .route(
            "/.well-known/openid-credential-issuer",
            get(handlers::issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(handlers::as_metadata),
        )
        // No `vct`-resolution endpoint: the diploma `vct` is a non-dereferenceable
        // URN (see `diploma::VCT`) and SD-JWT VC Type Metadata resolution is optional
        // (RFC 9901). The Type Metadata ships as a static artifact instead
        // (`type-metadata/UniversityDiploma-v1.json`, `cargo run -- type-metadata`).
        // OID4VCI issuance
        .route("/credential-offer", post(oid4vci::create_offer))
        .route("/credential-offer/{id}", get(oid4vci::get_offer))
        .route("/authorize", get(oid4vci::authorize))
        .route("/token", post(oid4vci::token))
        .route("/nonce", post(oid4vci::nonce))
        .route("/credential", post(oid4vci::credential))
        // Revocation
        .route("/status-lists/{id}", get(handlers::status_list))
        .route(
            "/admin/credentials/{jti}/revoke",
            post(handlers::admin_revoke),
        )
        // Mock IdP
        .route(
            "/mock-idp/login",
            get(oidc_mock::login_form).post(oidc_mock::login_submit),
        )
        // The verifier validates entirely in the browser, so it fetches the
        // issuer's one public document it needs — the **status list** — cross-origin
        // (the `vct` is a URN, so no type metadata is fetched). That document is
        // public, unauthenticated and read-only, and the universal verifier can be
        // served from any origin, so `allow_origin(Any)` scoped to GET is the correct,
        // intentional policy. The wallet's POST issuance endpoints are native HTTP
        // and need no CORS.
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET]),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
