//! Shared integration-test harness: boots the full app against a real Postgres.
//!
//! Requires `TEST_DATABASE_URL` to be set; otherwise `spawn()` returns `None`
//! and the calling test skips itself.

use std::sync::Arc;

use issuer_backend::config::AppConfig;
use issuer_backend::holder::HolderKey;
use issuer_backend::identity::CertIdentity;
use issuer_backend::{AppState, IssuerIdentity, db, router};
use serde_json::json;

pub struct TestApp {
    pub base: String,
    #[allow(dead_code)]
    pub db: sqlx::PgPool,
}

/// Build a wallet proof-of-possession JWT with caller-chosen `typ` / `audience` /
/// `nonce` — the general form, used by the negative tests to drive each proof-
/// validation branch (`nonce` is optional, to exercise the missing-nonce case).
/// The holder defaults to ES256; [`HolderKey::sign_jws`] stamps the JWS `alg`.
#[allow(dead_code)]
pub fn proof_with(holder: &HolderKey, typ: &str, audience: &str, nonce: Option<&str>) -> String {
    let header = json!({ "typ": typ, "jwk": holder.public_jwk() });
    let mut payload = json!({ "aud": audience, "iat": chrono::Utc::now().timestamp() });
    if let Some(n) = nonce {
        payload["nonce"] = json!(n);
    }
    holder.sign_jws(&header, &payload)
}

/// The standard, well-formed wallet proof bound to `audience` and `nonce`
/// (OID4VCI `openid4vci-proof+jwt`).
#[allow(dead_code)]
pub fn build_proof(holder: &HolderKey, audience: &str, nonce: &str) -> String {
    proof_with(holder, "openid4vci-proof+jwt", audience, Some(nonce))
}

pub async fn spawn() -> Option<TestApp> {
    let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("SKIP: set TEST_DATABASE_URL to run integration tests");
        return None;
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // `issuer_url` is purely the deployment / network base the test client dials and
    // OID4VCI metadata URLs derive from — kept as the raw 127.0.0.1 loopback, NOT
    // `localhost`: on dual-stack hosts `localhost` resolves to `::1` (IPv6) first,
    // but the listener above binds 127.0.0.1 (IPv4) only, so `localhost` would point
    // the client at an unbound address. The issued credential's
    // `iss` is decoupled from this (the cert-bound `CertIdentity::DEMO_ISS`), so it
    // binds to the leaf SAN at verification time regardless of this address.
    let issuer_url = format!("http://{addr}");

    let config = AppConfig {
        bind_addr: addr.to_string(),
        issuer_url: issuer_url.clone(),
        database_url: database_url.clone(),
        admin_user: "admin".into(),
        admin_password: "admin".into(),
    };

    // Prototype issuer signs with the bundled mock UFSC leaf (ES256 + x5c). Its
    // `iss` is the fixed cert-bound identity, independent of `issuer_url` above.
    let identity: Arc<dyn IssuerIdentity> = Arc::new(CertIdentity::demo().unwrap());

    let pool = db::connect(&database_url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    db::seed_students(&pool).await.unwrap();

    let state = AppState {
        db: pool.clone(),
        config: Arc::new(config),
        identity,
    };
    let app = router::build(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Some(TestApp {
        base: issuer_url,
        db: pool,
    })
}
