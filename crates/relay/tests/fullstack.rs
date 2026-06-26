//! Full-stack end-to-end: a real diploma issued over the **OID4VCI HTTP wire**
//! (issuer server + Postgres) is then presented over the **OID4VP transport**
//! (live relay) and verified.
//!
//! This is the cradle-to-grave seam the other tests leave open:
//!   * `tests/e2e.rs` (issuer crate) drives OID4VCI over HTTP but stops at checking
//!     the SD-JWT signature — it never presents the credential.
//!   * `e2e.rs::issuer_interop_real_diploma_verifies` chains issuance→presentation
//!     but mints via the issuer *library* (`diploma::issue`), with no DB, no HTTP,
//!     and validates the VP Token in-process (no relay transport).
//!
//! Here both wire protocols run in one test: the credential the HTTP `/credential`
//! endpoint actually emits is the one that travels the relay and faces the verifier.
//! The simulated holder (`wallet_sim`) plays the wallet — the Android app is not
//! needed to exercise the protocol surface.
//!
//! Requires `TEST_DATABASE_URL`; skips cleanly otherwise (so it is a no-op under the
//! DB-less `cargo test --workspace`, and runs under `just test-db`).

mod common;

use std::sync::Arc;

use common::{round_trip, spawn as spawn_relay};
use serde_json::{Value, json};

use issuer_backend::config::AppConfig;
use issuer_backend::diploma;
use issuer_backend::identity::CertIdentity;
use issuer_backend::{AppState, IssuerIdentity, db, router};

use ssi_core::crypto;
use ssi_core::dcql::DcqlQuery;
use ssi_core::holder::HolderKey;
use ssi_core::oid4vp::Check;
use ssi_core::resolve::MapFetcher;
use ssi_core::sd_jwt;
use ssi_core::testkit;
use ssi_core::wallet_sim::StoredCredential;

/// Boot the real issuer HTTP service against Postgres on an ephemeral port.
/// Returns its base URL, or `None` (skip) when `TEST_DATABASE_URL` is unset.
/// Mirrors the issuer crate's `tests/common::spawn` using only its public API.
async fn spawn_issuer() -> Option<String> {
    let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("SKIP: set TEST_DATABASE_URL to run the full-stack e2e");
        return None;
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer_url = format!("http://{addr}");

    let config = AppConfig {
        bind_addr: addr.to_string(),
        issuer_url: issuer_url.clone(),
        database_url: database_url.clone(),
        admin_user: "admin".into(),
        admin_password: "admin".into(),
    };
    let identity: Arc<dyn IssuerIdentity> = Arc::new(CertIdentity::demo().unwrap());

    let pool = db::connect(&database_url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    db::seed_students(&pool).await.unwrap();

    let state = AppState {
        db: pool,
        config: Arc::new(config),
        identity,
    };
    let app = router::build(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Some(issuer_url)
}

/// Build a wallet proof-of-possession JWT bound to `audience` + `nonce` (OID4VCI).
fn build_proof(holder: &HolderKey, audience: &str, nonce: &str) -> String {
    let header = json!({
        "typ": "openid4vci-proof+jwt",
        "jwk": holder.public_jwk(),
    });
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload = json!({
        "aud": audience,
        "iat": iat,
        "nonce": nonce,
    });
    holder.sign_jws(&header, &payload)
}

/// Drive the full pre-authorized OID4VCI flow over HTTP and return the issued
/// SD-JWT together with the holder key it is bound to.
async fn issue_over_http(
    http: &reqwest::Client,
    issuer: &str,
    student_number: &str,
) -> (String, HolderKey) {
    // 1. Admin mints a pre-authorized offer.
    let offer: Value = http
        .post(format!("{issuer}/credential-offer"))
        .basic_auth("admin", Some("admin"))
        .json(&json!({ "student_number": student_number, "grant": "pre_authorized" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pre_auth_code = offer["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .expect("offer carries a pre-authorized code")
        .to_string();

    // 2. Redeem it for an access token.
    let token: Value = http
        .post(format!("{issuer}/token"))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            ),
            ("pre-authorized_code", &pre_auth_code),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = token["access_token"].as_str().unwrap().to_string();

    // 3. Fetch a nonce and build the holder proof.
    let nonce: Value = http
        .post(format!("{issuer}/nonce"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let holder = HolderKey::generate();
    let proof = build_proof(&holder, issuer, nonce["c_nonce"].as_str().unwrap());

    // 4. Request the credential.
    let cred: Value = http
        .post(format!("{issuer}/credential"))
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": diploma::CREDENTIAL_CONFIG_ID,
            "proofs": { "jwt": [proof] }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sd_jwt = cred["credentials"][0]["credential"]
        .as_str()
        .expect("credential was issued")
        .to_string();

    (sd_jwt, holder)
}

/// Pull the issuer-signed status list off the HTTP service and map it under the
/// `uri` the credential's `status` claim actually points at. The credential's
/// `iss` is the cert-bound `https://diploma.ufsc.br` (non-routable in tests), so
/// the bytes are fetched from the live `issuer` base and re-keyed — the JWT itself
/// is the real one the issuer serves.
async fn status_fetcher(http: &reqwest::Client, issuer: &str, status_uri: &str) -> MapFetcher {
    let status_jwt = http
        .get(format!("{issuer}/status-lists/{}", diploma::STATUS_LIST_ID))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    MapFetcher::new().with(status_uri.to_string(), status_jwt.into_bytes())
}

/// A DCQL query for the diploma's name + degree title (both selectively disclosed).
fn name_and_degree(vct: &str) -> DcqlQuery {
    serde_json::from_value(json!({
        "credentials": [{
            "id": "diploma",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": [vct] },
            "claims": [
                { "path": ["student", "full_name"] },
                { "path": ["degree", "title"] }
            ]
        }]
    }))
    .unwrap()
}

/// Decode the issued SD-JWT (unverified) into its full reconstructed claim set
/// plus the issuer payload, so the test can learn the real values to assert on.
fn explain(sd_jwt: &str) -> (Value, Value) {
    let (issuer_jwt, disclosures) = sd_jwt::split(sd_jwt);
    let (_h, payload) = crypto::decode_jws_unverified(&issuer_jwt).unwrap();
    let full = sd_jwt::reconstruct_claims(&payload, &disclosures).unwrap();
    (payload, full)
}

/// Happy path: real HTTP issuance → relay transport → verifier accepts, with the
/// right issuer trust, holder binding, and data minimization.
#[tokio::test]
async fn issued_diploma_presents_and_verifies_over_the_relay() {
    let Some(issuer) = spawn_issuer().await else {
        return;
    };
    let relay = spawn_relay().await;
    let http = reqwest::Client::new();

    let (sd_jwt, holder) = issue_over_http(&http, &issuer, "2020000001").await;
    let (payload, full) = explain(&sd_jwt);
    let vct = payload["vct"].as_str().unwrap().to_string();
    let status_uri = payload["status"]["status_list"]["uri"].as_str().unwrap();

    let fetcher = status_fetcher(&http, &issuer, status_uri).await;
    let wallet = vec![StoredCredential { sd_jwt, holder }];
    let dcql = name_and_degree(&vct);

    let report = round_trip(
        &relay.base,
        &dcql,
        &wallet,
        &fetcher,
        &testkit::demo_trust_store(),
    )
    .await
    .unwrap();

    assert!(report.valid, "real issued diploma must verify: {report:?}");
    let c = &report.credentials[0];
    assert!(matches!(c.issuer_signature, Check::Pass));
    assert!(
        matches!(c.trusted_issuer, Check::Pass),
        "x5c chain must anchor to ICP-Brasil: {:?}",
        c.trusted_issuer
    );
    assert!(matches!(c.holder_binding, Check::Pass));
    assert!(matches!(c.revocation, Check::Pass));

    // The disclosed values are exactly what the issuer put in the credential.
    assert_eq!(
        c.disclosed_claims["student"]["full_name"],
        full["student"]["full_name"]
    );
    assert_eq!(c.disclosed_claims["degree"]["title"], full["degree"]["title"]);

    // Data minimization: claims not asked for never left the wallet, even though the
    // credential carries them (e.g. the CPF / national id).
    assert!(
        c.disclosed_claims["student"]["national_id"].is_null(),
        "unrequested national_id must not be disclosed"
    );
    assert!(c.disclosed_claims["gpa"].is_null());
}

/// Revoke the issued credential through the admin API, then present it: the same
/// transport chain must now fail the revocation check.
#[tokio::test]
async fn revoked_diploma_fails_verification_over_the_relay() {
    let Some(issuer) = spawn_issuer().await else {
        return;
    };
    let relay = spawn_relay().await;
    let http = reqwest::Client::new();

    let (sd_jwt, holder) = issue_over_http(&http, &issuer, "2020000002").await;
    let (payload, _full) = explain(&sd_jwt);
    let vct = payload["vct"].as_str().unwrap().to_string();
    let status_uri = payload["status"]["status_list"]["uri"].as_str().unwrap();
    let jti = payload["jti"].as_str().unwrap();

    // Revoke via the admin endpoint.
    let revoke = http
        .post(format!("{issuer}/admin/credentials/{jti}/revoke"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), 204, "revoke should return 204");

    // Re-fetch the (now updated) status list and present.
    let fetcher = status_fetcher(&http, &issuer, status_uri).await;
    let wallet = vec![StoredCredential { sd_jwt, holder }];
    let dcql = name_and_degree(&vct);

    let report = round_trip(
        &relay.base,
        &dcql,
        &wallet,
        &fetcher,
        &testkit::demo_trust_store(),
    )
    .await
    .unwrap();

    assert!(!report.valid, "revoked diploma must not verify");
    let c = &report.credentials[0];
    assert!(
        matches!(c.revocation, Check::Fail(_)),
        "revocation check must fail: {:?}",
        c.revocation
    );
    // The signature and trust chain are still intact — only revocation flips.
    assert!(matches!(c.issuer_signature, Check::Pass));
    assert!(matches!(c.trusted_issuer, Check::Pass));
}
