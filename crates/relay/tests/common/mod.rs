//! Shared harness: boot the dumb relay on an ephemeral port. No database, no
//! issuer server — the relay only transports opaque OID4VP messages, so these
//! tests always run (unlike the issuer's DB-backed integration tests).

use relay::{RelayState, router};
use serde_json::{Value, json};
use ssi_core::dcql::DcqlQuery;
use ssi_core::oid4vp::{self, VerificationReport};
use ssi_core::resolve::MapFetcher;
use ssi_core::trust::TrustStore;
use ssi_core::wallet_sim::{self, StoredCredential};

pub struct TestRelay {
    pub base: String,
}

pub async fn spawn() -> TestRelay {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let state = RelayState::new(base.clone());
    let app = router(state, None);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    TestRelay { base }
}

/// Run the full OID4VP relay round-trip (verifier ⇄ relay ⇄ simulated wallet) and
/// return the verifier's report. `#[allow(dead_code)]` because not every test file
/// that includes this module uses it (e.g. `walkthrough.rs` drives the steps inline).
#[allow(dead_code)]
pub async fn round_trip(
    base: &str,
    dcql: &DcqlQuery,
    wallet: &[StoredCredential],
    fetcher: &MapFetcher,
    trust: &TrustStore,
) -> Result<VerificationReport, String> {
    let http = reqwest::Client::new();

    let session: Value = http
        .post(format!("{base}/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_uri = session["request_uri"].as_str().unwrap();
    let response_uri = session["response_uri"].as_str().unwrap();

    // Verifier signs the request and (by-reference / compact-QR mode) uploads it to
    // the relay; the QR would carry client_id + request_uri.
    let (nonce, state) = oid4vp::fresh_request_ids();
    let signed = oid4vp::build_signed_request(dcql, &nonce, &state, response_uri);
    http.put(request_uri)
        .json(&json!({ "request": signed.request_jwt }))
        .send()
        .await
        .unwrap();

    // Wallet: fetch the signed request from the relay, verify the JAR against the QR
    // client_id, build the encrypted response.
    let fetched: Value = http.get(request_uri).send().await.unwrap().json().await.unwrap();
    let request_jwt = fetched["request"].as_str().unwrap();
    let request = oid4vp::verify_request(request_jwt, &signed.client_id).map_err(|e| e.to_string())?;
    let response_body =
        wallet_sim::create_response(&request, wallet).map_err(|e| e.to_string())?;

    http.post(response_uri).json(&response_body).send().await.unwrap();

    // Verifier: poll the relay, decrypt the JWE, validate the plaintext token.
    let response: Value = http.get(response_uri).send().await.unwrap().json().await.unwrap();
    let vp_token =
        oid4vp::decrypt_response(&response, &signed.enc_private_jwk).map_err(|e| e.to_string())?;
    Ok(oid4vp::validate_vp_token(&request, &vp_token, fetcher, trust))
}
