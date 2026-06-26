//! Negative-path tests for the OID4VCI/OAuth endpoints — the rejection logic that
//! is the issuer's security boundary. The happy paths live in `e2e.rs`; here every
//! test drives a *failure* and asserts the HTTP status + the OAuth/OID4VCI error
//! code (`{"error": ..., "error_description": ...}`).
//!
//! Run with: `TEST_DATABASE_URL=postgres://issuer:issuer@localhost:5432/issuer_backend cargo test --test negative`

mod common;

use common::{build_proof, proof_with, spawn};
use issuer_backend::diploma::CREDENTIAL_CONFIG_ID;
use issuer_backend::holder::HolderKey;
use issuer_backend::crypto;
use serde_json::{Value, json};

const PRE_AUTH_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// Decode an error response into `(status, error, error_description)`.
async fn problem(resp: reqwest::Response) -> (u16, String, String) {
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    (
        status,
        body["error"].as_str().unwrap_or_default().to_string(),
        body["error_description"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

/// Mint a fresh pre-authorized code for `student`.
async fn pre_auth_code(http: &reqwest::Client, base: &str, student: &str) -> String {
    let offer: Value = http
        .post(format!("{base}/credential-offer"))
        .basic_auth("admin", Some("admin"))
        .json(&json!({ "student_number": student, "grant": "pre_authorized" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    offer["credential_offer"]["grants"][PRE_AUTH_GRANT]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Mint a usable access token via the pre-authorized flow.
async fn access_token(http: &reqwest::Client, base: &str, student: &str) -> String {
    let code = pre_auth_code(http, base, student).await;
    let token: Value = http
        .post(format!("{base}/token"))
        .form(&[("grant_type", PRE_AUTH_GRANT), ("pre-authorized_code", &code)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    token["access_token"].as_str().unwrap().to_string()
}

async fn fresh_nonce(http: &reqwest::Client, base: &str) -> String {
    let n: Value = http
        .post(format!("{base}/nonce"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    n["c_nonce"].as_str().unwrap().to_string()
}

/// POST a credential request with the given bearer token and JSON body.
async fn post_credential(
    http: &reqwest::Client,
    base: &str,
    bearer: Option<&str>,
    body: Value,
) -> reqwest::Response {
    let mut req = http.post(format!("{base}/credential")).json(&body);
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }
    req.send().await.unwrap()
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_endpoint_rejects_bad_grants() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::new();

    // (form fields, expected error code) — every case expects HTTP 400.
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[("grant_type", "client_credentials")], "unsupported_grant_type"),
        (&[("grant_type", PRE_AUTH_GRANT)], "invalid_request"),
        (&[("grant_type", PRE_AUTH_GRANT), ("pre-authorized_code", "nope")], "invalid_grant"),
    ];
    for &(form, expected) in cases {
        let (status, err, _) = problem(
            http.post(format!("{}/token", app.base)).form(form).send().await.unwrap(),
        )
        .await;
        assert_eq!((status, err.as_str()), (400, expected), "form={form:?}");
    }
}

#[tokio::test]
async fn pre_authorized_code_is_single_use() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::new();
    let code = pre_auth_code(&http, &app.base, "2020000001").await;

    // First redemption succeeds.
    let first = http
        .post(format!("{}/token", app.base))
        .form(&[("grant_type", PRE_AUTH_GRANT), ("pre-authorized_code", &code)])
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);

    // Replaying the same code is rejected (the code was consumed).
    let (status, err, _) = problem(
        http.post(format!("{}/token", app.base))
            .form(&[("grant_type", PRE_AUTH_GRANT), ("pre-authorized_code", &code)])
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_grant"));
}

#[tokio::test]
async fn auth_code_token_rejects_bad_pkce_and_codes() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Drive /authorize + mock-idp login to obtain a real auth code bound to a
    // known PKCE challenge.
    let verifier = "test-verifier-0123456789-abcdefghijklmnop";
    let challenge = crypto::b64url(&crypto::sha256(verifier.as_bytes()));
    let auth = http
        .get(format!("{}/authorize", app.base))
        .query(&[
            ("response_type", "code"),
            ("client_id", "test-wallet"),
            ("redirect_uri", "http://127.0.0.1:9999/cb"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let session = auth
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .split("session=")
        .nth(1)
        .unwrap()
        .to_string();
    let login = http
        .post(format!("{}/mock-idp/login", app.base))
        .form(&[("session", session.as_str()), ("username", "alice"), ("password", "alice")])
        .send()
        .await
        .unwrap();
    let cb = login.headers().get("location").unwrap().to_str().unwrap().to_string();
    let code = cb.split("code=").nth(1).unwrap().split('&').next().unwrap().to_string();

    // Wrong PKCE verifier → invalid_grant.
    let (status, err, _) = problem(
        http.post(format!("{}/token", app.base))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("code_verifier", "the-wrong-verifier"),
            ])
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_grant"));

    // An unknown authorization code → invalid_grant.
    let (status, err, _) = problem(
        http.post(format!("{}/token", app.base))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", "not-a-real-code"),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_grant"));
}

// ---------------------------------------------------------------------------
// Credential endpoint — authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credential_endpoint_requires_valid_bearer() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::new();
    let body = json!({
        "credential_configuration_id": CREDENTIAL_CONFIG_ID,
        "proofs": { "jwt": ["x"] }
    });

    // Neither a missing nor a bogus bearer token is accepted.
    for bearer in [None, Some("garbage-token")] {
        let (status, err, _) =
            problem(post_credential(&http, &app.base, bearer, body.clone()).await).await;
        assert_eq!((status, err.as_str()), (401, "invalid_token"), "bearer={bearer:?}");
    }
}

// ---------------------------------------------------------------------------
// Credential endpoint — selector validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credential_endpoint_validates_selector() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::new();
    let token = access_token(&http, &app.base, "2020000001").await;
    let dummy = json!({ "jwt": ["x"] });

    // (request body, expected error) — every case expects HTTP 400.
    let cases = [
        (json!({ "proofs": dummy.clone() }), "invalid_credential_request"),
        (
            json!({ "credential_identifier": "x", "proofs": dummy.clone() }),
            "invalid_credential_request",
        ),
        (
            json!({ "credential_configuration_id": "SomethingElse", "proofs": dummy }),
            "unknown_credential_configuration",
        ),
    ];
    for (body, expected) in cases {
        let (status, err, _) =
            problem(post_credential(&http, &app.base, Some(&token), body).await).await;
        assert_eq!((status, err.as_str()), (400, expected), "expected {expected}");
    }
}

// ---------------------------------------------------------------------------
// Credential endpoint — proof validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credential_endpoint_rejects_bad_proofs() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::new();
    let token = access_token(&http, &app.base, "2020000001").await;
    let holder = HolderKey::generate();
    let cfg = CREDENTIAL_CONFIG_ID;

    let req = |proofs: Value| {
        json!({ "credential_configuration_id": cfg, "proofs": proofs })
    };

    // proofs.jwt missing entirely.
    let (status, err, _) = problem(
        post_credential(&http, &app.base, Some(&token), json!({ "credential_configuration_id": cfg }))
            .await,
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_proof"));

    // proofs.jwt present but empty.
    let (status, err, _) = problem(
        post_credential(&http, &app.base, Some(&token), req(json!({ "jwt": [] }))).await,
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_proof"));

    // Wrong proof `typ`.
    let nonce = fresh_nonce(&http, &app.base).await;
    let bad_typ = proof_with(&holder, "jwt", &app.base, Some(&nonce));
    let (status, err, _) = problem(
        post_credential(&http, &app.base, Some(&token), req(json!({ "jwt": [bad_typ] }))).await,
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_proof"));

    // Wrong audience.
    let nonce = fresh_nonce(&http, &app.base).await;
    let bad_aud = proof_with(&holder, "openid4vci-proof+jwt", "https://evil.example", Some(&nonce));
    let (status, err, _) = problem(
        post_credential(&http, &app.base, Some(&token), req(json!({ "jwt": [bad_aud] }))).await,
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_proof"));

    // Tampered signature (flip the last char of an otherwise-valid proof).
    let nonce = fresh_nonce(&http, &app.base).await;
    let good = build_proof(&holder, &app.base, &nonce);
    let mut tampered = good.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let (status, err, _) = problem(
        post_credential(&http, &app.base, Some(&token), req(json!({ "jwt": [tampered] }))).await,
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_proof"));

    // Unknown / never-issued nonce → invalid_nonce.
    let bad_nonce = proof_with(&holder, "openid4vci-proof+jwt", &app.base, Some("never-issued"));
    let (status, err, _) = problem(
        post_credential(&http, &app.base, Some(&token), req(json!({ "jwt": [bad_nonce] }))).await,
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_nonce"));
}

#[tokio::test]
async fn c_nonce_is_single_use() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::new();
    let cfg = CREDENTIAL_CONFIG_ID;
    let holder = HolderKey::generate();
    let nonce = fresh_nonce(&http, &app.base).await;

    // First credential request consuming `nonce` succeeds.
    let token1 = access_token(&http, &app.base, "2020000001").await;
    let proof1 = build_proof(&holder, &app.base, &nonce);
    let first = post_credential(
        &http,
        &app.base,
        Some(&token1),
        json!({ "credential_configuration_id": cfg, "proofs": { "jwt": [proof1] } }),
    )
    .await;
    assert_eq!(first.status(), 200, "first use of the nonce issues a credential");

    // Reusing the same nonce (fresh token, fresh proof) is rejected.
    let token2 = access_token(&http, &app.base, "2020000001").await;
    let proof2 = build_proof(&holder, &app.base, &nonce);
    let (status, err, _) = problem(
        post_credential(
            &http,
            &app.base,
            Some(&token2),
            json!({ "credential_configuration_id": cfg, "proofs": { "jwt": [proof2] } }),
        )
        .await,
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_nonce"));
}

// ---------------------------------------------------------------------------
// Offer endpoint (admin)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn offer_endpoint_requires_admin_and_valid_input() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::new();
    let offer = |student: Value| {
        json!({ "student_number": student, "grant": "pre_authorized" })
    };

    // No admin credentials.
    let (status, err, _) = problem(
        http.post(format!("{}/credential-offer", app.base))
            .json(&offer(json!("2020000001")))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (401, "invalid_token"));

    // Wrong admin password.
    let (status, err, _) = problem(
        http.post(format!("{}/credential-offer", app.base))
            .basic_auth("admin", Some("wrong"))
            .json(&offer(json!("2020000001")))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (401, "invalid_token"));

    // Unknown student number.
    let (status, err, _) = problem(
        http.post(format!("{}/credential-offer", app.base))
            .basic_auth("admin", Some("admin"))
            .json(&offer(json!("0000000000")))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_request"));

    // Unsupported grant.
    let (status, err, _) = problem(
        http.post(format!("{}/credential-offer", app.base))
            .basic_auth("admin", Some("admin"))
            .json(&json!({ "student_number": "2020000001", "grant": "device_code" }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_request"));
}

#[tokio::test]
async fn get_offer_unknown_id_is_404() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::new();
    let (status, err, _) = problem(
        http.get(format!("{}/credential-offer/does-not-exist", app.base))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (404, "not_found"));
}

// ---------------------------------------------------------------------------
// Admin revoke
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_revoke_authz_and_lookup() {
    let Some(app) = spawn().await else { return };
    let http = reqwest::Client::new();
    let real_uuid = "00000000-0000-0000-0000-000000000000";

    // No admin credentials.
    let resp = http
        .post(format!("{}/admin/credentials/{real_uuid}/revoke", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Authenticated, but the jti is not a valid UUID → invalid_request.
    let (status, err, _) = problem(
        http.post(format!("{}/admin/credentials/not-a-uuid/revoke", app.base))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (400, "invalid_request"));

    // Authenticated, valid UUID, but no such credential → not_found.
    let (status, err, _) = problem(
        http.post(format!("{}/admin/credentials/{real_uuid}/revoke", app.base))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, err.as_str()), (404, "not_found"));
}
