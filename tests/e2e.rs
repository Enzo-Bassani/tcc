//! End-to-end OID4VCI tests: issue a diploma and verify it, over both the
//! pre-authorized-code and the authorization-code flows.
//!
//! Run with: `TEST_DATABASE_URL=postgres://issuer:issuer@localhost:5432/issuer_backend cargo test`

mod common;

use common::{build_proof, spawn};
use issuer_backend::holder::HolderKey;
use issuer_backend::{crypto, diploma, sd_jwt, status};
use serde_json::{Value, json};

/// Fetch the status list and read the bit at `index`.
async fn fetch_status_bit(http: &reqwest::Client, base: &str, index: usize) -> bool {
    let jwt = http
        .get(format!("{base}/status-lists/diploma-2026"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let (_h, payload) = crypto::decode_jws_unverified(&jwt).unwrap();
    let lst = payload["status_list"]["lst"].as_str().unwrap();
    status::BitString::decode(lst).unwrap().get(index)
}

#[tokio::test]
async fn pre_authorized_flow_issues_and_revokes() {
    let Some(app) = spawn().await else {
        return;
    };
    let http = reqwest::Client::new();

    // 1. Admin mints a pre-authorized credential offer.
    let offer: Value = http
        .post(format!("{}/credential-offer", app.base))
        .basic_auth("admin", Some("admin"))
        .json(&json!({ "student_number": "2020000001", "grant": "pre_authorized" }))
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

    // 2. Exchange the pre-authorized code for an access token.
    let token: Value = http
        .post(format!("{}/token", app.base))
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

    // 3. Get a c_nonce and build the wallet proof.
    let nonce: Value = http
        .post(format!("{}/nonce", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let holder = HolderKey::generate();
    let proof = build_proof(&holder, &app.base, nonce["c_nonce"].as_str().unwrap());

    // 4. Request the credential.
    let cred: Value = http
        .post(format!("{}/credential", app.base))
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "UniversityDiplomaSdJwt",
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

    // 5. Verify the SD-JWT VC.
    let (issuer_jwt, disclosures) = sd_jwt::split(&sd_jwt);
    assert_eq!(
        disclosures.len(),
        diploma::disclosable_paths().len(),
        "every disclosable claim produces one disclosure"
    );

    let jwks: Value = http
        .get(format!("{}/.well-known/jwks.json", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // The issuer signs with ES256 (x5c); verify against the published EC JWK.
    let (_h, payload) = crypto::verify_jws_with_jwk(&issuer_jwt, &jwks["keys"][0])
        .expect("issuer signature is valid");

    let full = sd_jwt::reconstruct_claims(&payload, &disclosures).unwrap();
    assert_eq!(full["student"]["full_name"], "Alice Turing");
    assert_eq!(full["student"]["national_id"], "123.456.789-09");
    assert_eq!(full["degree"]["level"], "bachelor");
    assert_eq!(
        full["institution"]["name"],
        "Universidade Federal de Santa Catarina"
    );
    assert_eq!(full["registry"]["number"], "2026.0001");

    let jti = payload["jti"].as_str().unwrap().to_string();
    let status_idx = payload["status"]["status_list"]["idx"].as_u64().unwrap() as usize;

    // 6. The credential is not revoked yet.
    assert!(
        !fetch_status_bit(&http, &app.base, status_idx).await,
        "status bit clear before revocation"
    );

    // 7. Revoke it.
    let revoke = http
        .post(format!("{}/admin/credentials/{}/revoke", app.base, jti))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), 204);

    // 8. The status bit is now set.
    assert!(
        fetch_status_bit(&http, &app.base, status_idx).await,
        "status bit set after revocation"
    );
}

#[tokio::test]
async fn authorization_code_flow_issues_credential() {
    let Some(app) = spawn().await else {
        return;
    };
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let verifier = "test-verifier-0123456789-abcdefghijklmnop";
    let challenge = crypto::b64url(&crypto::sha256(verifier.as_bytes()));

    // 1. /authorize redirects to the mock IdP login.
    let auth = http
        .get(format!("{}/authorize", app.base))
        .query(&[
            ("response_type", "code"),
            ("client_id", "test-wallet"),
            ("redirect_uri", "http://127.0.0.1:9999/cb"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", "xyz"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(auth.status(), 303);
    let login_loc = auth
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let session = login_loc.split("session=").nth(1).unwrap().to_string();

    // 2. Student logs in at the mock IdP; redirected back with an auth code.
    let login = http
        .post(format!("{}/mock-idp/login", app.base))
        .form(&[
            ("session", session.as_str()),
            ("username", "alice"),
            ("password", "alice"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 303);
    let cb = login
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(cb.starts_with("http://127.0.0.1:9999/cb?code="));
    let code = cb
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();

    // 3. Exchange the auth code (with PKCE verifier) for an access token.
    let token: Value = http
        .post(format!("{}/token", app.base))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = token["access_token"]
        .as_str()
        .expect("access token issued")
        .to_string();

    // 4. Nonce + proof + credential request.
    let nonce: Value = http
        .post(format!("{}/nonce", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let holder = HolderKey::generate();
    let proof = build_proof(&holder, &app.base, nonce["c_nonce"].as_str().unwrap());
    let cred: Value = http
        .post(format!("{}/credential", app.base))
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "UniversityDiplomaSdJwt",
            "proofs": { "jwt": [proof] }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        cred["credentials"][0]["credential"].as_str().is_some(),
        "authorization-code flow issues a credential, got: {cred}"
    );
}
