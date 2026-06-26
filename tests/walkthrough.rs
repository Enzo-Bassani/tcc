//! A narrated, end-to-end walkthrough of the OID4VCI issuance protocol.
//!
//! Unlike `e2e.rs` (which asserts), this test exists to *visualize* the whole
//! exchange: it drives the real server over HTTP and pretty-prints every
//! request and response — credential offer, issuer & AS metadata, token,
//! nonce, and credential — with a banner announcing each protocol step. The
//! issued SD-JWT is decoded at the end so you can see the signed payload, the
//! disclosures, and the reconstructed claim set.
//!
//! It walks the pre-authorized-code flow (no browser redirects), the simplest
//! self-contained path.
//!
//! Run it (stdout is captured by default, so `--nocapture` is required):
//!
//! ```sh
//! TEST_DATABASE_URL=postgres://issuer:issuer@localhost:5432/issuer_backend \
//!     cargo test --test walkthrough -- --nocapture
//! ```

mod common;

use common::{build_proof, spawn};
use issuer_backend::holder::HolderKey;
use issuer_backend::{crypto, sd_jwt};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Pretty-printing helpers
// ---------------------------------------------------------------------------

const RULE: &str = "════════════════════════════════════════════════════════════════════";

/// Announce a protocol step with a numbered banner.
fn step(n: u8, title: &str, actors: &str) {
    println!("\n\n{RULE}");
    println!("  STEP {n} — {title}");
    println!("  {actors}");
    println!("{RULE}");
}

/// Print a labelled blob of pretty JSON, indented under an arrow.
fn show(label: &str, value: &Value) {
    println!("\n{label}");
    let pretty = serde_json::to_string_pretty(value).unwrap();
    for line in pretty.lines() {
        println!("    {line}");
    }
}

/// Print a labelled HTTP request line / form body (non-JSON).
fn show_raw(label: &str, body: &str) {
    println!("\n{label}");
    for line in body.lines() {
        println!("    {line}");
    }
}

/// Decode a compact JWS into `{header, payload}` without verifying it, for display.
fn decode_jwt(jwt: &str) -> Value {
    let (header, payload) = crypto::decode_jws_unverified(jwt).unwrap();
    json!({ "header": header, "payload": payload })
}

// ---------------------------------------------------------------------------
// The walkthrough
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oid4vci_protocol_walkthrough() {
    let Some(app) = spawn().await else {
        return; // TEST_DATABASE_URL not set — harness prints a SKIP notice.
    };
    let http = reqwest::Client::new();
    let base = &app.base;

    println!("\n{RULE}");
    println!("  OID4VCI ISSUANCE WALKTHROUGH — pre-authorized-code flow");
    println!("  issuer base URL: {base}");
    println!("{RULE}");
    println!(
        "\n  Actors:  ADMIN (university staff) · WALLET (student's app) · ISSUER (this server)\n  \
         The ISSUER also acts as the OAuth Authorization Server."
    );

    // -----------------------------------------------------------------------
    step(1, "Credential Offer", "ADMIN → ISSUER, then handed to the WALLET");
    // -----------------------------------------------------------------------
    println!(
        "\n  University staff ask the issuer to mint an offer for a specific student.\n  \
         The issuer returns the offer object plus a `credential_offer_uri` and an\n  \
         `openid-credential-offer://` deep link, which becomes the QR code the wallet scans."
    );
    show_raw(
        "→ REQUEST  POST /credential-offer  (HTTP Basic admin:admin)",
        "{ \"student_number\": \"2020000001\", \"grant\": \"pre_authorized\" }",
    );
    let offer_resp: Value = http
        .post(format!("{base}/credential-offer"))
        .basic_auth("admin", Some("admin"))
        .json(&json!({ "student_number": "2020000001", "grant": "pre_authorized" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    show("← RESPONSE  (the issuer's reply to the admin)", &offer_resp);
    show(
        "   ↪ Credential Offer object (this is what the QR code/deep-link delivers to the WALLET)",
        &offer_resp["credential_offer"],
    );
    let pre_auth_code = offer_resp["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .expect("offer carries a pre-authorized code")
        .to_string();
    println!(
        "\n  The WALLET extracts:\n    • credential_issuer        = {}\n    • pre-authorized_code      = {}\n  \
         and uses credential_issuer to discover the issuer's metadata next.",
        offer_resp["credential_offer"]["credential_issuer"]
            .as_str()
            .unwrap(),
        pre_auth_code,
    );

    // -----------------------------------------------------------------------
    step(2, "Issuer Metadata (discovery)", "WALLET → ISSUER");
    // -----------------------------------------------------------------------
    println!(
        "\n  The wallet GETs `/.well-known/openid-credential-issuer` to learn the credential\n  \
         endpoint, the nonce endpoint, which credential configurations are offered, and which\n  \
         proof types / signing algs it must use."
    );
    let issuer_md: Value = http
        .get(format!("{base}/.well-known/openid-credential-issuer"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    show(
        "← RESPONSE  GET /.well-known/openid-credential-issuer",
        &issuer_md,
    );

    // -----------------------------------------------------------------------
    step(3, "Authorization Server Metadata", "WALLET → ISSUER (as AS)");
    // -----------------------------------------------------------------------
    println!(
        "\n  Standard OAuth metadata (RFC 8414). The wallet reads `token_endpoint` and the\n  \
         supported `grant_types` to know where and how to redeem the pre-authorized code."
    );
    let as_md: Value = http
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    show(
        "← RESPONSE  GET /.well-known/oauth-authorization-server",
        &as_md,
    );

    // -----------------------------------------------------------------------
    step(4, "Token Request", "WALLET → ISSUER (Token Endpoint)");
    // -----------------------------------------------------------------------
    println!(
        "\n  The wallet trades the pre-authorized code for a bearer access token. This is a\n  \
         back-channel, form-encoded POST. Note: in OID4VCI 1.0 the token response does NOT\n  \
         carry a c_nonce — that now comes from a separate Nonce Endpoint (step 5)."
    );
    show_raw(
        "→ REQUEST  POST /token  (application/x-www-form-urlencoded)",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code\n\
             &pre-authorized_code={pre_auth_code}"
        ),
    );
    let token_resp: Value = http
        .post(format!("{base}/token"))
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
    show("← RESPONSE  (Cache-Control: no-store)", &token_resp);
    let access_token = token_resp["access_token"].as_str().unwrap().to_string();

    // -----------------------------------------------------------------------
    step(5, "Nonce Request", "WALLET → ISSUER (Nonce Endpoint, unauthenticated)");
    // -----------------------------------------------------------------------
    println!(
        "\n  The wallet fetches a fresh, single-use challenge (`c_nonce`) to embed in its key\n  \
         proof, so the issuer knows the proof was made for this issuance and isn't a replay."
    );
    show_raw("→ REQUEST  POST /nonce  (empty body, no access token)", "");
    let nonce_resp: Value = http
        .post(format!("{base}/nonce"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    show("← RESPONSE", &nonce_resp);
    let c_nonce = nonce_resp["c_nonce"].as_str().unwrap();

    // -----------------------------------------------------------------------
    step(6, "Credential Request", "WALLET → ISSUER (Credential Endpoint)");
    // -----------------------------------------------------------------------
    println!(
        "\n  The wallet generates a holder key pair, builds a proof JWT binding that key to this\n  \
         issuer (aud) and this nonce, and POSTs it with the access token. The issuer verifies\n  \
         the proof, then embeds the holder's public key into the credential it signs (`cnf`)."
    );
    let holder = HolderKey::generate();
    let proof = build_proof(&holder, base, c_nonce);
    show(
        "   ↪ The key proof JWT, decoded (typ=openid4vci-proof+jwt — this is the holder binding)",
        &decode_jwt(&proof),
    );
    let credential_request = json!({
        "credential_configuration_id": "UniversityDiplomaSdJwt",
        "proofs": { "jwt": [proof] }
    });
    show(
        "→ REQUEST  POST /credential  (Authorization: Bearer <access_token>)",
        &credential_request,
    );
    let cred_resp: Value = http
        .post(format!("{base}/credential"))
        .bearer_auth(&access_token)
        .json(&credential_request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    show("← RESPONSE  (a `credentials` array, one issued instance)", &cred_resp);

    let sd_jwt = cred_resp["credentials"][0]["credential"]
        .as_str()
        .expect("credential was issued");

    // -----------------------------------------------------------------------
    step(7, "Decoding the issued SD-JWT VC", "WALLET inspects what it received");
    // -----------------------------------------------------------------------
    println!(
        "\n  The credential is a compact SD-JWT: `<issuer-JWT>~<disclosure>~...~`. Below is the\n  \
         signed issuer payload (selectively-disclosable claims appear only as `_sd` digests),\n  \
         each disclosure broken into salt/name/value, and the full reconstructed claim set."
    );
    show_raw("Compact SD-JWT (base64url, ~-separated)", sd_jwt);
    let explained = sd_jwt::explain(sd_jwt).unwrap();
    show("Decoded SD-JWT", &explained);

    println!("\n\n{RULE}");
    println!("  WALKTHROUGH COMPLETE — the wallet now holds a verifiable diploma credential.");
    println!("{RULE}\n");
}
