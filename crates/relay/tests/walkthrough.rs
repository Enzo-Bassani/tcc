//! A narrated, end-to-end walkthrough of the OID4VP 1.0 presentation protocol —
//! the verifier's counterpart to the issuer's `tests/walkthrough.rs`.
//!
//! It drives the real dumb relay over HTTP and pretty-prints every message —
//! session creation, the Authorization Request (with its DCQL query), the wallet
//! fetching it, the VP Token (decoded SD-JWT + key-binding JWT), and finally the
//! verifier's local validation report. The credential is a *generic* SD-JWT VC
//! (not university-specific) to show the verifier is universal.
//!
//! Run it (stdout is captured by default, so `--nocapture` is required):
//!
//! ```sh
//! cargo test -p relay --test walkthrough -- --nocapture
//! ```

mod common;

use common::spawn;
use serde_json::{Value, json};
use ssi_core::testkit::{self, DEMO_VCT};
use std::sync::Arc;
use ssi_core::wallet_sim::StoredCredential;
use ssi_core::{crypto, oid4vp, sd_jwt};

const RULE: &str = "════════════════════════════════════════════════════════════════════";

fn step(n: u8, title: &str, actors: &str) {
    println!("\n\n{RULE}");
    println!("  STEP {n} — {title}");
    println!("  {actors}");
    println!("{RULE}");
}

fn show(label: &str, value: &Value) {
    println!("\n{label}");
    for line in serde_json::to_string_pretty(value).unwrap().lines() {
        println!("    {line}");
    }
}

fn show_raw(label: &str, body: &str) {
    println!("\n{label}");
    for line in body.lines() {
        println!("    {line}");
    }
}

fn decode_jwt(jwt: &str) -> Value {
    let (header, payload) = crypto::decode_jws_unverified(jwt).unwrap();
    json!({ "header": header, "payload": payload })
}

#[tokio::test]
async fn oid4vp_protocol_walkthrough() {
    let relay = spawn().await;
    let http = reqwest::Client::new();
    let base = &relay.base;

    println!("\n{RULE}");
    println!("  OID4VP PRESENTATION WALKTHROUGH — cross-device, dumb-relay transport");
    println!("  relay base URL: {base}");
    println!("{RULE}");
    println!(
        "\n  Actors:  VERIFIER (a hiring site, in the browser) · WALLET (holder's phone) ·\n  \
         RELAY (this server — a blind mailbox). All crypto is done by the VERIFIER locally;\n  \
         the RELAY only forwards opaque messages and never sees a key."
    );

    // The holder already holds a credential (issued earlier over OID4VCI). We mint
    // a generic SD-JWT VC here, carrying the issuer's x5c certificate chain, plus
    // the status list the verifier will fetch to check it.
    let demo = testkit::mint(false);
    let trust = testkit::demo_trust_store();
    println!(
        "\n  (Set-up) The WALLET already holds a generic SD-JWT VC of type:\n    {DEMO_VCT}\n  \
         issued by {} and bound to the holder's key.",
        demo.issuer
    );

    // -----------------------------------------------------------------------
    step(1, "Verifier opens a relay session", "VERIFIER → RELAY");
    // -----------------------------------------------------------------------
    println!(
        "\n  The verifier asks the relay for a transport session. The relay returns a request_uri\n  \
         (where the wallet will fetch the signed request — the compact-QR / by-reference mode\n  \
         shown here) and a response_uri (where the wallet POSTs its encrypted response). The\n  \
         relay stores nothing meaningful yet."
    );
    show_raw("→ REQUEST  POST /sessions", "(empty body)");
    let session: Value = http
        .post(format!("{base}/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    show("← RESPONSE", &session);
    let request_uri = session["request_uri"].as_str().unwrap();
    let response_uri = session["response_uri"].as_str().unwrap();

    // -----------------------------------------------------------------------
    step(2, "Verifier builds and SIGNS the Authorization Request (did:jwk JAR)", "VERIFIER");
    // -----------------------------------------------------------------------
    println!(
        "\n  The verifier expresses what it needs as a DCQL query — here, just the holder's\n  \
         given and family name from a diploma credential (data minimization). Having no CA\n  \
         certificate, it mints an EPHEMERAL key, encodes it as a did:jwk, and uses that as its\n  \
         client_id. It also mints an ephemeral ECDH-ES encryption key (advertised in\n  \
         client_metadata.jwks) and signs the whole request as a JAR (RFC 9101)."
    );
    let dcql: ssi_core::dcql::DcqlQuery = serde_json::from_value(json!({
        "credentials": [{
            "id": "diploma",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": [DEMO_VCT] },
            "claims": [
                { "path": ["given_name"] },
                { "path": ["family_name"] }
            ]
        }]
    }))
    .unwrap();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let signed = oid4vp::build_signed_request(&dcql, &nonce, &state, response_uri);
    show("   ↪ The Authorization Request (claims, before signing)", &signed.request);
    show("   ↪ The signed Request Object (JAR JWT), decoded", &decode_jwt(&signed.request_jwt));
    println!(
        "\n  The QR carries the client_id (the did:jwk — the wallet's trust anchor). In the\n  \
         compact-QR / by-reference mode shown here, the signed request is uploaded to the relay\n  \
         and the QR carries a request_uri:\n    \
         openid4vp://?client_id={}&request_uri=<relay>\n  \
         (A high-privacy mode instead embeds &request=<JWT> in the QR so the request never\n  \
         touches the relay — at the cost of a large, dense QR.) Either way the request is\n  \
         SIGNED, so the relay can never tamper with it or swap the verifier's keys.",
        signed.client_id
    );
    show_raw("→ REQUEST  PUT {request_uri}  (verifier uploads the signed request)", request_uri);
    http.put(request_uri)
        .json(&json!({ "request": signed.request_jwt }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // -----------------------------------------------------------------------
    step(3, "Wallet scans the QR, fetches the request, and verifies it", "WALLET → RELAY");
    // -----------------------------------------------------------------------
    println!(
        "\n  The wallet scans the QR, fetches the signed request from the relay (by reference),\n  \
         resolves the did:jwk from the client_id, and verifies the JAR signature against it.\n  \
         A tampered or relay-injected request would fail here."
    );
    let fetched: Value = http.get(request_uri).send().await.unwrap().json().await.unwrap();
    let request_jwt = fetched["request"].as_str().unwrap();
    let request = oid4vp::verify_request(request_jwt, &signed.client_id)
        .expect("the signed request must verify");
    show("   ↪ The verified Authorization Request", &request);

    // -----------------------------------------------------------------------
    step(4, "Wallet builds the VP Token and posts the ENCRYPTED response", "WALLET → RELAY");
    // -----------------------------------------------------------------------
    println!(
        "\n  The wallet finds a credential that satisfies the DCQL query, discloses only the\n  \
         requested claims, and signs a key-binding JWT over the verifier's nonce + client_id\n  \
         (the audience) and the sd_hash of the disclosures. It then JWE-encrypts the response\n  \
         to the verifier's ephemeral key and POSTs the ciphertext to the relay."
    );
    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: Arc::new(demo.holder.clone()),
    }];
    let vp_token = ssi_core::wallet_sim::create_vp_token(&request, &wallet).unwrap();
    show(
        "   ↪ vp_token (keyed by the DCQL credential id; value is an array of presentations)",
        &vp_token,
    );

    // Decode the presentation so the structure is visible.
    let presentation = vp_token["diploma"][0].as_str().unwrap();
    let parsed = sd_jwt::split_presentation(presentation).unwrap();
    show(
        "   ↪ The SD-JWT issuer JWT, decoded (selectively-disclosable claims are `_sd` digests)",
        &decode_jwt(&parsed.issuer_jwt),
    );
    show(
        "   ↪ The key-binding JWT, decoded (typ=kb+jwt — binds nonce, aud, sd_hash to the holder key)",
        &decode_jwt(parsed.key_binding_jwt.as_ref().unwrap()),
    );
    show(
        "   ↪ The presentation, fully explained (disclosed claims reconstructed)",
        &sd_jwt::explain(presentation).unwrap(),
    );

    let posted = ssi_core::wallet_sim::create_response(&request, &wallet).unwrap();
    show(
        "   ↪ The Authorization Response the relay actually carries (an opaque JWE — no cleartext claims)",
        &posted,
    );
    show_raw("→ REQUEST  POST {response_uri}  (encrypted Authorization Response)", response_uri);
    http.post(response_uri)
        .json(&posted)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // -----------------------------------------------------------------------
    step(5, "Verifier retrieves and decrypts the response", "VERIFIER → RELAY");
    // -----------------------------------------------------------------------
    println!(
        "\n  The verifier polls the relay for the response. (The relay replies 204 until the\n  \
         wallet has posted; here it is already present.) It then decrypts the JWE with its\n  \
         session encryption key — something the relay cannot do."
    );
    let response: Value = http
        .get(response_uri)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    show("← RESPONSE  GET {response_uri}  (ciphertext)", &response);
    let decrypted = oid4vp::decrypt_response(&response, &signed.enc_private_jwk).unwrap();

    // -----------------------------------------------------------------------
    step(6, "Verifier validates locally", "VERIFIER (ssi-core engine)");
    // -----------------------------------------------------------------------
    println!(
        "\n  This is the crux: the verifier does every check itself. It validates the issuer's\n  \
         X.509 certificate chain (x5c) up to a trusted CA root and binds `iss` to the leaf\n  \
         certificate, verifies the issuer signature with the leaf key, checks the key binding\n  \
         against its own nonce + client_id, confirms the DCQL query is answered, and checks\n  \
         revocation against the issuer's Token Status List. The relay did none of this."
    );
    println!("\n  Trusted CA roots the verifier anchors the issuer chain against:");
    for anchor in trust.anchors() {
        println!("    • {} [{}]", anchor.label, &anchor.fingerprint[..16]);
    }
    println!("\n  External documents the verifier fetches to validate (status list):");
    for url in oid4vp::inspect(&decrypted).unwrap() {
        println!("    • {url}");
    }
    println!(
        "  (In production these are fetched over HTTP from the issuer; here they come from the\n  \
         in-memory fixture the credential was minted with.)"
    );

    let report = oid4vp::validate_vp_token(&request, &decrypted, &demo.fetcher, &trust);
    show(
        "   ↪ Verification report (per-check, then overall)",
        &serde_json::to_value(&report).unwrap(),
    );
    assert!(report.valid, "the walkthrough presentation must verify");

    println!("\n\n{RULE}");
    println!("  WALKTHROUGH COMPLETE — the verifier accepted a minimal, holder-consented,");
    println!("  cryptographically-verified presentation, having trusted the relay with nothing.");
    println!("{RULE}\n");
}
