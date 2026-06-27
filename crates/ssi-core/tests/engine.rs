//! End-to-end engine tests: mint a credential, have the simulated wallet present
//! it against a DCQL query, and validate the resulting VP Token — all in-process,
//! no relay, no server. The issuer signs ES256 (x5c); the holder defaults to
//! ES256 with an explicit EdDSA backward-compatibility case. Covers the main
//! failure modes too.

use serde_json::{Value, json};
use ssi_core::dcql::DcqlQuery;
use ssi_core::testkit;
use std::sync::Arc;
use ssi_core::wallet_sim::StoredCredential;
use ssi_core::{oid4vp, testkit::DEMO_VCT};

/// A DCQL query asking for the holder's name from the demo credential.
fn name_query() -> (DcqlQuery, Value) {
    let raw = json!({
        "credentials": [{
            "id": "diploma",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": [DEMO_VCT] },
            "claims": [
                { "path": ["given_name"] },
                { "path": ["family_name"] }
            ]
        }]
    });
    (serde_json::from_value(raw.clone()).unwrap(), raw)
}

/// Present `demo` against a name query and validate it under `trust`.
fn drive_trust(demo: &testkit::DemoCredential, trust: &ssi_core::trust::TrustStore) -> oid4vp::VerificationReport {
    let (dcql, _) = name_query();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let request = oid4vp::build_signed_request(
        &dcql,
        &nonce,
        &state,
        "https://verifier.example/response",
    )
    .request;

    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: Arc::new(demo.holder.clone()),
    }];
    let vp_token = ssi_core::wallet_sim::create_vp_token(&request, &wallet).unwrap();

    oid4vp::validate_vp_token(&request, &vp_token, &demo.fetcher, trust)
}

fn drive(revoked: bool) -> oid4vp::VerificationReport {
    let demo = testkit::mint(revoked);
    drive_trust(&demo, &testkit::demo_trust_store())
}

#[test]
fn happy_path_is_valid() {
    let report = drive(false);
    assert!(report.valid, "report should be valid: {report:?}");
    let cred = &report.credentials[0];
    assert!(matches!(cred.issuer_signature, oid4vp::Check::Pass));
    assert!(matches!(cred.trusted_issuer, oid4vp::Check::Pass));
    assert!(matches!(cred.holder_binding, oid4vp::Check::Pass));
    assert!(matches!(cred.dcql_satisfied, oid4vp::Check::Pass));
    assert!(matches!(cred.revocation, oid4vp::Check::Pass));
    // Data minimization: only the two requested claims were disclosed.
    assert_eq!(cred.disclosed_claims["given_name"], "Ada");
    assert_eq!(cred.disclosed_claims["family_name"], "Lovelace");
    assert!(cred.disclosed_claims.get("degree").is_none());
}

#[test]
fn eddsa_holder_binding_is_still_accepted() {
    // The default holder is ES256, but the verifier MUST still accept an EdDSA
    // (Ed25519) key-binding JWT — the backward-compatibility path we keep.
    use ssi_core::holder::HolderKey;
    let demo = testkit::mint_with_holder(false, HolderKey::generate_ed25519());
    let report = drive_trust(&demo, &testkit::demo_trust_store());
    assert!(report.valid, "EdDSA holder binding must verify: {report:?}");
    assert!(matches!(
        report.credentials[0].holder_binding,
        oid4vp::Check::Pass
    ));
}

#[test]
fn revoked_credential_is_rejected() {
    let report = drive(true);
    assert!(!report.valid);
    assert!(matches!(
        report.credentials[0].revocation,
        oid4vp::Check::Fail(_)
    ));
}

#[test]
fn untrusted_root_fails_trusted_issuer_but_signature_still_passes() {
    // The rogue issuer's leaf signs the credential (so issuer_signature passes),
    // but its chain does not anchor at the bundled ICP-Brasil root.
    let demo = testkit::mint_with(&testkit::DemoIssuer::rogue(), None, false);
    let report = drive_trust(&demo, &testkit::demo_trust_store());
    assert!(!report.valid);
    let cred = &report.credentials[0];
    assert!(matches!(cred.issuer_signature, oid4vp::Check::Pass));
    assert!(matches!(cred.trusted_issuer, oid4vp::Check::Fail(_)));
}

#[test]
fn expired_leaf_fails_trusted_issuer() {
    let demo = testkit::mint_with(&testkit::DemoIssuer::expired(), None, false);
    let report = drive_trust(&demo, &testkit::demo_trust_store());
    assert!(!report.valid);
    let cred = &report.credentials[0];
    match &cred.trusted_issuer {
        oid4vp::Check::Fail(detail) => assert!(detail.contains("expired"), "detail: {detail}"),
        other => panic!("expected trusted_issuer Fail, got {other:?}"),
    }
}

#[test]
fn iss_san_mismatch_fails_trusted_issuer() {
    let demo = testkit::mint_with(&testkit::DemoIssuer::ufsc(), Some("https://evil.example"), false);
    let report = drive_trust(&demo, &testkit::demo_trust_store());
    assert!(!report.valid);
    assert!(matches!(
        report.credentials[0].trusted_issuer,
        oid4vp::Check::Fail(_)
    ));
}

#[test]
fn empty_trust_store_fails_trusted_issuer() {
    let demo = testkit::mint(false);
    let report = drive_trust(&demo, &ssi_core::trust::TrustStore::empty());
    assert!(!report.valid);
    assert!(matches!(
        report.credentials[0].trusted_issuer,
        oid4vp::Check::Fail(_)
    ));
}

#[test]
fn wrong_nonce_breaks_holder_binding() {
    let demo = testkit::mint(false);
    let (dcql, _) = name_query();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let request =
        oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r").request;

    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: Arc::new(demo.holder.clone()),
    }];
    let vp_token = ssi_core::wallet_sim::create_vp_token(&request, &wallet).unwrap();

    // Verifier checks the token against a DIFFERENT request (fresh nonce) — the
    // key binding must fail, defeating replay across sessions.
    let mut other = request.clone();
    other["nonce"] = json!("a-different-nonce");
    let report = oid4vp::validate_vp_token(&other, &vp_token, &demo.fetcher, &testkit::demo_trust_store());
    assert!(!report.valid);
    assert!(matches!(
        report.credentials[0].holder_binding,
        oid4vp::Check::Fail(_)
    ));
}

#[test]
fn tampered_issuer_signature_is_caught() {
    let demo = testkit::mint(false);
    let (dcql, _) = name_query();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let request =
        oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r").request;
    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: Arc::new(demo.holder.clone()),
    }];
    let mut vp_token = ssi_core::wallet_sim::create_vp_token(&request, &wallet).unwrap();

    // Flip a character inside the issuer JWT *signature* (after its 2nd '.', before
    // the first '~'), leaving header (x5c) and payload (iss) intact — so only the
    // signature check fails while trusted_issuer still passes.
    let pres = vp_token["diploma"][0].as_str().unwrap().to_string();
    let issuer_jwt_end = pres.find('~').unwrap_or(pres.len());
    let sig_start = pres[..issuer_jwt_end].rfind('.').unwrap() + 1;
    let idx = sig_start + 2;
    let mut bytes: Vec<char> = pres.chars().collect();
    bytes[idx] = if bytes[idx] == 'A' { 'B' } else { 'A' };
    vp_token["diploma"][0] = json!(bytes.into_iter().collect::<String>());

    let report = oid4vp::validate_vp_token(&request, &vp_token, &demo.fetcher, &testkit::demo_trust_store());
    assert!(!report.valid);
    // The chain is still valid, so trust passes; only the signature check fails.
    assert!(matches!(
        report.credentials[0].trusted_issuer,
        oid4vp::Check::Pass
    ));
    assert!(matches!(
        report.credentials[0].issuer_signature,
        oid4vp::Check::Fail(_)
    ));
}

#[test]
fn inspect_reports_only_status_urls() {
    let demo = testkit::mint(false);
    let (dcql, _) = name_query();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let request =
        oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r").request;
    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: Arc::new(demo.holder.clone()),
    }];
    let vp_token = ssi_core::wallet_sim::create_vp_token(&request, &wallet).unwrap();

    let urls = oid4vp::inspect(&vp_token).unwrap();
    // No DID documents are fetched anymore — only the status list.
    assert!(!urls.iter().any(|u| u.ends_with("/.well-known/did.json")));
    assert_eq!(urls, vec![demo.status_uri.clone()]);
}

// ---------------------------------------------------------------------------
// The zero-knowledge-relay path: a signed (did:jwk JAR) request and an encrypted
// (`direct_post.jwt`) response, end to end.
// ---------------------------------------------------------------------------

#[test]
fn signed_request_and_encrypted_response_roundtrip() {
    let demo = testkit::mint(false);
    let (dcql, _) = name_query();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let signed = oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r");

    // The request is a did:jwk JAR; its client_id is the QR-anchored trust root.
    assert!(signed.client_id.starts_with("decentralized_identifier:did:jwk:"));
    assert_eq!(signed.request["response_mode"], "direct_post.jwt");

    // Wallet side: verify the JAR against the QR client_id, then build + encrypt.
    let request = oid4vp::verify_request(&signed.request_jwt, &signed.client_id)
        .expect("signed request must verify");
    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: Arc::new(demo.holder.clone()),
    }];
    let response = ssi_core::wallet_sim::create_response(&request, &wallet).unwrap();

    // The relay would only ever see this — an opaque JWE, with no cleartext `vp_token`
    // channel (that exists only for unencrypted direct_post). The claims are recoverable
    // *only* by decrypting, which we confirm below. (A substring check against the JWE
    // body is unsound: it is base64url, so any short claim value — e.g. "Ada" — appears
    // in the ciphertext by chance ~1/50 runs, which made this assertion flaky.)
    let jwe = response["response"].as_str().expect("response is an encrypted JWE");
    assert_eq!(jwe.split('.').count(), 5);
    assert!(response.get("vp_token").is_none(), "no cleartext vp_token may accompany the JWE");

    // Verifier side: decrypt with its ephemeral key, then validate as usual.
    let vp_token = oid4vp::decrypt_response(&response, &signed.enc_private_jwk).unwrap();
    let report =
        oid4vp::validate_vp_token(&request, &vp_token, &demo.fetcher, &testkit::demo_trust_store());
    assert!(report.valid, "decrypted presentation must verify: {report:?}");
    assert_eq!(report.credentials[0].disclosed_claims["given_name"], "Ada");
}

#[test]
fn tampered_signed_request_is_rejected() {
    let (dcql, _) = name_query();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let signed = oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r");

    // Flip a byte in the JAR signature → the wallet must refuse the request.
    let mut jwt = signed.request_jwt.clone();
    let last = jwt.pop().unwrap();
    jwt.push(if last == 'A' { 'B' } else { 'A' });
    assert!(
        oid4vp::verify_request(&jwt, &signed.client_id).is_err(),
        "a tampered JAR must not verify"
    );
}

#[test]
fn swapped_client_id_is_rejected() {
    // An active relay can't help itself: if it swaps the QR client_id for its own
    // did:jwk, the request signature no longer matches that key → rejected.
    let (dcql, _) = name_query();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let signed = oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r");
    let attacker = oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r");

    assert!(
        oid4vp::verify_request(&signed.request_jwt, &attacker.client_id).is_err(),
        "request must not verify under a different did:jwk client_id"
    );
}

#[test]
fn wrong_enc_key_cannot_decrypt_response() {
    let demo = testkit::mint(false);
    let (dcql, _) = name_query();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let signed = oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r");
    let request = oid4vp::verify_request(&signed.request_jwt, &signed.client_id).unwrap();
    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: Arc::new(demo.holder.clone()),
    }];
    let response = ssi_core::wallet_sim::create_response(&request, &wallet).unwrap();

    // A different session's private key (what a key-swapping relay would hold) can't open it.
    let other = oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r");
    assert!(oid4vp::decrypt_response(&response, &other.enc_private_jwk).is_err());
}

#[test]
fn find_matches_reports_disclosed_and_always_shared() {
    use std::collections::{HashMap, HashSet};

    let demo = testkit::mint(false);
    let (dcql, _) = name_query();
    let (nonce, state) = oid4vp::fresh_request_ids();
    let request = oid4vp::build_signed_request(&dcql, &nonce, &state, "https://verifier.example/r").request;
    let sd_jwts = vec![demo.sd_jwt.clone()];

    let matches = ssi_core::wallet_sim::find_matches(&request, &sd_jwts).unwrap();
    assert_eq!(matches.len(), 1);
    let qm = &matches[0];
    assert_eq!(qm.query_id, "diploma");
    assert_eq!(qm.vct.as_deref(), Some(DEMO_VCT));
    assert_eq!(qm.matches.len(), 1, "the held diploma satisfies the query");

    let m = &qm.matches[0];
    assert_eq!(m.index, 0);
    assert_eq!(m.vct.as_deref(), Some(DEMO_VCT));

    // disclosed = exactly the two requested claims, with their raw values.
    let disclosed: HashMap<String, Value> =
        m.disclosed.iter().map(|d| (d.path.join("."), d.value.clone())).collect();
    assert_eq!(disclosed.len(), 2);
    assert_eq!(disclosed["given_name"], json!("Ada"));
    assert_eq!(disclosed["family_name"], json!("Lovelace"));

    // always_shared carries the signed metadata the holder can't withhold, but
    // never the selectively-disclosed claims.
    let always: HashSet<String> = m.always_shared.iter().map(|d| d.path.join(".")).collect();
    assert!(always.contains("vct"), "vct travels with every presentation");
    assert!(always.contains("cnf"), "holder key binding is always shared");
    assert!(!always.contains("given_name"));
    assert!(!always.contains("family_name"));
}
