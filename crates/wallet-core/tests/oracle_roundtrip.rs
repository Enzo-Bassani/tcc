//! Proves the conformance oracle itself is correct, end to end, in Rust — before
//! any Kotlin exists. `wallet_sim` plays the (known-good) wallet: mint a bundle,
//! let the simulated holder build a VP Token from its `request`, then verify it.
//! The Kotlin wallet's `ConformanceTest` runs the same loop, but driving the
//! `wallet-ffi` UniFFI engine (the same `wallet_sim` code) to produce the VP Token.

use ssi_core::holder::HolderKey;
use ssi_core::oid4vp::{self, Check};
use std::sync::Arc;
use ssi_core::wallet_sim::{StoredCredential, create_response, create_vp_token, encrypt_response};
use wallet_core::{mint_bundle, verify_bundle};

/// A stand-in wallet: generate a holder key, get a bundle bound to it, verify the
/// bundle's signed request (did:jwk JAR), and have `wallet_sim` build the
/// **encrypted** Authorization Response. Returns (bundle, response).
fn present(revoked: bool) -> (wallet_core::Bundle, serde_json::Value) {
    let holder = HolderKey::generate();
    let bundle = mint_bundle(&holder.public_jwk(), revoked);
    let request = oid4vp::verify_request(&bundle.request_jwt, &bundle.client_id)
        .expect("bundle's signed request verifies");
    let wallet = vec![StoredCredential {
        sd_jwt: bundle.sd_jwt.clone(),
        holder: Arc::new(holder.clone()),
    }];
    let response = create_response(&request, &wallet).expect("wallet builds a response");
    (bundle, response)
}

#[test]
fn good_presentation_is_valid() {
    let (bundle, response) = present(false);
    // The response the relay would carry is an opaque JWE.
    assert!(response.get("response").and_then(|v| v.as_str()).is_some());
    let report = verify_bundle(&bundle, &response);
    assert!(report.valid, "expected valid report, got {report:?}");

    // Only the two requested claims were disclosed (data minimization).
    let disclosed = &report.credentials[0].disclosed_claims;
    assert_eq!(disclosed["given_name"], "Ada");
    assert_eq!(disclosed["degree"], "BSc Mathematics");
    assert!(disclosed.get("family_name").is_none(), "undisclosed claim leaked");
}

#[test]
fn revoked_presentation_is_invalid() {
    let (bundle, response) = present(true);
    let report = verify_bundle(&bundle, &response);
    assert!(!report.valid);
    assert!(matches!(report.credentials[0].revocation, Check::Fail(_)));
}

#[test]
fn tampered_disclosure_breaks_holder_binding() {
    // If the VP Token's disclosures are altered after the KB-JWT is signed, the
    // sd_hash no longer matches and holder binding must fail. We tamper the token
    // *before* encrypting it (a malicious holder), then seal it as the real flow does.
    let holder = HolderKey::generate();
    let bundle = mint_bundle(&holder.public_jwk(), false);
    let request = oid4vp::verify_request(&bundle.request_jwt, &bundle.client_id).unwrap();
    let wallet = vec![StoredCredential {
        sd_jwt: bundle.sd_jwt.clone(),
        holder: Arc::new(holder.clone()),
    }];
    let mut vp_token = create_vp_token(&request, &wallet).unwrap();

    let pres = vp_token["diploma"][0].as_str().unwrap().to_string();
    // Flip a character inside the first disclosure segment (between the tildes).
    let mut segs: Vec<&str> = pres.split('~').collect();
    let mut tampered = segs[1].to_string();
    tampered.insert(0, 'X');
    segs[1] = &tampered;
    vp_token["diploma"][0] = serde_json::Value::String(segs.join("~"));

    let response = encrypt_response(&request, vp_token).unwrap();
    let report = verify_bundle(&bundle, &response);
    assert!(!report.valid, "tampered presentation must not verify");
}
