//! # wallet-core — the wallet conformance oracle
//!
//! The real wallet is a separate Kotlin/Android app. It runs this repo's
//! `ssi-core` engine over UniFFI (`crates/wallet-ffi`) rather than a port, so what
//! could drift is no longer the crypto but the **FFI boundary and the Kotlin app
//! shell** (request-verify → VP-build → JWE-seal). This crate is the guard: a
//! black-box wallet that builds an accepted presentation is wired up correctly.
//!
//! It exposes the same engine the verifier uses (`ssi_core::oid4vp`) as two steps
//! a black-box wallet can be tested around:
//!
//! 1. [`mint_bundle`] — given the wallet's **public** holder JWK, mint a demo
//!    SD-JWT VC bound to it (exactly as the issuer would) and an OID4VP
//!    Authorization Request asking for some of its claims. This is everything the
//!    wallet needs as input to build a presentation.
//! 2. [`verify_bundle`] — given that bundle and the **VP Token the wallet
//!    produced**, run the real verifier and return its [`VerificationReport`].
//!
//! A wallet is compatible iff the VP Token it builds makes [`verify_bundle`]
//! report `valid == true`. The `wallet-conformance`
//! binary wraps these two functions as a CLI so a Kotlin (JVM) test can drive them
//! over `ProcessBuilder` with no Rust toolchain knowledge.
//!
//! An optional UniFFI facade could let the wallet call the Rust holder directly
//! instead of reimplementing it; the same two functions keep guarding compatibility.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

use ssi_core::dcql::DcqlQuery;
use ssi_core::oid4vp::{self, VerificationReport};
use ssi_core::resolve::MapFetcher;
use ssi_core::testkit::{self, DEMO_VCT};
use ssi_core::trust::TrustStore;

/// A self-contained presentation challenge: the credential the wallet holds, the
/// request it must answer, and the external documents a verifier needs to fetch
/// to validate the answer. Serializable so `mint` and `verify` can run as
/// separate processes (the Kotlin wallet sits in between).
#[derive(Serialize, Deserialize)]
pub struct Bundle {
    /// The compact SD-JWT VC the wallet stores (issuer JWT + all disclosures).
    pub sd_jwt: String,
    /// The verifier's `did:jwk` Client Identifier — a QR parameter, and the
    /// wallet's trust anchor for verifying the signed request.
    pub client_id: String,
    /// The signed Authorization Request (JAR JWT) — the other QR parameter. The
    /// wallet verifies this against `client_id` before presenting.
    pub request_jwt: String,
    /// The verifier's ephemeral response-encryption **private** JWK, kept on the
    /// verifier side to decrypt the wallet's JWE response. (In the real flow this
    /// never leaves the verifier; here the oracle plays both roles.)
    pub enc_private_jwk: Value,
    /// `url -> document text` (the status list), enough to rebuild the
    /// [`MapFetcher`] the verifier resolves status through. The issuer key comes
    /// from the credential's `x5c` chain, so no DID document is included.
    pub fetcher: HashMap<String, String>,
    /// The verifier's trusted CA roots (PEM), against which the credential's `x5c`
    /// chain is anchored. Mirrors the anchor set passed across the wasm boundary.
    pub anchors: Vec<String>,
}

/// The response URI baked into the oracle's request. Nothing is sent to it; it is
/// only carried in the (signed) request so the shape matches the real flow.
const RESPONSE_URI: &str = "https://verifier.example/response";

/// Mint a demo credential bound to `holder_jwk` plus a **signed** request (did:jwk
/// JAR) for two of its claims. `revoked` marks the credential revoked in its
/// status list (used to prove the wallet/verifier actually honor revocation).
pub fn mint_bundle(holder_jwk: &Value, revoked: bool) -> Bundle {
    let minted = testkit::mint_for_holder(revoked, holder_jwk);

    // Ask for one top-level disclosable claim and one more — both emitted by the
    // demo credential — so the wallet exercises real disclosure selection.
    let dcql: DcqlQuery = serde_json::from_value(json!({
        "credentials": [{
            "id": "diploma",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": [DEMO_VCT] },
            "claims": [ { "path": ["given_name"] }, { "path": ["degree"] } ]
        }]
    }))
    .expect("static DCQL query is valid");

    let (nonce, state) = oid4vp::fresh_request_ids();
    let signed = oid4vp::build_signed_request(&dcql, &nonce, &state, RESPONSE_URI);

    Bundle {
        sd_jwt: minted.sd_jwt,
        client_id: signed.client_id,
        request_jwt: signed.request_jwt,
        enc_private_jwk: signed.enc_private_jwk,
        fetcher: minted.fetcher.as_text_map(),
        anchors: testkit::demo_trust_store().to_pem_list(),
    }
}

/// Validate a wallet's Authorization `response` end to end with the same engine
/// the browser verifier runs: re-verify the signed request (did:jwk JAR), decrypt
/// the JWE response with the verifier's ephemeral key, then `validate_vp_token`.
/// Any failure in the first two steps is surfaced as an invalid report (so the CLI
/// reports it rather than panicking).
pub fn verify_bundle(bundle: &Bundle, response: &Value) -> VerificationReport {
    let request = match oid4vp::verify_request(&bundle.request_jwt, &bundle.client_id) {
        Ok(r) => r,
        Err(e) => return fail_report(format!("signed request did not verify: {e:#}")),
    };
    let vp_token = match oid4vp::decrypt_response(response, &bundle.enc_private_jwk) {
        Ok(t) => t,
        Err(e) => return fail_report(format!("could not decrypt response: {e:#}")),
    };

    let mut fetcher = MapFetcher::new();
    for (url, text) in &bundle.fetcher {
        fetcher.insert(url.clone(), text.clone().into_bytes());
    }
    let trust = TrustStore::from_pems(&bundle.anchors).expect("bundle anchors are valid PEM");
    oid4vp::validate_vp_token(&request, &vp_token, &fetcher, &trust)
}

fn fail_report(error: String) -> VerificationReport {
    VerificationReport {
        valid: false,
        credentials: Vec::new(),
        errors: vec![error],
    }
}
