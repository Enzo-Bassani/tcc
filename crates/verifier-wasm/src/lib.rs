//! Browser bindings for the `ssi-core` verifier engine.
//!
//! The browser does all I/O (talking to the relay, fetching DID documents and
//! status lists); this module does all the *cryptography* — building the OID4VP
//! request and validating the VP Token — locally, in WebAssembly. The relay and
//! the page's JavaScript never see a verifier key and never make a trust
//! decision. JSON crosses the boundary as strings to keep the surface tiny.

use std::collections::HashMap;

use ssi_core::dcql::DcqlQuery;
use ssi_core::oid4vp;
use ssi_core::resolve::MapFetcher;
use ssi_core::trust::TrustStore;
use ssi_core::x509::Cert;
use wasm_bindgen::prelude::*;

/// Install a panic hook so Rust panics surface in the browser console.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Build a **signed** OID4VP Authorization Request (a `did:jwk` JAR) for a DCQL
/// query, with a fresh nonce + state and an ephemeral response-encryption key.
/// Returns a JSON object `{ client_id, request_jwt, request, enc_private_jwk }`:
/// the page puts `client_id` + `request_jwt` in the QR (the request never transits
/// the relay), and keeps `request` (the claims, for [`validate`]) and
/// `enc_private_jwk` (to [`decrypt_response`]) for the rest of the session.
#[wasm_bindgen]
pub fn build_request(dcql_json: &str, response_uri: &str) -> Result<String, JsError> {
    let dcql: DcqlQuery = serde_json::from_str(dcql_json).map_err(err)?;
    let (nonce, state) = oid4vp::fresh_request_ids();
    let signed = oid4vp::build_signed_request(&dcql, &nonce, &state, response_uri);
    serde_json::to_string(&signed).map_err(err)
}

/// Decrypt an encrypted Authorization Response (`direct_post.jwt`) into the inner
/// VP Token, using the session's `enc_private_jwk` from [`build_request`]. Returns
/// the VP Token JSON, which the page then feeds to [`inspect`] + [`validate`].
#[wasm_bindgen]
pub fn decrypt_response(response_json: &str, enc_private_jwk_json: &str) -> Result<String, JsError> {
    let response = serde_json::from_str(response_json).map_err(err)?;
    let enc_private_jwk = serde_json::from_str(enc_private_jwk_json).map_err(err)?;
    let vp_token = oid4vp::decrypt_response(&response, &enc_private_jwk).map_err(err)?;
    serde_json::to_string(&vp_token).map_err(err)
}

/// Report the external URLs the verifier must fetch to validate a VP Token
/// (status lists). The page fetches these and passes the bytes back to
/// [`validate`]. Returns a JSON array of URL strings.
#[wasm_bindgen]
pub fn inspect(vp_token_json: &str) -> Result<String, JsError> {
    let vp_token = serde_json::from_str(vp_token_json).map_err(err)?;
    let urls = oid4vp::inspect(&vp_token).map_err(err)?;
    serde_json::to_string(&urls).map_err(err)
}

/// Validate a VP Token locally. `fetched_json` maps each URL (from [`inspect`])
/// to the text the page fetched for it. `anchors_json` is a JSON array of the
/// trusted CA-root PEM strings (the user's trust store) against which each
/// credential's `x5c` chain is anchored. Returns the verification report as JSON.
#[wasm_bindgen]
pub fn validate(
    request_json: &str,
    vp_token_json: &str,
    fetched_json: &str,
    anchors_json: &str,
) -> Result<String, JsError> {
    let request = serde_json::from_str(request_json).map_err(err)?;
    let vp_token = serde_json::from_str(vp_token_json).map_err(err)?;
    let fetched: HashMap<String, String> = serde_json::from_str(fetched_json).map_err(err)?;
    let anchor_pems: Vec<String> = serde_json::from_str(anchors_json).map_err(err)?;
    let trust = TrustStore::from_pems(&anchor_pems).map_err(err)?;

    let mut fetcher = MapFetcher::new();
    for (url, body) in fetched {
        fetcher.insert(url, body.into_bytes());
    }

    let report = oid4vp::validate_vp_token(&request, &vp_token, &fetcher, &trust);
    serde_json::to_string(&report).map_err(err)
}

/// The default trust anchors (a JSON array of PEM strings) the page seeds
/// `localStorage` with on first run — the bundled mock ICP-Brasil root. The PEM is
/// a compile-time constant, so we serialize it directly rather than round-tripping
/// through a `TrustStore` (which would parse + DER-encode + fingerprint it only to
/// hand back the same PEM).
#[wasm_bindgen]
pub fn default_anchors() -> String {
    serde_json::to_string(&[ssi_core::trust::ICP_BRASIL_MOCK_ROOT_PEM])
        .expect("default anchors serialize")
}

/// Inspect a pasted PEM certificate for the trust-anchor UI: returns
/// `{ "label": <subject CN>, "fingerprint": <sha256 hex> }`. Errors if the PEM is
/// not a valid CA certificate (so the UI can reject bad input).
#[wasm_bindgen]
pub fn anchor_info(pem: &str) -> Result<String, JsError> {
    let cert = Cert::from_pem(pem).map_err(err)?;
    if !cert.is_ca() {
        return Err(JsError::new(
            "certificate is not a CA and cannot be a trust anchor",
        ));
    }
    serde_json::to_string(&serde_json::json!({
        "label": cert.label(),
        "fingerprint": cert.fingerprint(),
    }))
    .map_err(err)
}

/// Render `text` (the full `openid4vp://` request URL — `client_id` + the signed
/// `request` JWT by value) as a QR code SVG, generated locally so the page needs
/// no external QR service. The request JWT is sizeable, so the QR is dense.
#[wasm_bindgen]
pub fn request_qr_svg(text: &str) -> Result<String, JsError> {
    use qrcode::QrCode;
    use qrcode::render::svg;
    let code = QrCode::new(text.as_bytes()).map_err(err)?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .build())
}

// ---------------------------------------------------------------------------
// Demo-only helper — a ready-made query for the page's "Request a credential"
// button. Presentation is driven by a real external holder (the Kotlin wallet or
// a phone), so no in-browser wallet simulation (and no issuer signing key) ships
// in this bundle.
// ---------------------------------------------------------------------------

/// A ready-made DCQL query for the demo: the holder's full name + degree title
/// from a university diploma credential. The `vct` is a stable URN (the diploma type
/// id) — it must match the issuer's `diploma::VCT`, so the demo works on any host with
/// no per-deployment edits.
#[wasm_bindgen]
pub fn demo_dcql() -> String {
    serde_json::json!({
        "credentials": [{
            "id": "diploma",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:tcc:mec:UniversityDiploma:1"] },
            "claims": [
                { "path": ["student", "full_name"] },
                { "path": ["degree", "title"] }
            ]
        }]
    })
    .to_string()
}

fn err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}
