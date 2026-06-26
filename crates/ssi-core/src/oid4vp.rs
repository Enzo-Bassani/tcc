//! OpenID for Verifiable Presentations 1.0 — the verifier's jobs: building a
//! **signed** Authorization Request (a `did:jwk` JAR carrying a DCQL query and an
//! ephemeral response-encryption key), and validating the VP Token that comes back
//! (after decrypting it).
//!
//! ## The `did:jwk` + encrypted-response model (the zero-knowledge relay)
//!
//! This verifier is an *unauthenticated web page* — it has no CA-issued
//! certificate, so HAIP's `x509_hash` signed-request profile doesn't apply, and a
//! relay sitting between verifier and wallet could otherwise swap either side's
//! keys. The fix uses the only tamper-proof channel available — the **QR code**:
//!
//! - The verifier mints an ephemeral P-256 **signing** key per session, encodes its
//!   public half as a `did:jwk`, and uses `decentralized_identifier:did:jwk:…` as
//!   the `client_id` (a standard OID4VP Client Identifier Prefix). The request is
//!   signed (JAR, RFC 9101) with that key. Because the `client_id` is carried in the
//!   QR (out of band) and the wallet resolves the key from it deterministically, a
//!   relay can neither forge the request nor swap the verifier's keys.
//! - A separate ephemeral **encryption** key (ECDH-ES P-256) rides in the signed
//!   request's `client_metadata.jwks`. The wallet encrypts the Authorization
//!   Response to it (`response_mode: direct_post.jwt`, see [`crate::jwe`]). Since the
//!   request is signed, that key is authentic → the response is confidential even
//!   against an active relay. This is a deliberate, documented deviation from HAIP
//!   (which assumes authenticated verifiers).
//!
//! The request goes to the wallet *by value in the QR* (it never transits the
//! relay), so the relay only ever carries the opaque encrypted response.
//! [`validate_vp_token`] still runs on the plaintext token, unchanged.

use anyhow::{Result, anyhow, bail};
use serde::Serialize;
use serde_json::{Value, json};

use crate::dcql::DcqlQuery;
use crate::resolve::Fetcher;
use crate::trust::TrustStore;
use crate::{crypto, jwe, sd_jwt, status, x509};

/// Issuer-signature algorithms the verifier advertises for `dc+sd-jwt`. With the
/// `x5c` trust model the issuer signs with ES256 only (HAIP §6.1.1); EdDSA issuer
/// credentials do not resolve a key and are rejected, so it is not advertised.
const SD_JWT_ISSUER_ALGS: [&str; 1] = ["ES256"];
/// Key-binding (holder) algorithms the verifier accepts. Holder keys may be
/// Ed25519 (EdDSA) or P-256 (ES256); `verify_jws_with_jwk` dispatches both.
const KB_JWT_ALGS: [&str; 2] = ["EdDSA", "ES256"];

/// Content-encryption algorithms the verifier advertises (HAIP §5: both MUST be
/// offered; the wallet SHOULD prefer A256GCM).
const ENCRYPTED_RESPONSE_ENC_VALUES: [&str; 2] = ["A256GCM", "A128GCM"];
/// The `kid` of the verifier's ephemeral response-encryption key within a request.
const ENC_KID: &str = "verifier-enc-1";

/// A freshly built, signed Authorization Request, plus the secrets the verifier
/// must keep for the rest of the session. Only `client_id` and `request_jwt` go on
/// the wire (in the QR); `request` and `enc_private_jwk` stay with the verifier.
#[derive(Debug, Clone, Serialize)]
pub struct SignedRequest {
    /// `decentralized_identifier:did:jwk:…` — a QR parameter; the wallet's trust anchor.
    pub client_id: String,
    /// The JAR JWT (the signed Request Object) — the other QR parameter.
    pub request_jwt: String,
    /// The request claims (the JWT payload). The verifier keeps this to pass to
    /// [`validate_vp_token`] once the response arrives.
    pub request: Value,
    /// The verifier's ephemeral ECDH-ES private JWK — kept to decrypt the response.
    pub enc_private_jwk: Value,
}

/// Build a **signed** OID4VP Authorization Request with a `did:jwk` verifier
/// identity (JAR) and an ephemeral response-encryption key. See the module docs.
pub fn build_signed_request(
    dcql: &DcqlQuery,
    nonce: &str,
    state: &str,
    response_uri: &str,
) -> SignedRequest {
    // Ephemeral signing key → did:jwk → client_id (the QR-anchored trust root).
    let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let signing_jwk = crypto::es256_public_jwk(&signing);
    let did = did_jwk_for(&signing_jwk);
    let client_id = format!("decentralized_identifier:{did}");

    // Ephemeral encryption key, advertised in client_metadata.jwks (`use:enc`).
    let (enc_private_jwk, mut enc_pub) = jwe::gen_enc_keypair();
    let enc_obj = enc_pub.as_object_mut().expect("enc JWK is an object");
    enc_obj.insert("use".into(), json!("enc"));
    enc_obj.insert("alg".into(), json!("ECDH-ES"));
    enc_obj.insert("kid".into(), json!(ENC_KID));

    let request = json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "client_id": client_id,
        "response_uri": response_uri,
        "nonce": nonce,
        "state": state,
        "dcql_query": dcql,
        "client_metadata": {
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": SD_JWT_ISSUER_ALGS,
                    "kb-jwt_alg_values": KB_JWT_ALGS,
                }
            },
            "jwks": { "keys": [ enc_pub ] },
            "encrypted_response_enc_values_supported": ENCRYPTED_RESPONSE_ENC_VALUES,
        }
    });

    // Sign as a JAR JWT (RFC 9101). The `kid` points at the did:jwk verification method.
    let header = json!({ "alg": "ES256", "kid": format!("{did}#0"), "typ": "oauth-authz-req+jwt" });
    let request_jwt = crypto::sign_jws_es256(&header, &request, &signing);

    SignedRequest { client_id, request_jwt, request, enc_private_jwk }
}

/// Encode an EC P-256 public JWK as a `did:jwk` (the key is embedded in the DID,
/// so resolution is deterministic and needs no network — see the did:jwk method).
pub fn did_jwk_for(public_jwk: &Value) -> String {
    let bytes = serde_json::to_vec(public_jwk).expect("JWK serializes");
    format!("did:jwk:{}", crypto::b64url(&bytes))
}

/// Resolve a `did:jwk` (or a `decentralized_identifier:did:jwk:…` client_id, with
/// an optional `#fragment`) back to its embedded public JWK.
pub fn resolve_did_jwk(id: &str) -> Result<Value> {
    let did = id.strip_prefix("decentralized_identifier:").unwrap_or(id);
    let suffix = did
        .strip_prefix("did:jwk:")
        .ok_or_else(|| anyhow!("not a did:jwk identifier"))?;
    let suffix = suffix.split('#').next().unwrap_or(suffix);
    let bytes = crypto::b64url_decode(suffix)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Verify a JAR Request Object (wallet side) and return its request claims.
///
/// `expected_client_id` is the `client_id` the wallet read **from the QR** (the
/// out-of-band trust anchor). This checks that the signed request's `client_id`
/// matches it, resolves the `did:jwk` from it, and verifies the ES256 signature
/// against that key — so a tampered or relay-injected request is rejected.
pub fn verify_request(request_jwt: &str, expected_client_id: &str) -> Result<Value> {
    let signing_jwk = resolve_did_jwk(expected_client_id)?;
    let (_header, payload) = crypto::verify_jws_with_jwk(request_jwt, &signing_jwk)?;
    let embedded = payload.get("client_id").and_then(Value::as_str).unwrap_or_default();
    if embedded != expected_client_id {
        bail!("request client_id does not match the QR client_id");
    }
    Ok(payload)
}

/// Decrypt an Authorization Response into the inner VP Token, using the verifier's
/// ephemeral encryption private key. Accepts the encrypted form
/// `{"response":"<JWE>"}` (`direct_post.jwt`); if the response is already a plain
/// `{"vp_token":…}` it is returned as-is (tolerated for tests).
pub fn decrypt_response(response: &Value, enc_private_jwk: &Value) -> Result<Value> {
    if let Some(jwe_compact) = response.get("response").and_then(Value::as_str) {
        let plaintext = jwe::decrypt(jwe_compact, enc_private_jwk)?;
        let params: Value = serde_json::from_slice(&plaintext)?;
        return params
            .get("vp_token")
            .cloned()
            .ok_or_else(|| anyhow!("decrypted response has no vp_token"));
    }
    response
        .get("vp_token")
        .cloned()
        .ok_or_else(|| anyhow!("response is neither an encrypted JWE nor a vp_token"))
}

/// A fresh nonce + state pair for a request (128-bit entropy each).
pub fn fresh_request_ids() -> (String, String) {
    (crypto::random_b64url(16), crypto::random_b64url(16))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// The result of one validation check.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", content = "detail", rename_all = "lowercase")]
pub enum Check {
    Pass,
    Fail(String),
    Skipped(String),
}

impl Check {
    fn is_ok(&self) -> bool {
        !matches!(self, Check::Fail(_))
    }
}

/// Per-credential verification outcome.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialResult {
    pub query_id: String,
    pub issuer: Option<String>,
    pub vct: Option<String>,
    pub issuer_signature: Check,
    pub holder_binding: Check,
    pub dcql_satisfied: Check,
    pub revocation: Check,
    pub trusted_issuer: Check,
    pub disclosed_claims: Value,
}

impl CredentialResult {
    fn all_ok(&self) -> bool {
        self.issuer_signature.is_ok()
            && self.holder_binding.is_ok()
            && self.dcql_satisfied.is_ok()
            && self.revocation.is_ok()
            && self.trusted_issuer.is_ok()
    }
}

/// The full report for a VP Token.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    pub valid: bool,
    pub credentials: Vec<CredentialResult>,
    pub errors: Vec<String>,
}

/// The external documents the verifier needs to fetch to validate a VP Token:
/// any referenced status lists. (The issuer key comes from the `x5c` chain
/// carried in the credential itself, so no DID documents are fetched.) In the
/// browser, JS fetches these and supplies them via a `MapFetcher`; natively the
/// `HttpFetcher` retrieves them on demand. Either way validation is identical.
pub fn inspect(vp_token: &Value) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    for presentations in vp_token_entries(vp_token) {
        for pres in presentations {
            let parsed = sd_jwt::split_presentation(pres)?;
            let (_, payload) = crypto::decode_jws_unverified(&parsed.issuer_jwt)?;
            // Reconstruct (unverified) to find a status reference.
            if let Ok(full) = sd_jwt::reconstruct_claims(&payload, &parsed.disclosures)
                && let Some((uri, _)) = status::status_reference(&full)
            {
                push_unique(&mut urls, uri);
            }
        }
    }
    Ok(urls)
}

/// Validate a VP Token against the request that produced it. `trust` is the
/// verifier's set of trusted CA roots, against which each credential's `x5c`
/// chain is anchored (the `trusted_issuer` check).
pub fn validate_vp_token(
    request: &Value,
    vp_token: &Value,
    fetcher: &dyn Fetcher,
    trust: &TrustStore,
) -> VerificationReport {
    let mut errors = Vec::new();

    let dcql: DcqlQuery = match request.get("dcql_query").cloned().map(serde_json::from_value) {
        Some(Ok(q)) => q,
        _ => {
            return VerificationReport {
                valid: false,
                credentials: Vec::new(),
                errors: vec!["request has no valid dcql_query".into()],
            };
        }
    };
    let nonce = request.get("nonce").and_then(Value::as_str).unwrap_or_default();
    let client_id = request.get("client_id").and_then(Value::as_str).unwrap_or_default();
    // Sample the clock once so every credential in the token is evaluated at a
    // single instant (certificate validity is otherwise checked per-credential).
    let now = chrono::Utc::now().timestamp();

    let Some(token_obj) = vp_token.as_object() else {
        return VerificationReport {
            valid: false,
            credentials: Vec::new(),
            errors: vec!["vp_token must be a JSON object keyed by credential id".into()],
        };
    };

    let mut credentials = Vec::new();
    let mut present_ids = Vec::new();

    for (query_id, presentations) in token_obj {
        let Some(query) = dcql.credential(query_id) else {
            errors.push(format!("vp_token contains unrequested credential id '{query_id}'"));
            continue;
        };
        let Some(list) = presentations.as_array() else {
            errors.push(format!("vp_token['{query_id}'] must be an array of presentations"));
            continue;
        };
        for pres in list {
            let Some(pres) = pres.as_str() else {
                errors.push(format!("presentation under '{query_id}' is not a string"));
                continue;
            };
            let result = verify_one(query, pres, nonce, client_id, fetcher, trust, now);
            if result.all_ok() && !present_ids.contains(query_id) {
                present_ids.push(query_id.clone());
            }
            credentials.push(result);
        }
    }

    let overall_satisfied = dcql.overall_satisfied(&present_ids);
    if !overall_satisfied {
        errors.push("the presented credentials do not satisfy the DCQL credential_sets".into());
    }
    let valid = errors.is_empty()
        && !credentials.is_empty()
        && credentials.iter().all(CredentialResult::all_ok)
        && overall_satisfied;

    VerificationReport {
        valid,
        credentials,
        errors,
    }
}

/// Verify a single SD-JWT VC presentation, producing a per-check result. Each
/// check is recorded independently so the report can show exactly what failed.
fn verify_one(
    query: &crate::dcql::CredentialQuery,
    pres: &str,
    nonce: &str,
    client_id: &str,
    fetcher: &dyn Fetcher,
    trust: &TrustStore,
    now: i64,
) -> CredentialResult {
    let parsed = match sd_jwt::split_presentation(pres) {
        Ok(p) => p,
        Err(e) => {
            return error_result(query, format!("malformed SD-JWT: {e}"));
        }
    };
    let (issuer_header, issuer_payload) = match crypto::decode_jws_unverified(&parsed.issuer_jwt) {
        Ok(v) => v,
        Err(e) => return error_result(query, format!("undecodable issuer JWT: {e}")),
    };
    let issuer = issuer_payload.get("iss").and_then(Value::as_str).map(String::from);
    let vct = issuer_payload.get("vct").and_then(Value::as_str).map(String::from);

    // Reconstruct the disclosed claim set (used by several checks below).
    let disclosed = sd_jwt::reconstruct_claims(&issuer_payload, &parsed.disclosures)
        .unwrap_or_else(|_| issuer_payload.clone());

    // Resolve the issuer key from the `x5c` chain and decide trust (HAIP §6.1.1).
    // The leaf certificate's key verifies the issuer signature regardless of
    // trust; `trusted_issuer` separately attests that the leaf chains up to a
    // trusted CA root AND that `iss` is bound to the leaf certificate.
    let (issuer_jwk, trusted_issuer): (Result<Value>, Check) =
        match issuer_header.get("x5c").map(x509::parse_x5c) {
            None => (
                Err(anyhow!("issuer JWT has no x5c header")),
                Check::Fail("issuer JWT has no x5c certificate chain".into()),
            ),
            Some(Err(e)) => (
                Err(anyhow!("invalid x5c: {e:#}")),
                Check::Fail(format!("invalid x5c certificate chain: {e:#}")),
            ),
            Some(Ok(chain)) => {
                let leaf_jwk = chain[0].public_jwk();
                let trust_check = match x509::validate_chain(&chain, trust.anchor_certs(), now) {
                    Err(e) => Check::Fail(format!("untrusted issuer certificate chain: {e:#}")),
                    Ok(()) => match issuer.as_deref() {
                        Some(iss) => match x509::iss_matches_leaf(iss, &chain[0]) {
                            Ok(()) => Check::Pass,
                            Err(e) => Check::Fail(e.to_string()),
                        },
                        // No `iss` claim: the issuer is the leaf certificate subject.
                        None => Check::Pass,
                    },
                };
                (leaf_jwk, trust_check)
            }
        };
    let issuer_signature = match &issuer_jwk {
        Ok(jwk) => match sd_jwt::verify_issuer_signature(&parsed.issuer_jwt, jwk) {
            Ok(_) => Check::Pass,
            Err(e) => Check::Fail(e.to_string()),
        },
        Err(e) => Check::Fail(format!("issuer key not established: {e}")),
    };

    // 2. Holder binding — key-binding JWT bound to nonce + client_id + sd_hash.
    let holder_binding = if query.requires_holder_binding() {
        match &parsed.key_binding_jwt {
            None => Check::Fail("holder binding required but no key-binding JWT present".into()),
            Some(kb) => match issuer_payload.get("cnf").and_then(|c| c.get("jwk")) {
                None => Check::Fail("credential has no cnf.jwk to bind against".into()),
                Some(cnf_jwk) => {
                    let expect = sd_jwt::KeyBindingExpectations {
                        nonce,
                        audience: client_id,
                        sd_hash: &parsed.sd_hash,
                    };
                    match sd_jwt::verify_key_binding(kb, cnf_jwk, &expect) {
                        Ok(()) => Check::Pass,
                        Err(e) => Check::Fail(e.to_string()),
                    }
                }
            },
        }
    } else {
        Check::Skipped("holder binding waived by query".into())
    };

    // 3. DCQL satisfaction — does the disclosed claim set answer the query?
    let dcql_satisfied = match query.resolve_required_paths(&disclosed) {
        Some(_) => Check::Pass,
        None => Check::Fail("disclosed claims do not satisfy the credential query".into()),
    };

    // 4. Revocation — Token Status List. The status list establishes its own
    //    trust (its `x5c` chain + `iss` identity), so the issuer's signing key can
    //    rotate without invalidating already-issued credentials.
    let revocation = match status::status_reference(&disclosed) {
        None => Check::Skipped("no status reference".into()),
        Some((uri, idx)) => match fetcher.get(&uri) {
            Ok(bytes) => match String::from_utf8(bytes)
                .map_err(anyhow::Error::from)
                .and_then(|jwt| status::check_status(&jwt, idx, trust, now, issuer.as_deref()))
            {
                Ok(status::StatusCheck::Valid) => Check::Pass,
                Ok(status::StatusCheck::Revoked) => Check::Fail("credential is revoked".into()),
                Err(e) => Check::Fail(format!("status check failed: {e}")),
            },
            Err(e) => Check::Fail(format!("could not fetch status list: {e}")),
        },
    };

    CredentialResult {
        query_id: query.id.clone(),
        issuer,
        vct,
        issuer_signature,
        holder_binding,
        dcql_satisfied,
        revocation,
        trusted_issuer,
        disclosed_claims: disclosed,
    }
}

fn error_result(query: &crate::dcql::CredentialQuery, msg: String) -> CredentialResult {
    CredentialResult {
        query_id: query.id.clone(),
        issuer: None,
        vct: None,
        issuer_signature: Check::Fail(msg),
        holder_binding: Check::Fail("not checked".into()),
        dcql_satisfied: Check::Fail("not checked".into()),
        revocation: Check::Skipped("not checked".into()),
        trusted_issuer: Check::Skipped("not checked".into()),
        disclosed_claims: Value::Null,
    }
}

fn vp_token_entries(vp_token: &Value) -> Vec<Vec<&str>> {
    vp_token
        .as_object()
        .map(|obj| {
            obj.values()
                .filter_map(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                .collect()
        })
        .unwrap_or_default()
}

fn push_unique(urls: &mut Vec<String>, url: String) {
    if !urls.contains(&url) {
        urls.push(url);
    }
}
