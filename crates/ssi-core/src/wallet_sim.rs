//! A simulated holder (wallet), used to exercise the OID4VP flow end to end in
//! tests and the demo — the real wallet will be a separate Kotlin app.
//!
//! Given an Authorization Request and the credentials it holds, the wallet:
//! 1. matches each DCQL credential query to a held credential (format + `vct`);
//! 2. picks the minimal disclosures that satisfy the query (honoring `claim_sets`);
//! 3. builds a key-binding JWT bound to the request `nonce` + `client_id` + `sd_hash`;
//! 4. assembles the VP Token object `{ "<query id>": ["<sd-jwt+kb>"] }`.

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::dcql::DcqlQuery;
use crate::holder::HolderKey;
use crate::{crypto, jwe, sd_jwt};

/// One credential the wallet holds: the issued SD-JWT (issuer JWT + all
/// disclosures, no key binding) and the holder key matching its `cnf`.
pub struct StoredCredential {
    pub sd_jwt: String,
    pub holder: HolderKey,
}

impl StoredCredential {
    /// The reconstructed full claim set (all disclosures applied).
    fn full_claims(&self) -> Result<Value> {
        let (issuer_jwt, disclosures) = sd_jwt::split(&self.sd_jwt);
        let (_h, payload) = crypto::decode_jws_unverified(&issuer_jwt)?;
        sd_jwt::reconstruct_claims(&payload, &disclosures)
    }
}

/// Build a VP Token answering `request` with the wallet's credentials.
///
/// All-or-nothing per the spec: if a non-optional credential query can't be
/// satisfied, this returns an error and no token (the real wallet would surface
/// `access_denied`).
pub fn create_vp_token(request: &Value, wallet: &[StoredCredential]) -> Result<Value> {
    let dcql: DcqlQuery = serde_json::from_value(
        request
            .get("dcql_query")
            .ok_or_else(|| anyhow!("request has no dcql_query"))?
            .clone(),
    )?;
    let nonce = request
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("request has no nonce"))?;
    let client_id = request
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("request has no client_id"))?;

    let mut vp_token = Map::new();

    for query in &dcql.credentials {
        // Find a held credential that satisfies this query.
        let mut presented = None;
        for cred in wallet {
            let full = cred.full_claims()?;
            if let Some(required) = query.resolve_required_paths(&full) {
                let paths: Vec<&[Value]> = required.claims.iter().map(|c| c.path.as_slice()).collect();
                presented = Some(present(cred, &paths, nonce, client_id)?);
                break;
            }
        }
        match presented {
            Some(p) => {
                vp_token.insert(query.id.clone(), json!([p]));
            }
            None => {
                // Only required queries are fatal; without credential_sets every
                // query is required.
                let optional = dcql
                    .credential_sets
                    .as_ref()
                    .map(|sets| !sets.iter().any(|s| s.is_required() && set_mentions(s, &query.id)))
                    .unwrap_or(false);
                if !optional {
                    return Err(anyhow!(
                        "no held credential satisfies required query '{}'",
                        query.id
                    ));
                }
            }
        }
    }

    Ok(Value::Object(vp_token))
}

fn set_mentions(set: &crate::dcql::CredentialSetQuery, id: &str) -> bool {
    set.options.iter().any(|o| o.iter().any(|i| i == id))
}

/// Build the full **Authorization Response** for a (verified) request, honoring
/// its `response_mode`. For `direct_post.jwt` this JWE-encrypts `{vp_token, state}`
/// to the verifier's ephemeral key from `client_metadata.jwks` and returns
/// `{"response":"<JWE>"}`; otherwise it returns the plain `{"vp_token":…, "state":…}`.
///
/// The wallet calls this *after* [`crate::oid4vp::verify_request`] has authenticated
/// the request (did:jwk JAR) — never on an unverified request object.
pub fn create_response(request: &Value, wallet: &[StoredCredential]) -> Result<Value> {
    let vp_token = create_vp_token(request, wallet)?;
    encrypt_response(request, vp_token)
}

/// Wrap an already-built VP Token as the Authorization Response, honoring the
/// request's `response_mode` (JWE for `direct_post.jwt`, plain otherwise). Split
/// out from [`create_response`] so callers can build/alter the token first.
pub fn encrypt_response(request: &Value, vp_token: Value) -> Result<Value> {
    let state = request.get("state").and_then(Value::as_str).unwrap_or_default();

    let encrypted = request.get("response_mode").and_then(Value::as_str) == Some("direct_post.jwt");
    if !encrypted {
        return Ok(json!({ "vp_token": vp_token, "state": state }));
    }

    let (enc_jwk, kid) = verifier_enc_key(request)?;
    let enc_alg = pick_enc_alg(request);
    let params = json!({ "vp_token": vp_token, "state": state });
    let jwe_compact = jwe::encrypt(&enc_jwk, &kid, enc_alg, &serde_json::to_vec(&params)?)?;
    Ok(json!({ "response": jwe_compact }))
}

/// The verifier's response-encryption key from `client_metadata.jwks`: the first
/// JWK marked `use:enc`, returned with its `kid`.
fn verifier_enc_key(request: &Value) -> Result<(Value, String)> {
    let keys = request
        .pointer("/client_metadata/jwks/keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("request has no client_metadata.jwks.keys for response encryption"))?;
    for key in keys {
        if key.get("use").and_then(Value::as_str) == Some("enc") {
            let kid = key.get("kid").and_then(Value::as_str).unwrap_or_default().to_string();
            return Ok((key.clone(), kid));
        }
    }
    bail!("no use:enc key in client_metadata.jwks")
}

/// Pick the content-encryption algorithm: prefer A256GCM (HAIP), else the first
/// supported value the verifier advertised, else the A128GCM default.
fn pick_enc_alg(request: &Value) -> &'static str {
    // A256GCM preferred (HAIP); otherwise A128GCM — the default when unadvertised.
    let advertises_a256 = request
        .pointer("/client_metadata/encrypted_response_enc_values_supported")
        .and_then(Value::as_array)
        .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("A256GCM")));
    if advertises_a256 { "A256GCM" } else { "A128GCM" }
}

/// Build one SD-JWT presentation: select disclosures matching `paths`, then
/// append a key-binding JWT bound to nonce + audience + sd_hash.
fn present(
    cred: &StoredCredential,
    paths: &[&[Value]],
    nonce: &str,
    client_id: &str,
) -> Result<String> {
    let (issuer_jwt, all_disclosures) = sd_jwt::split(&cred.sd_jwt);

    // The leaf (last) element of each requested path is the claim name; select
    // the disclosures whose name matches one of them. (Our issuer emits one
    // disclosure per leaf claim, so name matching is sufficient.)
    let wanted: Vec<&str> = paths
        .iter()
        .filter_map(|p| p.last())
        .filter_map(Value::as_str)
        .collect();

    let mut selected = Vec::new();
    for enc in &all_disclosures {
        let (_salt, name, _value) = sd_jwt::decode_disclosure(enc)?;
        if wanted.contains(&name.as_str()) {
            selected.push(enc.clone());
        }
    }

    // Assemble issuer JWT + selected disclosures, each followed by '~'.
    let mut presentation = issuer_jwt.clone();
    for enc in &selected {
        presentation.push('~');
        presentation.push_str(enc);
    }
    presentation.push('~');

    // sd_hash is over exactly those bytes (everything before the KB-JWT).
    let sd_hash = crypto::b64url(&crypto::sha256(presentation.as_bytes()));
    let kb = build_kb_jwt(&cred.holder, nonce, client_id, &sd_hash);
    presentation.push_str(&kb);
    Ok(presentation)
}

fn build_kb_jwt(holder: &HolderKey, nonce: &str, aud: &str, sd_hash: &str) -> String {
    let header = json!({ "typ": "kb+jwt" });
    let payload = json!({
        "iat": chrono::Utc::now().timestamp(),
        "aud": aud,
        "nonce": nonce,
        "sd_hash": sd_hash,
    });
    holder.sign_jws(&header, &payload)
}
