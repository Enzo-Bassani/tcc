//! A simulated holder (wallet), used to exercise the OID4VP flow end to end in
//! tests and the demo — the real wallet will be a separate Kotlin app.
//!
//! Given an Authorization Request and the credentials it holds, the wallet:
//! 1. matches each DCQL credential query to a held credential (format + `vct`);
//! 2. picks the minimal disclosures that satisfy the query (honoring `claim_sets`);
//! 3. builds a key-binding JWT bound to the request `nonce` + `client_id` + `sd_hash`;
//! 4. assembles the VP Token object `{ "<query id>": ["<sd-jwt+kb>"] }`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::dcql::{DcqlQuery, select};
use crate::holder::{Signer, sign_jws_with};
use crate::{crypto, jwe, sd_jwt};

/// One credential the wallet holds: the issued SD-JWT (issuer JWT + all
/// disclosures, no key binding) and the [`Signer`] for the holder key matching its
/// `cnf`. The signer is shared (`Arc`) because the wallet binds every credential to
/// the same device key.
pub struct StoredCredential {
    pub sd_jwt: String,
    pub holder: Arc<dyn Signer>,
}

impl StoredCredential {
    /// Pair a stored SD-JWT with the holder [`Signer`] whose key it is bound to.
    pub fn new(sd_jwt: impl Into<String>, holder: Arc<dyn Signer>) -> Self {
        Self { sd_jwt: sd_jwt.into(), holder }
    }

    /// The reconstructed full claim set (all disclosures applied).
    fn full_claims(&self) -> Result<Value> {
        let (issuer_jwt, disclosures) = sd_jwt::split(&self.sd_jwt);
        let (_h, payload) = crypto::decode_jws_unverified(&issuer_jwt)?;
        sd_jwt::reconstruct_claims(&payload, &disclosures)
    }
}

/// Build a VP Token answering `request` with the wallet's credentials, picking the
/// first held credential that satisfies each query. See [`create_vp_token_selecting`]
/// to honor a holder's explicit credential choice.
///
/// All-or-nothing per the spec: if a non-optional credential query can't be
/// satisfied, this returns an error and no token (the real wallet would surface
/// `access_denied`).
pub fn create_vp_token(request: &Value, wallet: &[StoredCredential]) -> Result<Value> {
    create_vp_token_selecting(request, wallet, &HashMap::new())
}

/// Like [`create_vp_token`], but `selection` maps a DCQL query id to the **index**
/// (into `wallet`) of the credential the holder chose for it. Queries absent from
/// the map fall back to the first held credential that satisfies them.
pub fn create_vp_token_selecting(
    request: &Value,
    wallet: &[StoredCredential],
    selection: &HashMap<String, usize>,
) -> Result<Value> {
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
        // Try the holder's chosen credential first (if any and it satisfies the
        // query), then fall back to the rest in order.
        let mut presented = None;
        for &i in &candidate_order(wallet.len(), selection.get(&query.id).copied()) {
            let cred = &wallet[i];
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

/// The order to try credentials for a query: the holder's `chosen` index first
/// (when in range), then every other index in their natural order.
fn candidate_order(len: usize, chosen: Option<usize>) -> Vec<usize> {
    match chosen {
        Some(c) if c < len => {
            let mut order = Vec::with_capacity(len);
            order.push(c);
            order.extend((0..len).filter(|&i| i != c));
            order
        }
        _ => (0..len).collect(),
    }
}

/// Build the full **Authorization Response** for a (verified) request, honoring
/// its `response_mode`. For `direct_post.jwt` this JWE-encrypts `{vp_token, state}`
/// to the verifier's ephemeral key from `client_metadata.jwks` and returns
/// `{"response":"<JWE>"}`; otherwise it returns the plain `{"vp_token":…, "state":…}`.
///
/// The wallet calls this *after* [`crate::oid4vp::verify_request`] has authenticated
/// the request (did:jwk JAR) — never on an unverified request object.
pub fn create_response(request: &Value, wallet: &[StoredCredential]) -> Result<Value> {
    create_response_selecting(request, wallet, &HashMap::new())
}

/// Like [`create_response`], but honoring the holder's per-query credential
/// `selection` (DCQL query id → index into `wallet`). See [`create_vp_token_selecting`].
pub fn create_response_selecting(
    request: &Value,
    wallet: &[StoredCredential],
    selection: &HashMap<String, usize>,
) -> Result<Value> {
    let vp_token = create_vp_token_selecting(request, wallet, selection)?;
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
    let kb = build_kb_jwt(cred.holder.as_ref(), nonce, client_id, &sd_hash)?;
    presentation.push_str(&kb);
    Ok(presentation)
}

fn build_kb_jwt(signer: &dyn Signer, nonce: &str, aud: &str, sd_hash: &str) -> Result<String> {
    let header = json!({ "typ": "kb+jwt" });
    let payload = json!({
        "iat": chrono::Utc::now().timestamp(),
        "aud": aud,
        "nonce": nonce,
        "sd_hash": sd_hash,
    });
    sign_jws_with(&header, &payload, signer)
}

/// One disclosed (or always-shared) claim as raw structured data: the claim
/// `path` (string segments) and its JSON `value`. Humanized labels and value
/// formatting are the wallet UI's job — the engine returns only the structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDisclosure {
    pub path: Vec<String>,
    pub value: Value,
}

/// A held credential that satisfies a DCQL credential query, with what it would
/// reveal if chosen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedCredential {
    /// Index of this credential in the wallet slice — the selection key.
    pub index: usize,
    /// The credential's own `vct`, if present.
    pub vct: Option<String>,
    /// The selectively-disclosable claims this query would disclose.
    pub disclosed: Vec<ClaimDisclosure>,
    /// The non-selectively-disclosable issuer-JWT payload claims that travel with
    /// every presentation (top-level entries minus the `_sd` machinery and minus
    /// anything already in `disclosed`); the holder cannot withhold these.
    pub always_shared: Vec<ClaimDisclosure>,
}

/// All held credentials that satisfy one DCQL credential query. More than one
/// match is what drives the wallet's "choose which credential to present" step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMatch {
    pub query_id: String,
    /// The query's requested `vct` (its `meta.vct_values[0]`), if any.
    pub vct: Option<String>,
    pub matches: Vec<MatchedCredential>,
}

/// For each DCQL credential query in `request`, every held credential that can
/// satisfy it, together with the claims it would disclose and the claims it
/// always shares. Drives the consent / credential-choice UI; it never signs and
/// never builds a presentation.
/// `sd_jwts` are the held credentials as compact SD-JWT strings (the wallet's
/// storage form); a match's `index` points back into this slice. This is a
/// read-only inspection — it decodes but never signs — so it takes no signer.
pub fn find_matches(request: &Value, sd_jwts: &[String]) -> Result<Vec<QueryMatch>> {
    let dcql: DcqlQuery = serde_json::from_value(
        request
            .get("dcql_query")
            .ok_or_else(|| anyhow!("request has no dcql_query"))?
            .clone(),
    )?;

    let mut out = Vec::new();
    for query in &dcql.credentials {
        let query_vct = query
            .meta
            .as_ref()
            .and_then(|m| m.vct_values.as_ref())
            .and_then(|values| values.first())
            .cloned();

        let mut matches = Vec::new();
        for (index, sd_jwt) in sd_jwts.iter().enumerate() {
            let (issuer_jwt, disclosures) = sd_jwt::split(sd_jwt);
            let (_h, payload) = crypto::decode_jws_unverified(&issuer_jwt)?;
            let full = sd_jwt::reconstruct_claims(&payload, &disclosures)?;
            let Some(required) = query.resolve_required_paths(&full) else {
                continue;
            };

            let disclosed: Vec<ClaimDisclosure> = required
                .claims
                .iter()
                .map(|c| ClaimDisclosure {
                    path: c.path.iter().map(path_segment).collect(),
                    value: select(&full, &c.path).first().map(|v| (*v).clone()).unwrap_or(Value::Null),
                })
                .collect();
            let disclosed_paths: HashSet<Vec<String>> = disclosed.iter().map(|d| d.path.clone()).collect();

            matches.push(MatchedCredential {
                index,
                vct: full.get("vct").and_then(Value::as_str).map(String::from),
                always_shared: always_shared_claims(&payload, &disclosed_paths),
                disclosed,
            });
        }
        out.push(QueryMatch { query_id: query.id.clone(), vct: query_vct, matches });
    }
    Ok(out)
}

/// Stringify one DCQL path element to a display path segment (string keys pass
/// through; numbers/null stringify), matching the wallet's claim-path display.
fn path_segment(element: &Value) -> String {
    match element {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// The issuer-JWT payload's top-level entries that travel with every
/// presentation: everything except the `_sd`/`_sd_alg` machinery and anything
/// already disclosed. Values are raw — the UI labels and formats them.
fn always_shared_claims(payload: &Value, disclosed_paths: &HashSet<Vec<String>>) -> Vec<ClaimDisclosure> {
    let Some(obj) = payload.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, value) in obj {
        if key.as_str() == "_sd" || key.as_str() == "_sd_alg" {
            continue;
        }
        let path = vec![key.clone()];
        if disclosed_paths.contains(&path) {
            continue;
        }
        out.push(ClaimDisclosure { path, value: value.clone() });
    }
    out
}
