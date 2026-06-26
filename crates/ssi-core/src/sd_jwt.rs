//! Minimal SD-JWT implementation (IETF SD-JWT).
//!
//! A credential is `<issuer-JWT>~<disclosure>~<disclosure>~...~`. Each disclosure
//! is `base64url(JSON([salt, claim_name, claim_value]))`; the issuer JWT carries
//! the SHA-256 digest of each disclosure inside an `_sd` array on the claim's
//! parent object.

use anyhow::{Result, anyhow};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

use crate::crypto::{b64url, b64url_decode, decode_jws_unverified, random_b64url, sha256};

/// A single disclosure: its encoded form, its digest, and the claim name.
#[derive(Debug, Clone)]
pub struct Disclosure {
    pub encoded: String,
    pub digest: String,
}

fn make_disclosure(name: &str, value: &Value) -> Disclosure {
    let salt = random_b64url(16);
    let arr = Value::Array(vec![
        Value::String(salt),
        Value::String(name.to_string()),
        value.clone(),
    ]);
    let encoded = b64url(serde_json::to_string(&arr).unwrap().as_bytes());
    let digest = b64url(&sha256(encoded.as_bytes()));
    Disclosure { encoded, digest }
}

/// Walk to the object at a dotted path's parent; returns `&mut` to that object.
fn parent_object<'a>(root: &'a mut Value, parts: &[&str]) -> Option<&'a mut Map<String, Value>> {
    let mut cur = root;
    for p in &parts[..parts.len() - 1] {
        cur = cur.get_mut(*p)?;
    }
    cur.as_object_mut()
}

/// Convert the claims at each dotted `path` into SD-JWT disclosures, mutating
/// `claims` in place (claims are removed and replaced by `_sd` digests). A
/// top-level `_sd_alg` is added. Returns the disclosures to append to the JWT.
pub fn make_selectively_disclosable<S: AsRef<str>>(
    claims: &mut Value,
    paths: &[S],
) -> Vec<Disclosure> {
    let mut disclosures = Vec::new();
    for path in paths {
        let parts: Vec<&str> = path.as_ref().split('.').collect();
        let Some(obj) = parent_object(claims, &parts) else {
            continue;
        };
        let leaf = parts[parts.len() - 1];
        if let Some(value) = obj.remove(leaf) {
            let d = make_disclosure(leaf, &value);
            obj.entry("_sd")
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .unwrap()
                .push(Value::String(d.digest.clone()));
            disclosures.push(d);
        }
    }
    if let Some(root) = claims.as_object_mut() {
        root.insert("_sd_alg".into(), json!("sha-256"));
    }
    disclosures
}

/// Assemble the compact SD-JWT: issuer JWT followed by `~`-joined disclosures
/// and a trailing `~`.
pub fn assemble(issuer_jwt: &str, disclosures: &[Disclosure]) -> String {
    let mut out = String::from(issuer_jwt);
    for d in disclosures {
        out.push('~');
        out.push_str(&d.encoded);
    }
    out.push('~');
    out
}

/// Split a compact SD-JWT into `(issuer_jwt, disclosures)`, dropping an optional
/// trailing key-binding JWT and empty segments.
pub fn split(sd_jwt: &str) -> (String, Vec<String>) {
    let mut parts = sd_jwt.split('~');
    let issuer_jwt = parts.next().unwrap_or("").to_string();
    let disclosures = parts.filter(|s| !s.is_empty()).map(String::from).collect();
    (issuer_jwt, disclosures)
}

/// A presented SD-JWT decomposed into issuer JWT, disclosures, and an optional
/// key-binding JWT. The compact form is `<issuer-jwt>~<d1>~..~<dn>~[<kb-jwt>]`:
/// everything after the final `~` is the key-binding JWT (empty if absent).
pub struct Presentation {
    pub issuer_jwt: String,
    pub disclosures: Vec<String>,
    pub key_binding_jwt: Option<String>,
    /// The exact bytes the key-binding `sd_hash` is computed over: the issuer JWT
    /// and disclosures, each terminated by `~` (i.e. the input minus the KB-JWT).
    pub sd_hash: String,
}

/// Split a presented SD-JWT (KB-aware), unlike [`split`] which folds the KB-JWT
/// in with the disclosures.
pub fn split_presentation(sd_jwt: &str) -> Result<Presentation> {
    let last_tilde = sd_jwt
        .rfind('~')
        .ok_or_else(|| anyhow!("not an SD-JWT (no '~')"))?;
    let (prefix, kb) = sd_jwt.split_at(last_tilde + 1); // prefix keeps the trailing '~'
    let key_binding_jwt = if kb.is_empty() {
        None
    } else {
        Some(kb.to_string())
    };

    let mut segs = prefix.trim_end_matches('~').split('~');
    let issuer_jwt = segs.next().unwrap_or("").to_string();
    let disclosures = segs.filter(|s| !s.is_empty()).map(String::from).collect();

    Ok(Presentation {
        issuer_jwt,
        disclosures,
        key_binding_jwt,
        sd_hash: b64url(&sha256(prefix.as_bytes())),
    })
}

/// What the key-binding JWT must prove: this presentation was made for this
/// verifier (`aud` = client_id) and this transaction (`nonce`), over these
/// exact disclosures (`sd_hash`).
pub struct KeyBindingExpectations<'a> {
    pub nonce: &'a str,
    pub audience: &'a str,
    pub sd_hash: &'a str,
}

/// Verify the issuer's signature over the SD-JWT and return `(header, payload)`.
/// The `issuer_jwk` is resolved out of band (e.g. via `did:web`).
pub fn verify_issuer_signature(issuer_jwt: &str, issuer_jwk: &Value) -> Result<(Value, Value)> {
    crate::crypto::verify_jws_with_jwk(issuer_jwt, issuer_jwk)
}

/// Verify a key-binding JWT (`typ: kb+jwt`) against the holder's `cnf` key and
/// confirm it binds the expected nonce, audience, and `sd_hash`.
pub fn verify_key_binding(
    kb_jwt: &str,
    cnf_jwk: &Value,
    expect: &KeyBindingExpectations,
) -> Result<()> {
    let (header, payload) = crate::crypto::verify_jws_with_jwk(kb_jwt, cnf_jwk)?;
    if header.get("typ").and_then(Value::as_str) != Some("kb+jwt") {
        return Err(anyhow!("key-binding JWT must have typ=kb+jwt"));
    }
    let field = |k: &str| payload.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    if field("nonce") != expect.nonce {
        return Err(anyhow!("key-binding nonce mismatch (replay/wrong-session)"));
    }
    if field("aud") != expect.audience {
        return Err(anyhow!("key-binding audience mismatch (wrong verifier)"));
    }
    if field("sd_hash") != expect.sd_hash {
        return Err(anyhow!("key-binding sd_hash mismatch (disclosures tampered)"));
    }
    Ok(())
}

/// Decode a single encoded disclosure into `(salt, name, value)`. The wallet uses
/// this to pick which disclosures answer a query.
pub fn decode_disclosure(enc: &str) -> Result<(String, String, Value)> {
    let (_digest, salt, name, value) = parse_disclosure(enc)?;
    let salt = salt
        .as_str()
        .ok_or_else(|| anyhow!("disclosure salt must be a string"))?
        .to_string();
    Ok((salt, name, value))
}

fn parse_disclosure(enc: &str) -> Result<(String, Value, String, Value)> {
    let digest = b64url(&sha256(enc.as_bytes()));
    let arr: Vec<Value> = serde_json::from_slice(&b64url_decode(enc)?)?;
    if arr.len() != 3 {
        return Err(anyhow!("disclosure must be a 3-element array"));
    }
    let name = arr[1]
        .as_str()
        .ok_or_else(|| anyhow!("disclosure name must be a string"))?
        .to_string();
    Ok((digest, arr[0].clone(), name, arr[2].clone()))
}

/// Decode a compact SD-JWT into a human-readable JSON view for debugging: the
/// issuer JWT's header and payload, each disclosure broken into its `salt` /
/// `name` / `value` and matched against the `_sd` digests in the payload, and
/// the reconstructed full claim set (payload with every disclosure applied).
///
/// Nothing is verified — this is purely for inspecting the structure. Signatures
/// are not checked and the trailing key-binding JWT (if any) is ignored.
pub fn explain(sd_jwt: &str) -> Result<Value> {
    // KB-aware: a presented SD-JWT may carry a trailing key-binding JWT, which is
    // not a disclosure. `split_presentation` separates it out cleanly.
    let parsed = split_presentation(sd_jwt)?;
    let issuer_jwt = parsed.issuer_jwt;
    let encoded_disclosures = parsed.disclosures;
    let (header, payload) = decode_jws_unverified(&issuer_jwt)?;

    let disclosures: Vec<Value> = encoded_disclosures
        .iter()
        .map(|enc| {
            let (digest, salt, name, value) = parse_disclosure(enc)?;
            Ok(json!({ "digest": digest, "salt": salt, "name": name, "value": value }))
        })
        .collect::<Result<_>>()?;

    let reconstructed = reconstruct_claims(&payload, &encoded_disclosures)?;

    Ok(json!({
        "issuer_jwt": { "header": header, "payload": payload },
        "disclosures": disclosures,
        "reconstructed_claims": reconstructed,
    }))
}

/// Reconstruct the full claim set from an issuer JWT payload and the disclosures
/// the holder chose to present. Unmatched `_sd` digests are simply omitted.
///
/// Returns an error if any presented disclosure is not referenced by a digest
/// in the JWT, or if any digest appears more than once in the payload.
pub fn reconstruct_claims(payload: &Value, disclosures: &[String]) -> Result<Value> {
    let mut by_digest: HashMap<String, (String, Value)> = HashMap::new();
    for enc in disclosures {
        let (digest, _, name, value) = parse_disclosure(enc)?;
        if by_digest.contains_key(&digest) {
            return Err(anyhow!("duplicate disclosure presented"));
        }
        by_digest.insert(digest, (name, value));
    }

    let mut payload_digests = HashSet::new();
    collect_sd_digests(payload, &mut payload_digests)?;

    for digest in by_digest.keys() {
        if !payload_digests.contains(digest) {
            return Err(anyhow!("disclosure not referenced by any digest in the JWT"));
        }
    }

    Ok(walk(payload, &by_digest))
}

/// Collect all digest strings from `_sd` arrays in the payload tree, returning
/// an error if the same digest appears more than once.
fn collect_sd_digests(value: &Value, seen: &mut HashSet<String>) -> Result<()> {
    match value {
        Value::Object(obj) => {
            if let Some(sd) = obj.get("_sd").and_then(Value::as_array) {
                for digest in sd.iter().filter_map(Value::as_str) {
                    if !seen.insert(digest.to_string()) {
                        return Err(anyhow!("duplicate digest in SD-JWT payload"));
                    }
                }
            }
            for v in obj.values() {
                collect_sd_digests(v, seen)?;
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_sd_digests(v, seen)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn walk(value: &Value, map: &HashMap<String, (String, Value)>) -> Value {
    match value {
        Value::Object(obj) => {
            let mut out = Map::new();
            for (k, v) in obj {
                if k == "_sd" || k == "_sd_alg" {
                    continue;
                }
                out.insert(k.clone(), walk(v, map));
            }
            if let Some(sd) = obj.get("_sd").and_then(Value::as_array) {
                for digest in sd.iter().filter_map(Value::as_str) {
                    if let Some((name, val)) = map.get(digest) {
                        out.insert(name.clone(), walk(val, map));
                    }
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|v| walk(v, map)).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disclose_and_reconstruct_roundtrip() {
        let mut claims = json!({
            "vct": "Diploma",
            "student": { "full_name": "Ada", "student_id": "123" },
            "gpa": 9.0
        });
        let disclosures = make_selectively_disclosable(
            &mut claims,
            &["student.full_name", "student.student_id", "gpa"],
        );
        assert_eq!(disclosures.len(), 3);
        // Disclosable claims are gone from the signed payload.
        assert!(claims["student"].get("full_name").is_none());
        assert!(claims.get("gpa").is_none());
        assert_eq!(claims["_sd_alg"], "sha-256");

        let encoded: Vec<String> = disclosures.iter().map(|d| d.encoded.clone()).collect();
        let full = reconstruct_claims(&claims, &encoded).unwrap();
        assert_eq!(full["student"]["full_name"], "Ada");
        assert_eq!(full["student"]["student_id"], "123");
        assert_eq!(full["gpa"], 9.0);
        assert_eq!(full["vct"], "Diploma");
    }

    #[test]
    fn explain_decodes_header_payload_and_disclosures() {
        // A hand-built compact SD-JWT: header.payload.sig ~ disclosure ~
        // Payload references one disclosure ("a") by digest and keeps "b" plain.
        let mut claims = json!({ "a": 1, "b": 2 });
        let disclosures = make_selectively_disclosable(&mut claims, &["a"]);
        let header = json!({ "alg": "EdDSA", "typ": "dc+sd-jwt" });
        // Signature segment is irrelevant — explain does not verify it.
        let issuer_jwt = format!(
            "{}.{}.{}",
            b64url(serde_json::to_string(&header).unwrap().as_bytes()),
            b64url(serde_json::to_string(&claims).unwrap().as_bytes()),
            "sig"
        );
        let sd_jwt = assemble(&issuer_jwt, &disclosures);

        let view = explain(&sd_jwt).unwrap();
        assert_eq!(view["issuer_jwt"]["header"]["typ"], "dc+sd-jwt");
        assert_eq!(view["issuer_jwt"]["payload"]["b"], 2);
        let ds = view["disclosures"].as_array().unwrap();
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0]["name"], "a");
        assert_eq!(ds[0]["value"], 1);
        assert_eq!(ds[0]["digest"], disclosures[0].digest);
        // The reconstructed view re-merges the disclosed claim back in.
        assert_eq!(view["reconstructed_claims"]["a"], 1);
        assert_eq!(view["reconstructed_claims"]["b"], 2);
    }

    #[test]
    fn partial_disclosure_hides_undisclosed_claims() {
        let mut claims = json!({ "a": 1, "b": 2 });
        let disclosures = make_selectively_disclosable(&mut claims, &["a", "b"]);
        // Present only the first disclosure.
        let full = reconstruct_claims(&claims, &[disclosures[0].encoded.clone()]).unwrap();
        assert_eq!(full["a"], 1);
        assert!(full.get("b").is_none());
    }
}
