//! DCQL — the Digital Credentials Query Language (OID4VP 1.0, §6).
//!
//! A verifier expresses *what it wants* as a `DcqlQuery`. This module models the
//! query and implements the two operations both sides need:
//!
//! - **Claims Path Pointers** ([`select`]) — walk into a credential per the spec:
//!   a string selects an object key, a non-negative integer selects an array
//!   index, and `null` selects every element of the current array(s).
//! - **Satisfaction** ([`CredentialQuery::resolve_required_paths`]) — given a
//!   credential's claims, work out which claims (honoring `claim_sets`
//!   preference order) it can satisfy. The wallet uses this to decide what to
//!   disclose; the verifier uses it to confirm a presentation answers the query.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A full DCQL query: a non-empty set of credential queries and, optionally,
/// `credential_sets` expressing "satisfy one of these combinations".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlQuery {
    pub credentials: Vec<CredentialQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// A query for one credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialQuery {
    pub id: String,
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimsQuery>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
}

/// Format-specific constraints. For `dc+sd-jwt` this carries `vct_values`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vct_values: Option<Vec<String>>,
}

/// A single requested claim: a path pointer, an optional id (referenced by
/// `claim_sets`), and optional expected `values`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub path: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
}

/// "Satisfy one of these id combinations."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    pub options: Vec<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// A trust-framework constraint on acceptable issuers (`aki`, `etsi_tl`, `openid_federation`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedAuthority {
    #[serde(rename = "type")]
    pub authority_type: String,
    pub values: Vec<String>,
}

impl CredentialSetQuery {
    pub fn is_required(&self) -> bool {
        self.required.unwrap_or(true)
    }
}

/// Apply a DCQL Claims Path Pointer to a JSON value, returning every selected node.
///
/// - a string element selects that object key;
/// - a non-negative integer selects that array index;
/// - `null` selects all elements of the current array(s).
pub fn select<'a>(root: &'a Value, path: &[Value]) -> Vec<&'a Value> {
    let mut current = vec![root];
    for element in path {
        let mut next = Vec::new();
        for node in current {
            match element {
                Value::String(key) => {
                    if let Some(v) = node.get(key) {
                        next.push(v);
                    }
                }
                Value::Number(n) => {
                    if let Some(idx) = n.as_u64()
                        && let Some(v) = node.get(idx as usize)
                    {
                        next.push(v);
                    }
                }
                Value::Null => {
                    if let Some(arr) = node.as_array() {
                        next.extend(arr.iter());
                    }
                }
                _ => {}
            }
        }
        current = next;
    }
    current
}

impl ClaimsQuery {
    /// Is this claim present in `claims` (and, if `values` is set, matching one)?
    pub fn is_satisfied_by(&self, claims: &Value) -> bool {
        let selected = select(claims, &self.path);
        if selected.is_empty() {
            return false;
        }
        match &self.values {
            // `values` is best-effort privacy guidance, not a security gate, but
            // honoring it lets the wallet pick a credential that actually matches.
            Some(expected) => selected.iter().any(|v| expected.contains(v)),
            None => true,
        }
    }
}

/// What a credential must present to answer a [`CredentialQuery`].
#[derive(Debug, Clone)]
pub struct RequiredClaims<'a> {
    /// The claim queries that should be disclosed (empty = mandatory claims only).
    pub claims: Vec<&'a ClaimsQuery>,
}

impl CredentialQuery {
    pub fn requires_holder_binding(&self) -> bool {
        self.require_cryptographic_holder_binding.unwrap_or(true)
    }

    /// Does the credential's `vct` satisfy this query's `meta.vct_values`?
    pub fn vct_matches(&self, claims: &Value) -> bool {
        match self.meta.as_ref().and_then(|m| m.vct_values.as_ref()) {
            Some(values) => claims
                .get("vct")
                .and_then(Value::as_str)
                .map(|vct| values.iter().any(|v| v == vct))
                .unwrap_or(false),
            None => true,
        }
    }

    /// Resolve which claims a credential with `claims` should/does present,
    /// honoring `claim_sets` preference order. Returns `None` when the credential
    /// cannot satisfy the query at all.
    ///
    /// - On the **wallet** side `claims` is the full credential → picks the first
    ///   satisfiable `claim_set` (data minimization).
    /// - On the **verifier** side `claims` is the disclosed subset → confirms the
    ///   presentation answers the query.
    pub fn resolve_required_paths(&self, claims: &Value) -> Option<RequiredClaims<'_>> {
        if !self.vct_matches(claims) {
            return None;
        }
        // TODO(trust-list): enforce `self.trusted_authorities` here — confirm the
        // credential's issuer is a member of one of the named trust frameworks
        // (aki / etsi_tl / openid_federation). Skipped until trusted lists land.

        let Some(all_claims) = &self.claims else {
            // No claims requested → only mandatory-to-present claims.
            return Some(RequiredClaims { claims: Vec::new() });
        };

        match &self.claim_sets {
            Some(sets) => {
                // Index claims by id so claim_sets can reference them.
                let by_id = |id: &str| all_claims.iter().find(|c| c.id.as_deref() == Some(id));
                for option in sets {
                    let resolved: Option<Vec<&ClaimsQuery>> = option
                        .iter()
                        .map(|id| by_id(id))
                        .collect::<Option<Vec<_>>>();
                    let Some(set) = resolved else { continue };
                    if set.iter().all(|c| c.is_satisfied_by(claims)) {
                        return Some(RequiredClaims { claims: set });
                    }
                }
                None
            }
            None => {
                if all_claims.iter().all(|c| c.is_satisfied_by(claims)) {
                    Some(RequiredClaims {
                        claims: all_claims.iter().collect(),
                    })
                } else {
                    None
                }
            }
        }
    }
}

impl DcqlQuery {
    /// The credential-query ids that MUST be answered for the overall query to be
    /// satisfied. With no `credential_sets`, every credential is required; with
    /// them, the union of ids appearing in required sets' options is potentially
    /// required (a set is satisfied if *any* of its options is fully present).
    pub fn credential(&self, id: &str) -> Option<&CredentialQuery> {
        self.credentials.iter().find(|c| c.id == id)
    }

    /// Given the set of credential ids actually present in a VP Token, decide
    /// whether the overall query is satisfied (every required `credential_set`
    /// has at least one fully-present option; with no sets, all credentials present).
    pub fn overall_satisfied(&self, present_ids: &[String]) -> bool {
        let has = |id: &String| present_ids.contains(id);
        match &self.credential_sets {
            None => self.credentials.iter().all(|c| has(&c.id)),
            Some(sets) => sets.iter().filter(|s| s.is_required()).all(|set| {
                set.options
                    .iter()
                    .any(|option| option.iter().all(has))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cred() -> Value {
        json!({
            "vct": "https://example.com/identity",
            "address": { "street": "42 Market St" },
            "degrees": [ { "type": "BSc" }, { "type": "MSc" } ],
            "nationalities": ["British", "Betelgeusian"],
            "age_equal_or_over": { "18": true }
        })
    }

    #[test]
    fn path_pointer_semantics() {
        let c = cred();
        assert_eq!(select(&c, &[json!("address"), json!("street")])[0], "42 Market St");
        let degree_types = select(&c, &[json!("degrees"), Value::Null, json!("type")]);
        assert_eq!(degree_types, vec![&json!("BSc"), &json!("MSc")]);
        assert_eq!(select(&c, &[json!("nationalities"), json!(1)])[0], "Betelgeusian");
        assert!(select(&c, &[json!("missing")]).is_empty());
    }

    #[test]
    fn claim_sets_pick_first_satisfiable() {
        let query: CredentialQuery = serde_json::from_value(json!({
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://example.com/identity"] },
            "claims": [
                { "id": "over18", "path": ["age_equal_or_over", "18"] },
                { "id": "dob", "path": ["birthdate"] }
            ],
            "claim_sets": [ ["over18"], ["dob"] ]
        }))
        .unwrap();
        // Credential has over18 but not birthdate → first option chosen.
        let resolved = query.resolve_required_paths(&cred()).unwrap();
        assert_eq!(resolved.claims.len(), 1);
        assert_eq!(resolved.claims[0].id.as_deref(), Some("over18"));
    }

    #[test]
    fn vct_mismatch_fails() {
        let query: CredentialQuery = serde_json::from_value(json!({
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://other.example/type"] },
        }))
        .unwrap();
        assert!(query.resolve_required_paths(&cred()).is_none());
    }

    #[test]
    fn credential_sets_overall() {
        let q: DcqlQuery = serde_json::from_value(json!({
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt" },
                { "id": "mdl", "format": "dc+sd-jwt" }
            ],
            "credential_sets": [ { "options": [ ["pid"], ["mdl"] ], "required": true } ]
        }))
        .unwrap();
        assert!(q.overall_satisfied(&["pid".into()]));
        assert!(q.overall_satisfied(&["mdl".into()]));
        assert!(!q.overall_satisfied(&[]));
    }
}
