//! IETF Token Status List — issuer side.
//!
//! The bitstring codec lives in `ssi-core` (shared with the verifier); this
//! module re-exports it and keeps the issuer-only job of building and signing
//! the status-list JWT served at `/status-lists/{id}`.

use anyhow::Result;
use serde_json::{Value, json};

pub use ssi_core::status::BitString;

use crate::identity::IssuerIdentity;

/// Build the signed Token Status List JWT served at `/status-lists/{id}`.
pub fn build_status_list_jwt(
    identity: &dyn IssuerIdentity,
    issuer_url: &str,
    list_id: &str,
    bits: &BitString,
) -> Result<String> {
    let header = json!({ "alg": "ES256", "typ": "statuslist+jwt" });
    let payload: Value = json!({
        "iss": identity.iss(),
        "sub": format!("{issuer_url}/status-lists/{list_id}"),
        "iat": chrono::Utc::now().timestamp(),
        "ttl": 3600,
        "status_list": { "bits": 1, "lst": bits.encode()? },
    });
    Ok(identity.sign(header, payload))
}
