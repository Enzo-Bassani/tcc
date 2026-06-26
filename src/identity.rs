//! Issuer identity. The issuer signs SD-JWT VCs with **ES256** using its leaf
//! certificate's key and embeds the `x5c` certificate chain (HAIP §6.1.1) so a
//! verifier can validate it up to a trusted CA root. The `IssuerIdentity` trait
//! keeps the rest of the codebase agnostic about how signing is done.
//!
//! For this prototype the identity is the bundled mock UFSC leaf (chaining
//! UFSC → MEC → ICP-Brasil, see `ssi_core::x509::demo`). A production issuer would
//! load its private key + certificate chain from a KMS/HSM instead.

use anyhow::{Context, Result};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use serde_json::Value;

use crate::crypto;
use ssi_core::x509::{Cert, demo};

pub trait IssuerIdentity: Send + Sync {
    /// The issuer identifier — an https URL bound to the leaf certificate's SAN.
    fn iss(&self) -> &str;
    /// The issuer's public signing key as a JWK (EC P-256), for `/.well-known/jwks.json`.
    fn public_jwk(&self) -> Value;
    /// The `x5c` certificate chain (standard-base64 DER, leaf first, root excluded)
    /// embedded in every issued JWS header.
    fn x5c(&self) -> Vec<Value>;
    /// Sign a compact JWS with the issuer key (ES256); the `x5c` chain is injected
    /// into the header.
    fn sign(&self, header: Value, payload: Value) -> String;
}

/// A certificate-backed (X.509 / `x5c`) issuer identity signing with ES256.
pub struct CertIdentity {
    iss: String,
    signing: SigningKey,
    /// The `x5c` header value, prebuilt once at construction as a JSON array of
    /// standard-base64 DER certificates (leaf first, root excluded) so `sign`
    /// only clones it rather than re-encoding on every call.
    x5c: Value,
}

impl CertIdentity {
    /// Build an identity from a PKCS#8 leaf private key and its certificate chain
    /// (PEM, leaf first, trust-anchor root excluded). `iss` must be an https URL
    /// present in the leaf certificate's SAN.
    pub fn from_pem(iss: &str, leaf_key_pkcs8_pem: &str, chain_pem: &[&str]) -> Result<Self> {
        let signing = SigningKey::from_pkcs8_pem(leaf_key_pkcs8_pem)
            .context("issuer leaf key is not a valid PKCS#8 P-256 key")?;
        let x5c = chain_pem
            .iter()
            .map(|pem| Ok(Value::from(crypto::b64std(Cert::from_pem(pem)?.der()))))
            .collect::<Result<Vec<Value>>>()?;
        Ok(Self {
            iss: iss.to_string(),
            signing,
            x5c: Value::Array(x5c),
        })
    }

    /// The canonical identity (`iss`) of the bundled mock UFSC issuer — the primary
    /// SAN of the demo leaf certificate. Kept **decoupled** from the deployment /
    /// network address (`AppConfig::issuer_url`): the issuer's identity is a stable,
    /// certificate-bound value, independent of which host/port it is served from.
    pub const DEMO_ISS: &'static str = "https://diploma.ufsc.br";

    /// The bundled mock UFSC issuing identity (prototype). Chains to the mock
    /// ICP-Brasil root the verifier trusts by default. Its `iss` is the fixed
    /// [`CertIdentity::DEMO_ISS`] bound to the leaf certificate's SAN — **not** the
    /// deployment URL, so a credential issued from any host (localhost, 127.0.0.1,
    /// an emulator alias) still binds to the certificate at verification time.
    pub fn demo() -> Result<Self> {
        Self::from_pem(
            Self::DEMO_ISS,
            demo::UFSC_LEAF_KEY_PKCS8_PEM,
            &[demo::UFSC_LEAF_PEM, demo::MEC_INTERMEDIATE_PEM],
        )
    }
}

impl IssuerIdentity for CertIdentity {
    fn iss(&self) -> &str {
        &self.iss
    }

    fn public_jwk(&self) -> Value {
        crypto::es256_public_jwk(&self.signing)
    }

    fn x5c(&self) -> Vec<Value> {
        self.x5c.as_array().cloned().unwrap_or_default()
    }

    fn sign(&self, mut header: Value, payload: Value) -> String {
        header["x5c"] = self.x5c.clone();
        crypto::sign_jws_es256(&header, &payload, &self.signing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi_core::x509;

    #[test]
    fn demo_identity_iss_binds_to_leaf_and_signs_es256() {
        let id = CertIdentity::demo().unwrap();
        assert_eq!(id.iss(), CertIdentity::DEMO_ISS);
        // The signed JWS carries x5c and verifies against the leaf cert, which
        // binds to the iss and chains to the bundled ICP-Brasil root.
        let jws = id.sign(json!({ "alg": "ES256", "typ": "dc+sd-jwt" }), json!({ "hi": 1 }));
        let (header, _) = crypto::decode_jws_unverified(&jws).unwrap();
        let chain = x509::parse_x5c(&header["x5c"]).unwrap();
        x509::iss_matches_leaf(id.iss(), &chain[0]).unwrap();
        let store = ssi_core::trust::TrustStore::with_defaults();
        x509::validate_chain(&chain, store.anchor_certs(), chrono::Utc::now().timestamp()).unwrap();
        crypto::verify_jws_with_jwk(&jws, &chain[0].public_jwk().unwrap()).unwrap();
    }
}
