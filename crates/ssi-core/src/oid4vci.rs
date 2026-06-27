//! Holder-side OID4VCI — the one thing a wallet signs during issuance.
//!
//! The wallet proves possession of its holder key by signing a key proof JWT
//! (`typ: openid4vci-proof+jwt`) over the issuer's `c_nonce`. The proof's `jwk`
//! header becomes the issued credential's `cnf.jwk`, binding the credential to
//! that key. Everything else in OID4VCI (offers, token/nonce/credential
//! endpoints, metadata) is transport orchestration that lives in the wallet's
//! HTTP layer and the issuer service — not here.

use anyhow::Result;
use serde_json::json;

use crate::holder::{Signer, sign_jws_with};

/// Build the OID4VCI key proof JWT binding the holder's public key to the
/// issuer's `c_nonce`. The `jwk` header is the public half of `signer`'s key and
/// becomes the credential's `cnf.jwk` at issuance.
pub fn build_vci_proof(signer: &dyn Signer, credential_issuer: &str, c_nonce: &str) -> Result<String> {
    let header = json!({
        "typ": "openid4vci-proof+jwt",
        "jwk": signer.public_jwk(),
    });
    let payload = json!({
        "aud": credential_issuer,
        "iat": chrono::Utc::now().timestamp(),
        "nonce": c_nonce,
    });
    sign_jws_with(&header, &payload, signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, holder::HolderKey};

    #[test]
    fn vci_proof_is_a_valid_key_proof() {
        let holder = HolderKey::generate();
        let proof = build_vci_proof(&holder, "https://issuer.example", "n-123").unwrap();

        let (header, payload) = crypto::decode_jws_unverified(&proof).unwrap();
        assert_eq!(header["typ"], "openid4vci-proof+jwt");
        assert_eq!(header["alg"], "ES256");
        // The proof self-attests its key: the `jwk` header verifies its own signature.
        crypto::verify_jws_with_jwk(&proof, &header["jwk"]).expect("proof verifies under its own jwk");
        assert_eq!(payload["aud"], "https://issuer.example");
        assert_eq!(payload["nonce"], "n-123");
    }
}
