//! A holder (wallet) signing key, used by the reference holder ([`crate::wallet_sim`]),
//! the test/demo minting helpers ([`crate::testkit`]), and the issuer's offline
//! demo. It signs the two things a holder ever signs: the OID4VCI key proof and
//! the OID4VP key-binding JWT.
//!
//! The default is **ES256** (ECDSA P-256) — the HAIP §7 baseline every conformant
//! wallet must support, and the only algorithm a hardware-backed device key
//! (Android StrongBox/Keystore) can use. **EdDSA** (Ed25519) remains available via
//! [`HolderKey::generate_ed25519`], but it is never the default.

use ed25519_dalek::SigningKey as Ed25519Key;
use p256::ecdsa::SigningKey as P256Key;
use serde_json::{Value, json};

use crate::crypto;

/// A holder key pair, dispatching on its algorithm.
#[derive(Clone)]
pub enum HolderKey {
    /// ECDSA P-256 / `ES256` — the default.
    Es256(P256Key),
    /// Ed25519 / `EdDSA` — kept only to exercise the verifier's compatibility path.
    Ed25519(Ed25519Key),
}

impl HolderKey {
    /// Generate a fresh ES256 (P-256) holder key — the default.
    pub fn generate() -> Self {
        HolderKey::Es256(P256Key::random(&mut rand::rngs::OsRng))
    }

    /// Generate a fresh EdDSA (Ed25519) holder key. Use only to prove the verifier
    /// still accepts EdDSA holder binding; ES256 is the default everywhere else.
    pub fn generate_ed25519() -> Self {
        HolderKey::Ed25519(Ed25519Key::generate(&mut rand::rngs::OsRng))
    }

    /// The JOSE `alg` identifier this key signs with.
    pub fn alg(&self) -> &'static str {
        match self {
            HolderKey::Es256(_) => "ES256",
            HolderKey::Ed25519(_) => "EdDSA",
        }
    }

    /// The public JWK to embed as the credential's `cnf.jwk` — an EC JWK for
    /// ES256, an OKP JWK for EdDSA.
    pub fn public_jwk(&self) -> Value {
        match self {
            HolderKey::Es256(k) => crypto::es256_public_jwk(k),
            HolderKey::Ed25519(k) => crypto::ed25519_public_jwk(&k.verifying_key()),
        }
    }

    /// Sign a compact JWS with this key, setting the JWS `alg` to match the key
    /// type. `header` supplies the remaining members (`typ`, and `jwk` for a key
    /// proof); any `alg` it carries is overwritten.
    pub fn sign_jws(&self, header: &Value, payload: &Value) -> String {
        let mut header = header.clone();
        header
            .as_object_mut()
            .expect("JWS header must be a JSON object")
            .insert("alg".into(), json!(self.alg()));
        match self {
            HolderKey::Es256(k) => crypto::sign_jws_es256(&header, payload, k),
            HolderKey::Ed25519(k) => crypto::sign_jws(&header, payload, k),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both holder algorithms produce a JWS the universal verifier accepts, with
    /// the right `alg` header and a JWK of the matching key type.
    #[test]
    fn signs_and_verifies_both_algorithms() {
        for (holder, kty, alg) in [
            (HolderKey::generate(), "EC", "ES256"),
            (HolderKey::generate_ed25519(), "OKP", "EdDSA"),
        ] {
            let jwk = holder.public_jwk();
            assert_eq!(jwk["kty"], kty);
            let jws = holder.sign_jws(&json!({ "typ": "kb+jwt" }), &json!({ "n": 1 }));
            let (header, payload) =
                crypto::verify_jws_with_jwk(&jws, &jwk).expect("holder JWS verifies");
            assert_eq!(header["alg"], alg);
            assert_eq!(payload["n"], 1);
        }
    }
}
