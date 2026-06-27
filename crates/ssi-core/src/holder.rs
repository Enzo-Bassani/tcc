//! A holder (wallet) signing key, used by the reference holder ([`crate::wallet_sim`]),
//! the test/demo minting helpers ([`crate::testkit`]), and the issuer's offline
//! demo. It signs the two things a holder ever signs: the OID4VCI key proof and
//! the OID4VP key-binding JWT.
//!
//! The default is **ES256** (ECDSA P-256) — the HAIP §7 baseline every conformant
//! wallet must support, and the only algorithm a hardware-backed device key
//! (Android StrongBox/Keystore) can use. **EdDSA** (Ed25519) remains available via
//! [`HolderKey::generate_ed25519`], but it is never the default.

use anyhow::{Result, anyhow};
use ed25519_dalek::SigningKey as Ed25519Key;
use p256::ecdsa::SigningKey as P256Key;
use serde_json::{Value, json};

use crate::crypto;

/// Signs arbitrary bytes with the holder's private key.
///
/// This abstracts *where* the private key lives so the engine never has to own it.
/// [`HolderKey`] implements it natively (in-memory key, used by tests, the demo and
/// the reference [`crate::wallet_sim`]); the real wallet implements it over a
/// **non-exportable** Android Keystore/StrongBox key reached through an FFI
/// callback. Either way the engine does all JWS framing in [`sign_jws_with`] — the
/// signer only ever sees opaque `signing_input` bytes, so there is a single
/// serializer and the wire format cannot diverge between implementations.
pub trait Signer: Send + Sync {
    /// The raw signature over `message`: ES256 → JOSE R‖S (64 bytes), EdDSA →
    /// 64-byte Ed25519 signature. The signer hashes internally (ES256 over SHA-256),
    /// matching `p256`/`ed25519-dalek` and the Android Keystore `SHA256withECDSA`.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// The public JWK to embed as the credential's `cnf.jwk` or a key-proof header.
    fn public_jwk(&self) -> Value;

    /// The JOSE `alg` this signer produces (`"ES256"` or `"EdDSA"`).
    fn alg(&self) -> &str;
}

/// Build a compact JWS, signing the `header.payload` input with `signer` and
/// stamping the `alg` from [`Signer::alg`] (any `alg` already in `header` is
/// overwritten). This is the **one** place a holder JWS is framed, so the byte
/// layout is identical for every [`Signer`] implementation.
pub fn sign_jws_with(header: &Value, payload: &Value, signer: &dyn Signer) -> Result<String> {
    let mut header = header.clone();
    header
        .as_object_mut()
        .ok_or_else(|| anyhow!("JWS header must be a JSON object"))?
        .insert("alg".into(), json!(signer.alg()));
    let h = crypto::b64url(&serde_json::to_vec(&header)?);
    let p = crypto::b64url(&serde_json::to_vec(payload)?);
    let signing_input = format!("{h}.{p}");
    let sig = signer.sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", crypto::b64url(&sig)))
}

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

    /// Sign a compact JWS with this key. Convenience wrapper over [`sign_jws_with`]
    /// for the in-memory key, whose signing is infallible; `header` supplies the
    /// remaining members (`typ`, and `jwk` for a key proof) and its `alg` is set
    /// from the key type.
    pub fn sign_jws(&self, header: &Value, payload: &Value) -> String {
        sign_jws_with(header, payload, self).expect("in-memory holder signing never fails")
    }
}

impl Signer for HolderKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            HolderKey::Es256(k) => {
                use p256::ecdsa::{Signature as P256Sig, signature::Signer};
                let sig: P256Sig = k.sign(message);
                sig.to_bytes().to_vec()
            }
            HolderKey::Ed25519(k) => {
                use ed25519_dalek::Signer;
                k.sign(message).to_bytes().to_vec()
            }
        })
    }

    fn public_jwk(&self) -> Value {
        HolderKey::public_jwk(self)
    }

    fn alg(&self) -> &str {
        HolderKey::alg(self)
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
