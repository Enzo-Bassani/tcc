//! Low-level cryptographic primitives: base64url, SHA-256, and compact JWS
//! signing/verification — EdDSA (Ed25519) built directly on `ed25519-dalek` and
//! ES256 (ECDSA P-256) on `p256`.

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn b64url(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    Ok(B64.decode(s)?)
}

/// Standard base64 (with `+`/`/` and `=` padding) — NOT base64url. The `x5c`
/// JOSE header parameter carries DER certificates as *standard* base64 per
/// RFC 7515 §4.1.6, so it must use this engine, never [`b64url_decode`].
pub fn b64std(data: &[u8]) -> String {
    B64_STD.encode(data)
}

pub fn b64std_decode(s: &str) -> Result<Vec<u8>> {
    Ok(B64_STD.decode(s)?)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// `n` random bytes, base64url-encoded — used for salts, codes and nonces.
pub fn random_b64url(n: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    b64url(&buf)
}

/// Build a compact JWS (`header.payload.signature`) signed with EdDSA.
pub fn sign_jws(header: &Value, payload: &Value, key: &SigningKey) -> String {
    let h = b64url(&serde_json::to_vec(header).expect("header is serializable"));
    let p = b64url(&serde_json::to_vec(payload).expect("payload is serializable"));
    let signing_input = format!("{h}.{p}");
    let sig: Signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&sig.to_bytes()))
}

/// Verify a compact JWS against a public key, returning `(header, payload)`.
pub fn verify_jws(jws: &str, key: &VerifyingKey) -> Result<(Value, Value)> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        bail!("compact JWS must have 3 parts");
    }
    let header: Value = serde_json::from_slice(&b64url_decode(parts[0])?)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        bail!("expected alg EdDSA");
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = Signature::from_slice(&b64url_decode(parts[2])?)?;
    key.verify_strict(signing_input.as_bytes(), &sig)?;
    Ok((
        header,
        serde_json::from_slice(&b64url_decode(parts[1])?)?,
    ))
}

/// Decode a JWS without verifying its signature (for inspecting untrusted input).
pub fn decode_jws_unverified(jws: &str) -> Result<(Value, Value)> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        bail!("compact JWS must have 3 parts");
    }
    Ok((
        serde_json::from_slice(&b64url_decode(parts[0])?)?,
        serde_json::from_slice(&b64url_decode(parts[1])?)?,
    ))
}

/// Reconstruct an Ed25519 public key from an OKP JWK (`{"kty","crv","x"}`).
pub fn verifying_key_from_jwk(jwk: &Value) -> Result<VerifyingKey> {
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("JWK missing 'x'"))?;
    let bytes: [u8; 32] = b64url_decode(x)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("JWK 'x' must be 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

/// Verify a compact JWS against a public **JWK**, dispatching on the JWS `alg`.
/// Supports the two algorithms a universal SD-JWT VC verifier needs: `EdDSA`
/// (OKP/Ed25519, what our issuer emits) and `ES256` (EC/P-256, what HAIP/ARF
/// mandate for EUDI credentials). Returns `(header, payload)`.
pub fn verify_jws_with_jwk(jws: &str, jwk: &Value) -> Result<(Value, Value)> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        bail!("compact JWS must have 3 parts");
    }
    let header: Value = serde_json::from_slice(&b64url_decode(parts[0])?)?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64url_decode(parts[2])?;

    match alg {
        "EdDSA" => {
            let key = verifying_key_from_jwk(jwk)?;
            let sig = Signature::from_slice(&sig_bytes)?;
            key.verify_strict(signing_input.as_bytes(), &sig)?;
        }
        "ES256" => verify_es256(signing_input.as_bytes(), &sig_bytes, jwk)?,
        other => bail!("unsupported JWS alg: {other}"),
    }

    Ok((header, serde_json::from_slice(&b64url_decode(parts[1])?)?))
}

/// Parse an EC P-256 public key from a JWK, reading only the `x`/`y` coordinates so
/// a JWK that also carries the standard optional members a real `jwks` endpoint
/// emits (`use`, `alg`, `kid`, …) still loads — `p256::PublicKey::from_jwk_str`
/// rejects any unknown member. Shared by ES256 verification and the JWE/ECDH path.
pub fn p256_public_from_jwk(jwk: &Value) -> Result<p256::PublicKey> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        bail!("invalid P-256 JWK: expected kty=EC, crv=P-256");
    }
    let x = b64url_decode(
        jwk.get("x")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("P-256 JWK missing x"))?,
    )?;
    let y = b64url_decode(
        jwk.get("y")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("P-256 JWK missing y"))?,
    )?;
    // Uncompressed SEC1 encoding: 0x04 || X || Y.
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|e| anyhow::anyhow!("invalid P-256 JWK point: {e}"))
}

/// The bare public EC JWK (`kty:EC, crv:P-256, x, y`) for a P-256 public key —
/// the single home for the EC-public-JWK wire shape (used for ES256 signing keys
/// and ECDH-ES encryption keys alike).
pub fn p256_public_jwk(key: &p256::PublicKey) -> Value {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = key.to_encoded_point(false);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(point.x().expect("uncompressed point has x")),
        "y": b64url(point.y().expect("uncompressed point has y")),
    })
}

/// Verify a P-256 ECDSA (ES256) signature over `msg` using an EC JWK.
fn verify_es256(msg: &[u8], sig_bytes: &[u8], jwk: &Value) -> Result<()> {
    use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Vk, signature::Verifier};

    let vk: P256Vk = p256_public_from_jwk(jwk)?.into();
    let sig = P256Sig::from_slice(sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid ES256 signature: {e}"))?;
    vk.verify(msg, &sig)
        .map_err(|_| anyhow::anyhow!("ES256 signature verification failed"))?;
    Ok(())
}

/// The public OKP JWK (`kty:OKP, crv:Ed25519`) for an Ed25519 verifying key —
/// the inverse of [`verifying_key_from_jwk`].
pub fn ed25519_public_jwk(key: &VerifyingKey) -> Value {
    serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url(key.as_bytes()),
    })
}

/// Sign a compact JWS with ES256 (P-256 ECDSA). The issuer in this repo signs
/// its credentials and status lists with ES256 (HAIP/x5c), and the wallet's
/// holder key proofs use it too.
pub fn sign_jws_es256(header: &Value, payload: &Value, key: &p256::ecdsa::SigningKey) -> String {
    use p256::ecdsa::{Signature as P256Sig, signature::Signer};
    let h = b64url(&serde_json::to_vec(header).expect("header is serializable"));
    let p = b64url(&serde_json::to_vec(payload).expect("payload is serializable"));
    let signing_input = format!("{h}.{p}");
    let sig: P256Sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&sig.to_bytes()))
}

/// The public EC JWK (`kty:EC, crv:P-256`) for an ES256 signing key.
pub fn es256_public_jwk(key: &p256::ecdsa::SigningKey) -> Value {
    p256_public_jwk(&(*key.verifying_key()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jws_roundtrip() {
        let mut rng = rand::rngs::OsRng;
        let key = SigningKey::generate(&mut rng);
        let header = json!({"alg": "EdDSA"});
        let payload = json!({"hello": "world", "n": 42});
        let jws = sign_jws(&header, &payload, &key);
        let (h, p) = verify_jws(&jws, &key.verifying_key()).expect("verifies");
        assert_eq!(h, header);
        assert_eq!(p, payload);
    }

    #[test]
    fn jws_rejects_tampering() {
        let mut rng = rand::rngs::OsRng;
        let key = SigningKey::generate(&mut rng);
        let jws = sign_jws(&json!({"alg": "EdDSA"}), &json!({"a": 1}), &key);
        let tampered = format!("{}x", &jws[..jws.len() - 1]);
        assert!(verify_jws(&tampered, &key.verifying_key()).is_err());
    }

    #[test]
    fn es256_verifies_jwk_carrying_extra_members() {
        // A JWK served by a real `jwks` endpoint also carries `use`/`alg`/`kid`;
        // the verifier must tolerate them.
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
        let jws = sign_jws_es256(&json!({"alg": "ES256"}), &json!({"hi": 1}), &sk);
        let mut jwk = es256_public_jwk(&sk);
        let obj = jwk.as_object_mut().unwrap();
        obj.insert("use".into(), json!("sig"));
        obj.insert("alg".into(), json!("ES256"));
        obj.insert("kid".into(), json!("key-1"));
        verify_jws_with_jwk(&jws, &jwk).expect("ES256 verifies despite extra JWK members");
    }
}
