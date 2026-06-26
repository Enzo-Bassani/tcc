//! JWE for OID4VP encrypted responses — **ECDH-ES (Direct Key Agreement)** over
//! P-256 with **A128GCM/A256GCM** content encryption, in compact serialization.
//!
//! This is the HAIP §5 response-encryption profile (`alg=ECDH-ES`, P-256;
//! `enc` ∈ {A128GCM, A256GCM}; RFC 7516/7518). Like the rest of the engine the
//! crypto is **self-implemented**: the elliptic-curve Diffie–
//! Hellman comes from `p256` (its `ecdh` feature), the key-derivation is the NIST
//! SP 800-56A **Concat KDF** (RFC 7518 §4.6) built directly on `sha2`, and the
//! only "new" dependency is `aes-gcm` for the AES-GCM AEAD. We do NOT pull a JOSE
//! library.
//!
//! Direction in this project: the **wallet** is always the JWE *sender* (it
//! generates the ephemeral `epk` and encrypts the Authorization Response), and the
//! **verifier** is the *recipient* (it advertises an ephemeral P-256 key in the
//! signed request's `client_metadata.jwks` and decrypts with the matching private
//! key). The recipient key is authenticated because it travels inside the request
//! object the verifier signs (a `did:jwk` JAR), so a relay cannot swap it.
//!
//! Compact form (5 parts, empty Encrypted Key for Direct Key Agreement):
//! `BASE64URL(header) "." "" "." BASE64URL(iv) "." BASE64URL(ciphertext) "." BASE64URL(tag)`

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use anyhow::{Result, anyhow, bail};
use p256::SecretKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::crypto::{b64url, b64url_decode, p256_public_from_jwk, p256_public_jwk};

/// Content-encryption algorithms we support (HAIP requires both; the wallet
/// SHOULD prefer A256GCM).
pub const ENC_ALGS: [&str; 2] = ["A128GCM", "A256GCM"];

/// Generate a fresh ephemeral P-256 key pair for ECDH-ES, returned as a
/// `(private_jwk, public_jwk)` pair. The private JWK carries `d` (plus `x`/`y`);
/// the public JWK is the bare EC key (`kty`/`crv`/`x`/`y`) — the caller decorates
/// it with `use`/`alg`/`kid` for `client_metadata.jwks`.
pub fn gen_enc_keypair() -> (Value, Value) {
    let secret = SecretKey::random(&mut rand::rngs::OsRng);
    let public = secret.public_key();
    (private_jwk(&secret), p256_public_jwk(&public))
}

/// Encrypt `plaintext` to `recipient_pub_jwk` (an EC P-256 JWK) using ECDH-ES
/// Direct Key Agreement + `enc_alg` (`A128GCM` or `A256GCM`). `kid` is copied into
/// the JWE header so the recipient knows which advertised key was used (RFC 7516
/// §4.1.6). Returns the compact JWE string.
pub fn encrypt(recipient_pub_jwk: &Value, kid: &str, enc_alg: &str, plaintext: &[u8]) -> Result<String> {
    let keydatalen = keydatalen_bits(enc_alg)?;
    let recipient_pub = p256_public_from_jwk(recipient_pub_jwk)?;

    // Sender's ephemeral key (the JWE `epk`).
    let eph_secret = SecretKey::random(&mut rand::rngs::OsRng);
    let epk = p256_public_jwk(&eph_secret.public_key());

    // Z = ECDH(eph_priv, recipient_pub) → the shared secret's x-coordinate.
    let shared = p256::ecdh::diffie_hellman(eph_secret.to_nonzero_scalar(), recipient_pub.as_affine());
    let cek = concat_kdf(shared.raw_secret_bytes().as_slice(), keydatalen, enc_alg.as_bytes());

    // Protected header. apu/apv are omitted (treated as empty in the Concat KDF).
    let header = json!({ "alg": "ECDH-ES", "enc": enc_alg, "epk": epk, "kid": kid });
    let header_b64 = b64url(&serde_json::to_vec(&header).expect("JWE header serializes"));

    // 96-bit IV; AAD is the ASCII-encoded protected header (RFC 7516 §5.1).
    let iv = random_iv();
    let mut buf = plaintext.to_vec();
    let tag = gcm_encrypt(enc_alg, &cek, &iv, header_b64.as_bytes(), &mut buf)?;

    // Compact: header . (empty key) . iv . ciphertext . tag
    Ok(format!(
        "{header_b64}..{}.{}.{}",
        b64url(&iv),
        b64url(&buf),
        b64url(&tag),
    ))
}

/// Decrypt a compact JWE produced by [`encrypt`] using `recipient_priv_jwk` (a
/// P-256 private JWK carrying `d`). Reads `enc`/`epk`/`kid` from the header,
/// re-derives the CEK by ECDH against the embedded `epk`, and AEAD-opens with the
/// protected header as the AAD. Returns the plaintext bytes.
pub fn decrypt(jwe: &str, recipient_priv_jwk: &Value) -> Result<Vec<u8>> {
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        bail!("compact JWE must have 5 parts, got {}", parts.len());
    }
    let (header_b64, encrypted_key, iv_b64, ct_b64, tag_b64) =
        (parts[0], parts[1], parts[2], parts[3], parts[4]);

    let header: Value = serde_json::from_slice(&b64url_decode(header_b64)?)?;
    if header.get("alg").and_then(Value::as_str) != Some("ECDH-ES") {
        bail!("unsupported JWE alg: expected ECDH-ES");
    }
    if !encrypted_key.is_empty() {
        bail!("ECDH-ES is Direct Key Agreement; the Encrypted Key must be empty");
    }
    let enc_alg = header
        .get("enc")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("JWE header missing enc"))?;
    let keydatalen = keydatalen_bits(enc_alg)?;
    let epk = header
        .get("epk")
        .ok_or_else(|| anyhow!("JWE header missing epk"))?;

    let sender_pub = p256_public_from_jwk(epk)?;
    let secret = p256_secret_from_jwk(recipient_priv_jwk)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), sender_pub.as_affine());
    let cek = concat_kdf(shared.raw_secret_bytes().as_slice(), keydatalen, enc_alg.as_bytes());

    let iv = b64url_decode(iv_b64)?;
    let tag = b64url_decode(tag_b64)?;
    let mut buf = b64url_decode(ct_b64)?;
    gcm_decrypt(enc_alg, &cek, &iv, header_b64.as_bytes(), &mut buf, &tag)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Concat KDF (NIST SP 800-56A §5.8.1, as profiled by RFC 7518 §4.6)
// ---------------------------------------------------------------------------

/// Derive `keydatalen` bits of keying material from the ECDH shared secret `z`.
/// For ECDH-ES Direct Key Agreement the AlgorithmID is the `enc` value and the
/// derived key IS the Content Encryption Key.
fn concat_kdf(z: &[u8], keydatalen: u32, alg_id: &[u8]) -> Vec<u8> {
    // OtherInfo = AlgorithmID ‖ PartyUInfo ‖ PartyVInfo ‖ SuppPubInfo ‖ SuppPrivInfo.
    // Each of the first three is a 32-bit big-endian length prefix followed by the
    // data; apu/apv are empty here. SuppPubInfo is the key length in bits.
    let mut other_info = Vec::new();
    other_info.extend_from_slice(&(alg_id.len() as u32).to_be_bytes());
    other_info.extend_from_slice(alg_id);
    other_info.extend_from_slice(&0u32.to_be_bytes()); // PartyUInfo (apu): empty
    other_info.extend_from_slice(&0u32.to_be_bytes()); // PartyVInfo (apv): empty
    other_info.extend_from_slice(&keydatalen.to_be_bytes()); // SuppPubInfo
    // SuppPrivInfo: empty.

    let want = (keydatalen / 8) as usize;
    let mut out = Vec::with_capacity(want);
    let mut counter: u32 = 1;
    while out.len() < want {
        let mut h = Sha256::new();
        h.update(counter.to_be_bytes());
        h.update(z);
        h.update(&other_info);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(want);
    out
}

// ---------------------------------------------------------------------------
// AES-GCM (detached tag, to match JWE's separate ciphertext/tag segments)
// ---------------------------------------------------------------------------

fn gcm_encrypt(enc_alg: &str, cek: &[u8], iv: &[u8], aad: &[u8], buf: &mut [u8]) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(iv);
    let tag = match enc_alg {
        "A128GCM" => Aes128Gcm::new_from_slice(cek)
            .map_err(|_| anyhow!("invalid A128GCM key length"))?
            .encrypt_in_place_detached(nonce, aad, buf)
            .map_err(|_| anyhow!("AES-128-GCM encryption failed"))?,
        "A256GCM" => Aes256Gcm::new_from_slice(cek)
            .map_err(|_| anyhow!("invalid A256GCM key length"))?
            .encrypt_in_place_detached(nonce, aad, buf)
            .map_err(|_| anyhow!("AES-256-GCM encryption failed"))?,
        other => bail!("unsupported JWE enc: {other}"),
    };
    Ok(tag.to_vec())
}

fn gcm_decrypt(enc_alg: &str, cek: &[u8], iv: &[u8], aad: &[u8], buf: &mut [u8], tag: &[u8]) -> Result<()> {
    let nonce = Nonce::from_slice(iv);
    let tag = aes_gcm::Tag::from_slice(tag);
    match enc_alg {
        "A128GCM" => Aes128Gcm::new_from_slice(cek)
            .map_err(|_| anyhow!("invalid A128GCM key length"))?
            .decrypt_in_place_detached(nonce, aad, buf, tag)
            .map_err(|_| anyhow!("AES-128-GCM authentication failed"))?,
        "A256GCM" => Aes256Gcm::new_from_slice(cek)
            .map_err(|_| anyhow!("invalid A256GCM key length"))?
            .decrypt_in_place_detached(nonce, aad, buf, tag)
            .map_err(|_| anyhow!("AES-256-GCM authentication failed"))?,
        other => bail!("unsupported JWE enc: {other}"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// P-256 JWK <-> key helpers. Public-key parsing/serialization is shared with the
// ES256 path (`crypto::p256_public_from_jwk` / `crypto::p256_public_jwk`); only
// the private-key (`d`) helpers are JWE-specific and live here.
// ---------------------------------------------------------------------------

fn keydatalen_bits(enc_alg: &str) -> Result<u32> {
    match enc_alg {
        "A128GCM" => Ok(128),
        "A256GCM" => Ok(256),
        other => bail!("unsupported JWE enc: {other}"),
    }
}

fn random_iv() -> [u8; 12] {
    use rand::RngCore;
    let mut iv = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    iv
}

fn private_jwk(sk: &SecretKey) -> Value {
    let mut jwk = p256_public_jwk(&sk.public_key());
    jwk.as_object_mut()
        .expect("p256_public_jwk is an object")
        .insert("d".into(), json!(b64url(&sk.to_bytes())));
    jwk
}

fn p256_secret_from_jwk(jwk: &Value) -> Result<SecretKey> {
    let d = b64url_decode(
        jwk.get("d").and_then(Value::as_str).ok_or_else(|| anyhow!("P-256 private JWK missing d"))?,
    )?;
    SecretKey::from_slice(&d).map_err(|e| anyhow!("invalid P-256 private scalar: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(enc_alg: &str) {
        let (priv_jwk, pub_jwk) = gen_enc_keypair();
        let msg = br#"{"vp_token":{"diploma":["abc~def~kb"]},"state":"s123"}"#;
        let jwe = encrypt(&pub_jwk, "verifier-key-1", enc_alg, msg).expect("encrypts");
        assert_eq!(jwe.split('.').count(), 5);
        // The header echoes the kid + alg/enc; the body is opaque.
        assert!(!jwe.contains("vp_token"));
        let out = decrypt(&jwe, &priv_jwk).expect("decrypts");
        assert_eq!(out, msg);
    }

    #[test]
    fn roundtrip_a128gcm() {
        roundtrip("A128GCM");
    }

    #[test]
    fn roundtrip_a256gcm() {
        roundtrip("A256GCM");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (priv_jwk, pub_jwk) = gen_enc_keypair();
        let jwe = encrypt(&pub_jwk, "k", "A256GCM", b"hello world").expect("encrypts");
        let mut parts: Vec<String> = jwe.split('.').map(String::from).collect();
        // Flip a byte in the ciphertext segment.
        let mut ct = b64url_decode(&parts[3]).unwrap();
        ct[0] ^= 0x01;
        parts[3] = b64url(&ct);
        let tampered = parts.join(".");
        assert!(decrypt(&tampered, &priv_jwk).is_err(), "GCM tag must reject tampering");
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let (_priv_jwk, pub_jwk) = gen_enc_keypair();
        let (other_priv, _other_pub) = gen_enc_keypair();
        let jwe = encrypt(&pub_jwk, "k", "A128GCM", b"secret").expect("encrypts");
        assert!(decrypt(&jwe, &other_priv).is_err(), "a different key must not decrypt");
    }

    #[test]
    fn tampered_tag_fails() {
        let (priv_jwk, pub_jwk) = gen_enc_keypair();
        let jwe = encrypt(&pub_jwk, "k", "A128GCM", b"abc").expect("encrypts");
        let mut parts: Vec<String> = jwe.split('.').map(String::from).collect();
        let mut tag = b64url_decode(&parts[4]).unwrap();
        tag[0] ^= 0xff;
        parts[4] = b64url(&tag);
        assert!(decrypt(&parts.join("."), &priv_jwk).is_err());
    }
}
