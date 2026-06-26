//! IETF Token Status List bitstring.
//!
//! A status list is a bitstring (LSB-first, 1 bit per credential). A set bit
//! means "revoked". The `lst` wire format is DEFLATE + base64url. Building and
//! signing a status-list *JWT* is the issuer's job; this crate provides the
//! bitstring codec and the verifier-side status check.

use anyhow::{Result, anyhow, bail};

use crate::crypto::{b64url, b64url_decode, decode_jws_unverified, verify_jws_with_jwk};
use crate::trust::TrustStore;
use crate::x509;

/// A revocation bitstring, one bit per credential, LSB-first within each byte.
pub struct BitString {
    bytes: Vec<u8>,
}

impl BitString {
    pub fn new(size_bits: usize) -> Self {
        Self {
            bytes: vec![0u8; size_bits.div_ceil(8)],
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn get(&self, index: usize) -> bool {
        let (byte, bit) = (index / 8, index % 8);
        byte < self.bytes.len() && (self.bytes[byte] >> bit) & 1 == 1
    }

    pub fn set(&mut self, index: usize, value: bool) {
        let (byte, bit) = (index / 8, index % 8);
        if byte >= self.bytes.len() {
            return;
        }
        if value {
            self.bytes[byte] |= 1 << bit;
        } else {
            self.bytes[byte] &= !(1 << bit);
        }
    }

    /// Encode as the Token Status List `lst` value: DEFLATE + base64url.
    pub fn encode(&self) -> Result<String> {
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write;
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(&self.bytes)?;
        Ok(b64url(&e.finish()?))
    }

    /// Decode a Token Status List `lst` value back into a bitstring.
    pub fn decode(lst: &str) -> Result<Self> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let compressed = b64url_decode(lst)?;
        let mut d = ZlibDecoder::new(&compressed[..]);
        let mut bytes = Vec::new();
        d.read_to_end(&mut bytes)?;
        Ok(Self { bytes })
    }
}

/// Outcome of a revocation check against a Token Status List.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCheck {
    Valid,
    Revoked,
}

/// Verify a `statuslist+jwt` and read the bit at `index`.
///
/// Unlike the credential — which is frozen at issuance and carries the very
/// certificate that signed it — the status list is fetched *fresh* and is signed
/// with the issuer's *current* key. So we cannot reuse the credential's leaf key:
/// after a key rotation the status list is signed by a new certificate while the
/// credential still embeds the old one. Instead we establish trust in the status
/// list independently:
///
/// 1. validate the status list's own `x5c` chain up to a trusted CA root;
/// 2. bind it to the credential issuer by **identity** (`iss`) — stable across
///    key rotation — rather than by key;
/// 3. verify the JWT signature against the status list leaf's own key.
///
/// Returns whether the referenced credential is revoked.
pub fn check_status(
    status_list_jwt: &str,
    index: usize,
    trust: &TrustStore,
    now_unix: i64,
    credential_iss: Option<&str>,
) -> Result<StatusCheck> {
    let (header, _) = decode_jws_unverified(status_list_jwt)?;
    let chain = x509::parse_x5c(
        header
            .get("x5c")
            .ok_or_else(|| anyhow!("status list JWT has no x5c header"))?,
    )?;
    // (1) the status list signer chains to a trusted anchor.
    x509::validate_chain(&chain, trust.anchor_certs(), now_unix)
        .map_err(|e| anyhow!("untrusted status list certificate chain: {e:#}"))?;
    // (3) the signature is by the status list leaf's own key.
    let (_header, payload) = verify_jws_with_jwk(status_list_jwt, &chain[0].public_jwk()?)?;
    // (2) same issuer as the credential — identity binding, key-agnostic.
    let status_iss = payload.get("iss").and_then(serde_json::Value::as_str);
    if let (Some(cred), Some(st)) = (credential_iss, status_iss)
        && cred != st
    {
        bail!("status list iss '{st}' does not match credential iss '{cred}'");
    }
    if let Some(iss) = status_iss {
        x509::iss_matches_leaf(iss, &chain[0])
            .map_err(|e| anyhow!("status list iss not bound to its certificate: {e}"))?;
    }
    let lst = payload
        .get("status_list")
        .and_then(|s| s.get("lst"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("status list JWT missing status_list.lst"))?;
    let bits = BitString::decode(lst)?;
    Ok(if bits.get(index) {
        StatusCheck::Revoked
    } else {
        StatusCheck::Valid
    })
}

/// Decode a credential's `status` claim into `(status_list_uri, index)`, if present.
pub fn status_reference(claims: &serde_json::Value) -> Option<(String, usize)> {
    let sl = claims.get("status")?.get("status_list")?;
    let uri = sl.get("uri")?.as_str()?.to_string();
    let idx = sl.get("idx")?.as_u64()? as usize;
    Some((uri, idx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_set_get_at_edges() {
        let mut bs = BitString::new(64);
        for idx in [0usize, 7, 8, 63] {
            assert!(!bs.get(idx));
            bs.set(idx, true);
            assert!(bs.get(idx));
            bs.set(idx, false);
            assert!(!bs.get(idx));
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut bs = BitString::new(1024);
        bs.set(3, true);
        bs.set(900, true);
        let encoded = bs.encode().unwrap();
        let decoded = BitString::decode(&encoded).unwrap();
        assert!(decoded.get(3));
        assert!(decoded.get(900));
        assert!(!decoded.get(4));
    }
}
