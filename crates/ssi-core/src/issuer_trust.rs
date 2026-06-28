//! Holder-side issuer acceptance — the wallet's side of HAIP §6.1.1 `x5c` trust.
//!
//! When a wallet receives a credential (or signed Credential Issuer Metadata) it
//! must decide whether the issuer is trustworthy *before* accepting it. That
//! decision is exactly the verifier's `x5c` issuer-trust check — [`crate::oid4vp`]
//! runs the same one at presentation time — so wallet and verifier agree on what a
//! trustworthy issuer credential is. This module bundles those checks behind
//! holder-facing entry points, reusing the shared [`crate::x509`] primitives, and
//! adds the holder-side revocation check that badges a stored credential.

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::resolve::Fetcher;
use crate::trust::TrustStore;
use crate::{crypto, sd_jwt, status, x509};

/// Verify a received compact SD-JWT VC under the HAIP §6.1.1 issuer-trust model:
/// the issuer-signed JWT's `x5c` chain validates to a trusted anchor, its ES256
/// signature verifies under the leaf certificate, and its `iss` is bound to that
/// leaf. The wallet calls this before accepting a credential; the SD-JWT is still
/// stored and later forwarded unchanged (this only gates *acceptance*).
pub fn verify_issuer_credential(sd_jwt: &str, anchors_pem: &[String], now_unix: i64) -> Result<()> {
    let (issuer_jwt, _disclosures) = sd_jwt::split(sd_jwt);
    verify_x5c_jws(&issuer_jwt, anchors_pem, now_unix)?;
    Ok(())
}

/// Verify signed Credential Issuer Metadata (OID4VCI §11.2.3 / HAIP §4.1): the
/// `signed_metadata` JWT validates under the same `x5c` machinery as a credential
/// and is additionally bound to `expected_issuer` — its `sub` / `credential_issuer`
/// claim, the Credential Issuer Identifier the wallet is talking to. Returns the
/// verified metadata claims.
pub fn verify_signed_metadata(
    jwt: &str,
    expected_issuer: &str,
    anchors_pem: &[String],
    now_unix: i64,
) -> Result<Value> {
    let payload = verify_x5c_jws(jwt, anchors_pem, now_unix)?;
    let sub = payload.get("sub").and_then(Value::as_str);
    let credential_issuer = payload.get("credential_issuer").and_then(Value::as_str);
    if sub != Some(expected_issuer) && credential_issuer != Some(expected_issuer) {
        bail!(
            "signed metadata does not authenticate the expected issuer '{expected_issuer}' \
             (sub={sub:?}, credential_issuer={credential_issuer:?})"
        );
    }
    Ok(payload)
}

/// The holder-side revocation state of a stored credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    /// The credential carries no status reference — nothing to check.
    Unknown,
    /// The status-list bit is clear: not revoked.
    Fresh,
    /// The status-list bit is set: revoked.
    Revoked,
}

/// Check a stored credential's revocation state against its Token Status List,
/// fetching the list through `fetcher`. Lets the wallet badge revoked credentials.
/// Trust in the status list is established independently of the credential's
/// signing key (its own `x5c` chain → a trusted anchor + `iss` identity binding),
/// so issuer key rotation doesn't break the check.
pub fn credential_status(
    sd_jwt: &str,
    fetcher: &dyn Fetcher,
    anchors_pem: &[String],
    now_unix: i64,
) -> Result<CredentialStatus> {
    let (issuer_jwt, disclosures) = sd_jwt::split(sd_jwt);
    let (_h, issuer_payload) = crypto::decode_jws_unverified(&issuer_jwt)?;
    let claims =
        sd_jwt::reconstruct_claims(&issuer_payload, &disclosures).unwrap_or(issuer_payload);

    let Some((uri, index)) = status::status_reference(&claims) else {
        return Ok(CredentialStatus::Unknown);
    };
    let issuer = claims.get("iss").and_then(Value::as_str);
    let trust = TrustStore::from_pems(anchors_pem)?;
    let jwt = String::from_utf8(fetcher.get(&uri)?)?;
    Ok(match status::check_status(&jwt, index, &trust, now_unix, issuer)? {
        status::StatusCheck::Valid => CredentialStatus::Fresh,
        status::StatusCheck::Revoked => CredentialStatus::Revoked,
    })
}

/// Verify a compact `x5c`-signed JWS under HAIP §6.1.1 and return its payload:
/// resolve the chain from the `x5c` header, validate it to a trusted anchor (which
/// also enforces leaf-not-CA and CA issuers), verify the ES256 signature under the
/// leaf key, and bind the JWT's `iss` to the leaf certificate. Shared by
/// [`verify_issuer_credential`] and [`verify_signed_metadata`], mirroring the
/// verifier's `oid4vp` issuer-trust path so the two never diverge.
fn verify_x5c_jws(jwt: &str, anchors_pem: &[String], now_unix: i64) -> Result<Value> {
    let (header, payload) = crypto::decode_jws_unverified(jwt)?;
    let chain = x509::parse_x5c(
        header
            .get("x5c")
            .ok_or_else(|| anyhow!("JWS header carries no x5c (HAIP §6.1.1)"))?,
    )?;
    let trust = TrustStore::from_pems(anchors_pem)?;

    // Chain → trusted anchor (validity, leaf-not-CA, CA issuers, links, anchor).
    x509::validate_chain(&chain, trust.anchor_certs(), now_unix)
        .map_err(|e| anyhow!("untrusted issuer certificate chain: {e:#}"))?;

    // ES256 signature under the leaf certificate's own key.
    sd_jwt::verify_issuer_signature(jwt, &chain[0].public_jwk()?)?;

    // Bind iss to the leaf certificate (string compare; never dereferenced).
    let iss = payload
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("JWS has no iss claim to bind to the leaf certificate"))?;
    x509::iss_matches_leaf(iss, &chain[0])?;

    Ok(payload)
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::*;
    use crate::trust::ICP_BRASIL_MOCK_ROOT_PEM;

    // A fixed "now" inside the 2020..2099 validity window of the mock PKI.
    const NOW: i64 = 1_700_000_000;

    fn anchors() -> Vec<String> {
        vec![ICP_BRASIL_MOCK_ROOT_PEM.to_string()]
    }

    #[test]
    fn accepts_a_genuine_issuer_credential() {
        let demo = crate::testkit::mint(false);
        verify_issuer_credential(&demo.sd_jwt, &anchors(), NOW)
            .expect("the demo diploma chains to the bundled ICP-Brasil root");
    }

    #[test]
    fn rejects_a_credential_under_an_untrusted_anchor() {
        let demo = crate::testkit::mint(false);
        let rogue = vec![include_str!("../fixtures/pki/rogue_root.pem").to_string()];
        assert!(verify_issuer_credential(&demo.sd_jwt, &rogue, NOW).is_err());
    }

    #[test]
    fn reports_fresh_and_revoked_status() {
        let fresh = crate::testkit::mint(false);
        assert_eq!(
            credential_status(&fresh.sd_jwt, &fresh.fetcher, &anchors(), NOW).unwrap(),
            CredentialStatus::Fresh,
        );
        let revoked = crate::testkit::mint(true);
        assert_eq!(
            credential_status(&revoked.sd_jwt, &revoked.fetcher, &anchors(), NOW).unwrap(),
            CredentialStatus::Revoked,
        );
    }

    #[test]
    fn verifies_signed_issuer_metadata_and_rejects_wrong_issuer_or_tampering() {
        use crate::x509::{Cert, demo};
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::DecodePrivateKey;
        use serde_json::json;

        // Sign issuer metadata with the demo leaf key, carrying the leaf+intermediate x5c.
        let leaf_key = SigningKey::from_pkcs8_pem(demo::UFSC_LEAF_KEY_PKCS8_PEM).unwrap();
        let x5c = json!([
            crypto::b64std(Cert::from_pem(demo::UFSC_LEAF_PEM).unwrap().der()),
            crypto::b64std(Cert::from_pem(demo::MEC_INTERMEDIATE_PEM).unwrap().der()),
        ]);
        let issuer = "https://diploma.ufsc.br"; // a SAN of the demo leaf
        let header = json!({ "alg": "ES256", "typ": "openid-credential-issuer+jwt", "x5c": x5c });
        let jwt = crypto::sign_jws_es256(&header, &json!({ "iss": issuer, "sub": issuer }), &leaf_key);

        // Happy path: trusted chain + iss bound to the leaf + sub == the issuer we expect.
        let claims = verify_signed_metadata(&jwt, issuer, &anchors(), NOW).unwrap();
        assert_eq!(claims["sub"], issuer);

        // A document authenticating a different issuer than the one we're talking to is rejected.
        assert!(verify_signed_metadata(&jwt, "https://evil.example", &anchors(), NOW).is_err());

        // A tampered signature is rejected.
        let tampered = format!("{}x", &jwt[..jwt.len() - 1]);
        assert!(verify_signed_metadata(&tampered, issuer, &anchors(), NOW).is_err());
    }
}
