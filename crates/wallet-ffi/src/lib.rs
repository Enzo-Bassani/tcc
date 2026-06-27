//! UniFFI facade over `ssi-core`'s holder engine for the Kotlin/Android wallet.
//!
//! The wallet's holder key is a **non-exportable** Android Keystore key, so the
//! engine cannot own it: signing is a callback ([`ForeignSigner`]) the wallet
//! implements. HTTP is likewise injectable ([`ForeignFetcher`]). Everything crosses
//! the FFI as owned JSON strings + simple types — `ssi-core`'s `serde_json::Value`,
//! its lifetimes and generics never cross. This is the **only** crate that depends
//! on `uniffi`; `ssi-core` itself stays UniFFI-agnostic.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use ssi_core::holder::Signer;
use ssi_core::resolve::Fetcher;
use ssi_core::wallet_sim::StoredCredential;

uniffi::setup_scaffolding!();

/// Errors surfaced to the wallet. `ssi-core`'s rich `anyhow` chains are flattened
/// into [`WalletError::Engine`] with their full `{:#}` message preserved.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum WalletError {
    #[error("invalid input: {detail}")]
    InvalidInput { detail: String },
    #[error("{detail}")]
    Engine { detail: String },
}

fn engine<T>(result: anyhow::Result<T>) -> Result<T, WalletError> {
    result.map_err(|e| WalletError::Engine { detail: format!("{e:#}") })
}

fn parse_json(label: &str, json: &str) -> Result<Value, WalletError> {
    serde_json::from_str(json).map_err(|e| WalletError::InvalidInput {
        detail: format!("{label} is not valid JSON: {e}"),
    })
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, WalletError> {
    serde_json::to_string(value).map_err(|e| WalletError::Engine {
        detail: format!("failed to serialize result: {e}"),
    })
}

// ----------------------------------------------------------------------------
// Signer callback
// ----------------------------------------------------------------------------

/// An error a [`ForeignSigner`] may raise (e.g. the Keystore refused to sign).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SignerError {
    #[error("signing failed: {detail}")]
    Failed { detail: String },
}

/// The holder's signer, implemented by the wallet over its (non-exportable)
/// platform key. Mirrors `ssi_core::holder::Signer` with FFI-friendly types: the
/// public JWK is JSON text and the signature is raw bytes (ES256 → JOSE R‖S).
#[uniffi::export(with_foreign)]
pub trait ForeignSigner: Send + Sync {
    /// The public JWK (`{kty,crv,x,y}`) as JSON text.
    fn public_jwk(&self) -> String;
    /// The JOSE `alg` this signer produces (`"ES256"` or `"EdDSA"`).
    fn algorithm(&self) -> String;
    /// The raw signature over `message`: ES256 → JOSE R‖S (64 bytes).
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, SignerError>;
}

/// Adapts a [`ForeignSigner`] to `ssi_core::holder::Signer`. The `alg` and public
/// JWK are fetched once and cached (the key is fixed); only `sign` calls back over
/// the FFI per use.
struct SignerAdapter {
    inner: Arc<dyn ForeignSigner>,
    alg: String,
    public_jwk: Value,
}

impl SignerAdapter {
    fn wrap(inner: Arc<dyn ForeignSigner>) -> Result<Arc<dyn Signer>, WalletError> {
        let alg = inner.algorithm();
        let public_jwk = parse_json("signer public_jwk", &inner.public_jwk())?;
        Ok(Arc::new(SignerAdapter { inner, alg, public_jwk }))
    }
}

impl Signer for SignerAdapter {
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.inner
            .sign(message.to_vec())
            .map_err(|e| anyhow::anyhow!("foreign signer failed: {e}"))
    }
    fn public_jwk(&self) -> Value {
        self.public_jwk.clone()
    }
    fn alg(&self) -> &str {
        &self.alg
    }
}

// ----------------------------------------------------------------------------
// Fetcher callback
// ----------------------------------------------------------------------------

/// An error a [`ForeignFetcher`] may raise (network/HTTP failure).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FetchError {
    #[error("fetch failed: {detail}")]
    Failed { detail: String },
}

/// A blocking HTTP GET the wallet implements — used only by [`credential_status`]
/// (the holder-side revocation badge). Mirrors `ssi_core::resolve::Fetcher`.
#[uniffi::export(with_foreign)]
pub trait ForeignFetcher: Send + Sync {
    fn get(&self, url: String) -> Result<Vec<u8>, FetchError>;
}

struct FetcherAdapter(Arc<dyn ForeignFetcher>);

impl Fetcher for FetcherAdapter {
    fn get(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        self.0
            .get(url.to_string())
            .map_err(|e| anyhow::anyhow!("foreign fetcher failed: {e}"))
    }
}

// ----------------------------------------------------------------------------
// Exported engine operations (JSON in / JSON out)
// ----------------------------------------------------------------------------

fn build_wallet(sd_jwts: &[String], signer: Arc<dyn Signer>) -> Vec<StoredCredential> {
    sd_jwts
        .iter()
        .map(|sd_jwt| StoredCredential::new(sd_jwt.clone(), signer.clone()))
        .collect()
}

fn usize_selection(selection: HashMap<String, u32>) -> HashMap<String, usize> {
    selection.into_iter().map(|(k, v)| (k, v as usize)).collect()
}

/// Build the OID4VCI key proof JWT (`openid4vci-proof+jwt`) over the issuer's `c_nonce`.
#[uniffi::export]
pub fn build_vci_proof(
    signer: Arc<dyn ForeignSigner>,
    credential_issuer: String,
    c_nonce: String,
) -> Result<String, WalletError> {
    let signer = SignerAdapter::wrap(signer)?;
    engine(ssi_core::oid4vci::build_vci_proof(signer.as_ref(), &credential_issuer, &c_nonce))
}

/// Build the OID4VP Authorization Response (the VP Token, JWE-encrypted for
/// `direct_post.jwt`) answering `request_json` with the held `sd_jwts`. `selection`
/// maps a DCQL query id to the index (into `sd_jwts`) the holder chose for it.
#[uniffi::export]
pub fn create_response(
    request_json: String,
    sd_jwts: Vec<String>,
    selection: HashMap<String, u32>,
    signer: Arc<dyn ForeignSigner>,
) -> Result<String, WalletError> {
    let request = parse_json("request", &request_json)?;
    let wallet = build_wallet(&sd_jwts, SignerAdapter::wrap(signer)?);
    let response = engine(ssi_core::wallet_sim::create_response_selecting(
        &request,
        &wallet,
        &usize_selection(selection),
    ))?;
    to_json(&response)
}

/// Build just the VP Token (no Authorization-Response wrapping/encryption).
#[uniffi::export]
pub fn create_vp_token(
    request_json: String,
    sd_jwts: Vec<String>,
    selection: HashMap<String, u32>,
    signer: Arc<dyn ForeignSigner>,
) -> Result<String, WalletError> {
    let request = parse_json("request", &request_json)?;
    let wallet = build_wallet(&sd_jwts, SignerAdapter::wrap(signer)?);
    let token = engine(ssi_core::wallet_sim::create_vp_token_selecting(
        &request,
        &wallet,
        &usize_selection(selection),
    ))?;
    to_json(&token)
}

/// The held credentials that satisfy each DCQL query in `request_json`, with what
/// each would disclose and always-share — for the consent UI. Returns the engine's
/// `QueryMatch[]` as JSON.
#[uniffi::export]
pub fn find_matches(request_json: String, sd_jwts: Vec<String>) -> Result<String, WalletError> {
    let request = parse_json("request", &request_json)?;
    let matches = engine(ssi_core::wallet_sim::find_matches(&request, &sd_jwts))?;
    to_json(&matches)
}

/// The full reconstructed claim set of a stored SD-JWT (all disclosures applied), as JSON.
#[uniffi::export]
pub fn read_credential(sd_jwt: String) -> Result<String, WalletError> {
    let claims = engine(read_claims(&sd_jwt))?;
    to_json(&claims)
}

fn read_claims(sd_jwt: &str) -> anyhow::Result<Value> {
    let (issuer_jwt, disclosures) = ssi_core::sd_jwt::split(sd_jwt);
    let (_header, payload) = ssi_core::crypto::decode_jws_unverified(&issuer_jwt)?;
    ssi_core::sd_jwt::reconstruct_claims(&payload, &disclosures)
}

/// Verify a signed OID4VP Authorization Request (JAR) against the QR `client_id`,
/// returning the request claims as JSON.
#[uniffi::export]
pub fn verify_request(request_jwt: String, client_id: String) -> Result<String, WalletError> {
    let claims = engine(ssi_core::oid4vp::verify_request(&request_jwt, &client_id))?;
    to_json(&claims)
}

/// Verify a received SD-JWT VC's issuer trust (HAIP §6.1.1: the `x5c` chain validates
/// to one of `anchors_pem`, the signature verifies under the leaf, and `iss` binds to
/// it). `now_unix` is the validation time.
#[uniffi::export]
pub fn verify_issuer_credential(
    sd_jwt: String,
    anchors_pem: Vec<String>,
    now_unix: i64,
) -> Result<(), WalletError> {
    engine(ssi_core::issuer_trust::verify_issuer_credential(&sd_jwt, &anchors_pem, now_unix))
}

/// Verify signed Credential Issuer Metadata bound to `expected_issuer`; returns the
/// verified claims as JSON.
#[uniffi::export]
pub fn verify_signed_metadata(
    jwt: String,
    expected_issuer: String,
    anchors_pem: Vec<String>,
    now_unix: i64,
) -> Result<String, WalletError> {
    let claims = engine(ssi_core::issuer_trust::verify_signed_metadata(
        &jwt,
        &expected_issuer,
        &anchors_pem,
        now_unix,
    ))?;
    to_json(&claims)
}

/// The holder-side revocation state of a stored credential, fetching its Token
/// Status List through `fetcher`. Returns `"unknown"`, `"fresh"`, or `"revoked"`.
#[uniffi::export]
pub fn credential_status(
    sd_jwt: String,
    fetcher: Arc<dyn ForeignFetcher>,
    anchors_pem: Vec<String>,
    now_unix: i64,
) -> Result<String, WalletError> {
    let fetcher = FetcherAdapter(fetcher);
    let status = engine(ssi_core::issuer_trust::credential_status(
        &sd_jwt,
        &fetcher,
        &anchors_pem,
        now_unix,
    ))?;
    to_json(&status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi_core::holder::HolderKey;
    use ssi_core::{oid4vp, testkit};

    /// An in-process [`ForeignSigner`] backed by an in-memory [`HolderKey`] — stands
    /// in for the wallet's Keystore signer so the FFI surface is exercised with no JVM.
    struct LocalSigner(HolderKey);

    impl ForeignSigner for LocalSigner {
        fn public_jwk(&self) -> String {
            serde_json::to_string(&Signer::public_jwk(&self.0)).unwrap()
        }
        fn algorithm(&self) -> String {
            Signer::alg(&self.0).to_string()
        }
        fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, SignerError> {
            Signer::sign(&self.0, &message).map_err(|e| SignerError::Failed { detail: e.to_string() })
        }
    }

    fn name_query() -> ssi_core::dcql::DcqlQuery {
        serde_json::from_value(json!({
            "credentials": [{
                "id": "diploma",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [testkit::DEMO_VCT] },
                "claims": [ { "path": ["given_name"] } ]
            }]
        }))
        .unwrap()
    }

    #[test]
    fn build_vci_proof_through_ffi() {
        let signer: Arc<dyn ForeignSigner> = Arc::new(LocalSigner(HolderKey::generate()));
        let proof = build_vci_proof(signer, "https://issuer.example".into(), "n-1".into()).unwrap();
        let (header, payload) = ssi_core::crypto::decode_jws_unverified(&proof).unwrap();
        assert_eq!(header["typ"], "openid4vci-proof+jwt");
        assert_eq!(payload["nonce"], "n-1");
    }

    #[test]
    fn create_response_round_trips_through_the_real_verifier() {
        let holder = HolderKey::generate();
        let demo = testkit::mint_with_holder(false, holder.clone());

        let (nonce, state) = oid4vp::fresh_request_ids();
        let signed = oid4vp::build_signed_request(&name_query(), &nonce, &state, "https://verifier.example/r");
        let request = oid4vp::verify_request(&signed.request_jwt, &signed.client_id).unwrap();

        let signer: Arc<dyn ForeignSigner> = Arc::new(LocalSigner(holder));
        let response_json = create_response(
            serde_json::to_string(&request).unwrap(),
            vec![demo.sd_jwt.clone()],
            HashMap::new(),
            signer,
        )
        .unwrap();

        // The verifier accepts the FFI-built response end to end.
        let response: Value = serde_json::from_str(&response_json).unwrap();
        let vp_token = oid4vp::decrypt_response(&response, &signed.enc_private_jwk).unwrap();
        let report = oid4vp::validate_vp_token(&request, &vp_token, &demo.fetcher, &testkit::demo_trust_store());
        assert!(report.valid, "verifier should accept the FFI response: {report:?}");
    }

    #[test]
    fn find_matches_and_read_credential_through_ffi() {
        let demo = testkit::mint(false);
        let request = json!({ "dcql_query": name_query() });

        let matches_json = find_matches(request.to_string(), vec![demo.sd_jwt.clone()]).unwrap();
        assert!(matches_json.contains("\"query_id\":\"diploma\""));

        let claims_json = read_credential(demo.sd_jwt.clone()).unwrap();
        let claims: Value = serde_json::from_str(&claims_json).unwrap();
        assert_eq!(claims["vct"], testkit::DEMO_VCT);
    }

    #[test]
    fn verify_issuer_credential_and_status_through_ffi() {
        let demo = testkit::mint(false);
        let anchors = vec![ssi_core::trust::ICP_BRASIL_MOCK_ROOT_PEM.to_string()];
        verify_issuer_credential(demo.sd_jwt.clone(), anchors.clone(), 1_700_000_000).unwrap();

        struct MapFetcherShim(ssi_core::resolve::MapFetcher);
        impl ForeignFetcher for MapFetcherShim {
            fn get(&self, url: String) -> Result<Vec<u8>, FetchError> {
                Fetcher::get(&self.0, &url).map_err(|e| FetchError::Failed { detail: e.to_string() })
            }
        }
        let fetcher: Arc<dyn ForeignFetcher> = Arc::new(MapFetcherShim(demo.fetcher.clone()));
        let status = credential_status(demo.sd_jwt.clone(), fetcher, anchors, 1_700_000_000).unwrap();
        assert_eq!(status, "\"fresh\"");
    }
}
