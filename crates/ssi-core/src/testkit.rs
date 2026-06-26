//! Test/demo helpers: mint a self-contained SD-JWT VC together with everything
//! needed to verify it (its `x5c` certificate chain and a status list), with no
//! issuer server or database. Used by this crate's tests and the relay walkthrough.
//!
//! Demo specifics (the mock UFSC issuer identity, [`DEMO_ISS`]) deliberately live
//! here — the *verifier engine itself* stays universal; this module is just the
//! fixtures that exercise it.
//!
//! The demo issuer signs **ES256** with the mock UFSC leaf key and embeds the
//! `x5c` chain `[UFSC leaf, MEC intermediate]` (the ICP-Brasil root is excluded,
//! per HAIP §6.1.1). The verifier resolves the issuer key from that chain and
//! anchors it at the bundled mock ICP-Brasil root — see [`crate::x509`] / [`crate::trust`].

use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::DecodePrivateKey;
use serde_json::{Value, json};

use crate::holder::HolderKey;
use crate::resolve::MapFetcher;
use crate::status::BitString;
use crate::trust::TrustStore;
use crate::x509::Cert;
use crate::{crypto, sd_jwt};

// The committed mock PKI (see src/x509.rs `mock` + fixtures/pki/). The UFSC leaf
// material is shared with the issuer crate via `x509::demo`.
use crate::x509::demo::{
    MEC_INTERMEDIATE_PEM, UFSC_LEAF_KEY_PKCS8_PEM as UFSC_LEAF_KEY, UFSC_LEAF_PEM,
};
const EXPIRED_LEAF_PEM: &str = include_str!("../fixtures/pki/expired_leaf.pem");
const EXPIRED_LEAF_KEY: &str = include_str!("../fixtures/pki/expired_leaf.key");
const ROGUE_LEAF_PEM: &str = include_str!("../fixtures/pki/rogue_leaf.pem");
const ROGUE_LEAF_KEY: &str = include_str!("../fixtures/pki/rogue_leaf.key");

/// The example credential type used across tests/demo.
pub const DEMO_VCT: &str = "https://credentials.example.com/university_diploma";

/// The `iss` URL the demo credential carries — an https URL bound to the leaf
/// certificate's SAN (never dereferenced; matched by string comparison).
pub const DEMO_ISS: &str = "https://diploma.ufsc.br";

/// A demo issuing identity: an ES256 signing key plus the `x5c` chain to embed.
pub struct DemoIssuer {
    signing: P256SigningKey,
    /// Standard-base64 DER certificates, leaf first (root excluded).
    x5c: Vec<String>,
    /// The default `iss` claim — an https URL bound to the leaf cert SAN.
    pub iss: String,
}

impl DemoIssuer {
    fn from_chain(key_pem: &str, chain_pem: &[&str]) -> DemoIssuer {
        let signing = P256SigningKey::from_pkcs8_pem(key_pem).expect("leaf key is valid PKCS#8");
        let x5c = chain_pem
            .iter()
            .map(|pem| crypto::b64std(Cert::from_pem(pem).expect("fixture cert parses").der()))
            .collect();
        DemoIssuer {
            signing,
            x5c,
            iss: DEMO_ISS.to_string(),
        }
    }

    /// The trusted UFSC issuer: leaf signed by MEC, chaining to the ICP-Brasil root.
    pub fn ufsc() -> DemoIssuer {
        DemoIssuer::from_chain(UFSC_LEAF_KEY, &[UFSC_LEAF_PEM, MEC_INTERMEDIATE_PEM])
    }

    /// An issuer whose leaf certificate has expired (chains correctly otherwise).
    pub fn expired() -> DemoIssuer {
        DemoIssuer::from_chain(EXPIRED_LEAF_KEY, &[EXPIRED_LEAF_PEM, MEC_INTERMEDIATE_PEM])
    }

    /// An issuer whose chain anchors at an untrusted (rogue) self-signed root.
    pub fn rogue() -> DemoIssuer {
        DemoIssuer::from_chain(ROGUE_LEAF_KEY, &[ROGUE_LEAF_PEM])
    }
}

/// A `TrustStore` seeded with the bundled mock ICP-Brasil root — the verifier-side
/// trust set for tests and the demo.
pub fn demo_trust_store() -> TrustStore {
    TrustStore::with_defaults()
}

/// A minted demo credential and everything needed to verify it — but with no
/// holder key. The holder lives elsewhere (e.g. the real Kotlin wallet), so only
/// its public JWK was supplied to [`mint_for_holder`].
pub struct MintedCredential {
    /// The compact SD-JWT VC (issuer JWT + all disclosures, no key binding).
    pub sd_jwt: String,
    /// The credential `iss` (an https URL bound to the leaf cert).
    pub issuer: String,
    pub status_uri: String,
    pub status_index: usize,
    /// A `Fetcher` pre-loaded with the (valid) status list. (No DID document —
    /// the issuer key comes from the `x5c` chain in the credential itself.)
    pub fetcher: MapFetcher,
}

/// A freshly-minted demo credential plus its holder key. This is a
/// [`MintedCredential`] with the locally-generated holder added; it `Deref`s to
/// the inner `MintedCredential` so `demo.sd_jwt`, `demo.fetcher`, etc. still work.
pub struct DemoCredential {
    /// The holder key whose public JWK is the credential's `cnf` (the wallet
    /// key). ES256 by default; [`mint_with_holder`] supplies the EdDSA compat path.
    pub holder: HolderKey,
    /// The minted credential (SD-JWT + status list fetcher + metadata).
    pub inner: MintedCredential,
}

impl std::ops::Deref for DemoCredential {
    type Target = MintedCredential;
    fn deref(&self) -> &MintedCredential {
        &self.inner
    }
}

/// Mint a demo SD-JWT VC from the trusted UFSC issuer. `revoked` controls whether
/// the status list marks it revoked. The holder key is generated here.
pub fn mint(revoked: bool) -> DemoCredential {
    mint_with(&DemoIssuer::ufsc(), None, revoked)
}

/// Mint a demo credential from a chosen [`DemoIssuer`] (and optional `iss`
/// override), generating a default **ES256** holder key. Used to exercise the
/// trust failure modes (untrusted root, expired cert, iss/SAN mismatch).
pub fn mint_with(issuer: &DemoIssuer, iss_override: Option<&str>, revoked: bool) -> DemoCredential {
    build_demo(issuer, iss_override, revoked, HolderKey::generate())
}

/// Mint a trusted-issuer demo credential bound to a caller-supplied holder key.
/// Lets tests exercise both the default ES256 holder and the EdDSA
/// backward-compatibility path ([`HolderKey::generate_ed25519`]).
pub fn mint_with_holder(revoked: bool, holder: HolderKey) -> DemoCredential {
    build_demo(&DemoIssuer::ufsc(), None, revoked, holder)
}

/// Shared body: mint the SD-JWT VC bound to `holder`'s public JWK, then package it
/// together with the holder key for presentation.
fn build_demo(
    issuer: &DemoIssuer,
    iss_override: Option<&str>,
    revoked: bool,
    holder: HolderKey,
) -> DemoCredential {
    let inner = mint_advanced(issuer, iss_override, revoked, &holder.public_jwk());
    DemoCredential { holder, inner }
}

/// Mint a demo SD-JWT VC whose `cnf.jwk` is the supplied holder **public** JWK,
/// from the trusted UFSC issuer. Used by the wallet conformance oracle.
pub fn mint_for_holder(revoked: bool, holder_jwk: &Value) -> MintedCredential {
    mint_advanced(&DemoIssuer::ufsc(), None, revoked, holder_jwk)
}

/// The flexible minting entry point: choose the [`DemoIssuer`] and optionally
/// override the `iss` claim (for the iss/SAN-mismatch test).
pub fn mint_advanced(
    issuer: &DemoIssuer,
    iss_override: Option<&str>,
    revoked: bool,
    holder_jwk: &Value,
) -> MintedCredential {
    let iss = iss_override.unwrap_or(&issuer.iss).to_string();
    let status_uri = "https://issuer.example/status/1".to_string();
    let status_index = 7usize;
    let x5c: Vec<Value> = issuer.x5c.iter().map(|c| json!(c)).collect();

    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "vct": DEMO_VCT,
        "iss": iss,
        "iat": now,
        "cnf": { "jwk": holder_jwk },
        "status": { "status_list": { "idx": status_index, "uri": status_uri } },
        "given_name": "Ada",
        "family_name": "Lovelace",
        "degree": "BSc Mathematics",
        "graduation_year": 1843,
    });
    let disclosures = sd_jwt::make_selectively_disclosable(
        &mut claims,
        &["given_name", "family_name", "degree", "graduation_year"],
    );

    // HAIP issuer-signed JWT header: ES256 + the x5c chain (no `kid`, no did:web).
    let header = json!({ "alg": "ES256", "typ": "dc+sd-jwt", "x5c": x5c });
    let issuer_jwt = crypto::sign_jws_es256(&header, &claims, &issuer.signing);
    let sd_jwt = sd_jwt::assemble(&issuer_jwt, &disclosures);

    // The signed status list (valid or revoked at our index), also ES256 + x5c.
    let mut bits = BitString::new(256);
    bits.set(status_index, revoked);
    let status_payload = json!({
        "iss": iss,
        "sub": status_uri,
        "iat": now,
        "status_list": { "bits": 1, "lst": bits.encode().unwrap() },
    });
    let status_header = json!({ "alg": "ES256", "typ": "statuslist+jwt", "x5c": x5c });
    let status_jwt = crypto::sign_jws_es256(&status_header, &status_payload, &issuer.signing);

    let fetcher = MapFetcher::new().with(status_uri.clone(), status_jwt.into_bytes());

    MintedCredential {
        sd_jwt,
        issuer: iss,
        status_uri,
        status_index,
        fetcher,
    }
}
