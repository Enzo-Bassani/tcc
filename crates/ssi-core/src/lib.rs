//! # ssi-core
//!
//! The shared Self-Sovereign Identity engine for this project. It is deliberately
//! transport- and framework-agnostic so the same code runs on the server, in the
//! browser (compiled to WebAssembly), and — later — inside the Kotlin wallet.
//!
//! What lives here:
//! - [`crypto`] — base64url, SHA-256, compact JWS signing/verification (EdDSA + ES256).
//! - [`holder`] — a wallet/holder signing key (ES256 by default, EdDSA for compat).
//! - [`sd_jwt`] — the SD-JWT engine: disclosures, assembly, reconstruction, and
//!   full *presentation verification* (issuer signature + key-binding JWT).
//! - [`jwe`] — JWE (ECDH-ES P-256 + A128GCM/A256GCM) for OID4VP encrypted responses.
//! - [`status`] — IETF Token Status List bitstring + the verifier-side revocation check.
//! - [`issuer_trust`] — holder-side issuer acceptance: `x5c` credential/metadata trust + revocation badge.
//! - [`x509`] — X.509 parsing + `x5c` certificate-chain validation (HAIP issuer trust).
//! - [`trust`] — the verifier's user-managed set of trusted CA roots (anchors).
//! - [`dcql`] — the Digital Credentials Query Language (OID4VP 1.0) types + matcher.
//! - [`oid4vci`] — the holder-side OID4VCI key proof (the one thing a wallet signs at issuance).
//! - [`oid4vp`] — building Authorization Requests and validating VP Tokens.
//! - [`resolve`] — a `Fetcher` abstraction so the engine never hard-codes HTTP.
//! - [`wallet_sim`] — a simulated holder used to exercise the protocol in tests/demos.

pub mod crypto;
pub mod dcql;
pub mod holder;
pub mod issuer_trust;
pub mod jwe;
pub mod oid4vci;
pub mod oid4vp;
pub mod resolve;
pub mod sd_jwt;
pub mod status;
pub mod trust;
pub mod x509;

#[cfg(feature = "wallet-sim")]
pub mod wallet_sim;

#[cfg(feature = "testkit")]
pub mod testkit;
