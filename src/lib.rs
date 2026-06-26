//! University issuer backend — issues academic diplomas as SD-JWT Verifiable
//! Credentials over OID4VCI.

pub mod config;
pub mod db;
pub mod diploma;
pub mod error;
pub mod identity;
pub mod handlers;
pub mod oid4vci;
pub mod oidc_mock;
pub mod router;
pub mod state;
pub mod status;
pub mod telemetry;

// Cryptographic + SD-JWT primitives and the holder keypair are re-exported from
// the shared `ssi-core` crate, so issuer call sites can use `crate::crypto`,
// `crate::sd_jwt`, `crate::holder`.
pub use ssi_core::{crypto, holder, sd_jwt};

pub use error::{AppError, AppResult};
pub use identity::IssuerIdentity;
pub use state::AppState;
