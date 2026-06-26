//! The verifier's trust-anchor store: a user-managed set of trusted root CA
//! certificates, browser-root-store style.
//!
//! This is the "more open, adapted to Brazil" trust model: instead of the EU's
//! monolithic ETSI Trusted Lists, the verifier carries a flat set of CA roots it
//! accepts. A mock **ICP-Brasil** root is bundled as a default ([`TrustStore::with_defaults`]),
//! but it is an ordinary, removable entry — there are no hardcoded/un-removable
//! anchors. The user may add or remove any anchor. An issuer's `x5c` chain is
//! trusted iff it validates up to one of these anchors (see [`crate::x509`]).
//!
//! Anchors are kept as PEM strings — the form that crosses the wasm boundary and
//! lives in the browser's `localStorage` — parsed to [`Cert`] on insert.

use anyhow::{Context, Result, bail};

use crate::x509::Cert;

/// The bundled default trust anchor: the mock ICP-Brasil root CA. Adapted to
/// Brazil per the project goals; a real deployment would ship the genuine
/// ICP-Brasil root(s) here instead.
pub const ICP_BRASIL_MOCK_ROOT_PEM: &str = include_str!("../fixtures/pki/icp_brasil_root.pem");

/// One trusted root, with display metadata for the management UI.
#[derive(Clone)]
pub struct Anchor {
    /// Subject CN (or a placeholder), for display.
    pub label: String,
    /// Lowercase-hex SHA-256 of the cert DER — the stable id used to remove it.
    pub fingerprint: String,
    /// The PEM the anchor was loaded from (round-trips to `localStorage`).
    pub pem: String,
}

/// A managed set of trusted root CA certificates.
///
/// The parsed [`Cert`]s are kept in `certs`, parallel to `anchors` (index `i` of
/// one corresponds to index `i` of the other), so the verification hot path can
/// borrow them as a `&[Cert]` slice ([`Self::anchor_certs`]) without cloning.
#[derive(Clone, Default)]
pub struct TrustStore {
    anchors: Vec<Anchor>,
    certs: Vec<Cert>,
}

impl TrustStore {
    /// An empty store (trusts nothing — every chain fails `trusted_issuer`).
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store seeded with the bundled default anchors (the mock ICP-Brasil root).
    pub fn with_defaults() -> Self {
        let mut store = Self::default();
        store
            .add_pem(ICP_BRASIL_MOCK_ROOT_PEM)
            .expect("bundled ICP-Brasil mock root must parse");
        store
    }

    /// Build a store from a list of PEM strings (e.g. from `localStorage`).
    pub fn from_pems(pems: &[String]) -> Result<Self> {
        let mut store = Self::default();
        for pem in pems {
            store.add_pem(pem)?;
        }
        Ok(store)
    }

    /// Add a trust anchor from a PEM certificate. Only CA certificates are
    /// accepted. De-dupes by fingerprint; returns `true` if it was newly added.
    pub fn add_pem(&mut self, pem: &str) -> Result<bool> {
        let cert = Cert::from_pem(pem).context("trust anchor is not a valid PEM certificate")?;
        if !cert.is_ca() {
            bail!(
                "certificate '{}' is not a CA and cannot be used as a trust anchor",
                cert.label()
            );
        }
        let fingerprint = cert.fingerprint();
        if self.anchors.iter().any(|a| a.fingerprint == fingerprint) {
            return Ok(false);
        }
        self.anchors.push(Anchor {
            label: cert.label(),
            fingerprint,
            pem: pem.to_string(),
        });
        self.certs.push(cert);
        Ok(true)
    }

    /// Remove the anchor with the given fingerprint. Returns `true` if removed.
    pub fn remove(&mut self, fingerprint: &str) -> bool {
        match self.anchors.iter().position(|a| a.fingerprint == fingerprint) {
            Some(pos) => {
                self.anchors.remove(pos);
                self.certs.remove(pos);
                true
            }
            None => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }

    /// The parsed anchor certificates, for [`crate::x509::validate_chain`].
    ///
    /// Borrows the store's certs directly (no clone), so the per-credential
    /// verification path can pass `&[Cert]` straight through.
    pub fn anchor_certs(&self) -> &[Cert] {
        &self.certs
    }

    /// The anchors as a PEM list — what the browser persists to `localStorage`.
    pub fn to_pem_list(&self) -> Vec<String> {
        self.anchors.iter().map(|a| a.pem.clone()).collect()
    }

    pub fn fingerprints(&self) -> Vec<String> {
        self.anchors.iter().map(|a| a.fingerprint.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAF: &str = include_str!("../fixtures/pki/ufsc_leaf.pem");
    const MEC: &str = include_str!("../fixtures/pki/mec_intermediate.pem");
    const ROGUE_ROOT: &str = include_str!("../fixtures/pki/rogue_root.pem");

    #[test]
    fn defaults_contain_a_single_icp_brasil_root() {
        let store = TrustStore::with_defaults();
        assert_eq!(store.len(), 1);
        let anchor = &store.anchors()[0];
        assert!(anchor.label.contains("ICP-Brasil"));
        assert_eq!(anchor.fingerprint.len(), 64);
    }

    #[test]
    fn add_dedupes_and_remove_works() {
        let mut store = TrustStore::with_defaults();
        assert!(store.add_pem(ROGUE_ROOT).unwrap()); // newly added
        assert_eq!(store.len(), 2);
        assert!(!store.add_pem(ROGUE_ROOT).unwrap()); // duplicate ignored
        assert_eq!(store.len(), 2);

        let fp = store.fingerprints().into_iter().nth(1).unwrap();
        assert!(store.remove(&fp));
        assert_eq!(store.len(), 1);
        assert!(!store.remove(&fp)); // already gone
    }

    #[test]
    fn non_ca_certificate_is_rejected_as_anchor() {
        let mut store = TrustStore::empty();
        let err = store.add_pem(LEAF).unwrap_err();
        assert!(err.to_string().contains("not a CA"));
    }

    #[test]
    fn round_trips_through_pem_list() {
        let mut store = TrustStore::with_defaults();
        store.add_pem(ROGUE_ROOT).unwrap();
        let rebuilt = TrustStore::from_pems(&store.to_pem_list()).unwrap();
        assert_eq!(rebuilt.fingerprints(), store.fingerprints());
    }

    #[test]
    fn default_anchors_validate_the_real_chain() {
        let store = TrustStore::with_defaults();
        let chain = vec![Cert::from_pem(LEAF).unwrap(), Cert::from_pem(MEC).unwrap()];
        crate::x509::validate_chain(&chain, store.anchor_certs(), 1_700_000_000)
            .expect("UFSC→MEC chain validates against the bundled ICP-Brasil root");
    }
}
