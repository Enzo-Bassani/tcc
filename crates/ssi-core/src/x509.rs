//! X.509 certificate parsing and chain validation for HAIP `x5c` issuer-trust.
//!
//! HAIP §6.1.1 requires an SD-JWT VC to carry the issuer's signing certificate
//! plus its trust chain in the `x5c` JOSE header (the trust-anchor root
//! excluded). The verifier extracts the leaf certificate's public key, validates
//! the chain up to a trusted CA root, and binds the credential's `iss` to the
//! leaf certificate. This module is the verifier side of that.
//!
//! Parsing uses the `x509-cert` crate (pure Rust, builds for wasm32). All
//! *signature* crypto goes through `p256` (we pull the raw SEC1 point and the
//! DER ECDSA-Sig-Value out of the certs), so we never depend on der/spki version
//! alignment with `p256`. Only P-256 / ES256 (`ecdsa-with-SHA256`) is supported —
//! the algorithm HAIP mandates and the one our mock ICP-Brasil PKI uses.

use anyhow::{Context, Result, anyhow, bail};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::{Value, json};
use x509_cert::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, SubjectAltName};

use crate::crypto;

/// OID `2.5.4.3` — `commonName`.
const CN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// OID `1.2.840.10045.4.3.2` — `ecdsa-with-SHA256` (ES256 certificate signatures).
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// A parsed X.509 certificate. Holds the canonical DER alongside the parsed
/// structure so the SHA-256 fingerprint is stable regardless of how it was loaded.
#[derive(Clone)]
pub struct Cert {
    inner: Certificate,
    der: Vec<u8>,
    /// The re-encoded TBSCertificate DER — the exact bytes the issuer signed.
    /// Cached at construction so signature verification (`verify_signed_by`)
    /// doesn't re-serialize it on every chain link / anchor candidate.
    tbs_der: Vec<u8>,
}

impl Cert {
    pub fn from_der(der: &[u8]) -> Result<Cert> {
        let inner = Certificate::from_der(der).context("parse DER certificate")?;
        let tbs_der = inner.tbs_certificate.to_der().context("re-encode TBSCertificate")?;
        Ok(Cert {
            inner,
            der: der.to_vec(),
            tbs_der,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Cert> {
        let inner = Certificate::from_pem(pem.as_bytes()).context("parse PEM certificate")?;
        let der = inner.to_der().context("re-encode certificate to DER")?;
        let tbs_der = inner.tbs_certificate.to_der().context("re-encode TBSCertificate")?;
        Ok(Cert { inner, der, tbs_der })
    }

    /// Parse one `x5c` header entry: **standard** base64 (not base64url) of DER,
    /// per RFC 7515 §4.1.6.
    pub fn from_x5c_entry(b64_std: &str) -> Result<Cert> {
        let der = crypto::b64std_decode(b64_std.trim())
            .context("x5c entry is not valid standard base64")?;
        Cert::from_der(&der)
    }

    /// The certificate DER (used for the fingerprint).
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Lowercase-hex SHA-256 of the DER — a stable id for de-dupe / removal.
    pub fn fingerprint(&self) -> String {
        hex_lower(&crypto::sha256(&self.der))
    }

    /// The raw SEC1 public-key point bytes from the SubjectPublicKeyInfo.
    fn spki_point(&self) -> &[u8] {
        self.inner
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(self.spki_point())
            .map_err(|e| anyhow!("certificate public key is not a valid P-256 point: {e}"))
    }

    /// The subject public key as an EC P-256 JWK (`{kty,crv,x,y}`), ready for
    /// `crypto::verify_jws_with_jwk`.
    pub fn public_jwk(&self) -> Result<Value> {
        let vk = self.verifying_key()?;
        let pt = vk.to_encoded_point(false);
        Ok(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": crypto::b64url(pt.x().ok_or_else(|| anyhow!("EC point has no x coordinate"))?),
            "y": crypto::b64url(pt.y().ok_or_else(|| anyhow!("EC point has no y coordinate"))?),
        }))
    }

    /// `commonName` from the subject, if present.
    pub fn subject_cn(&self) -> Option<String> {
        for rdn in self.inner.tbs_certificate.subject.0.iter() {
            for atv in rdn.0.iter() {
                if atv.oid == CN_OID {
                    // PrintableString/UTF8String/IA5String content bytes are all
                    // ASCII-compatible UTF-8, so decoding the raw value works.
                    if let Ok(s) = std::str::from_utf8(atv.value.value()) {
                        return Some(s.to_string());
                    }
                }
            }
        }
        None
    }

    /// dNSName + uniformResourceIdentifier entries from the SubjectAltName extension.
    pub fn san_identifiers(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(Some((_, san))) = self.inner.tbs_certificate.get::<SubjectAltName>() {
            for gn in san.0.iter() {
                match gn {
                    GeneralName::DnsName(n) => out.push(n.as_str().to_string()),
                    GeneralName::UniformResourceIdentifier(n) => out.push(n.as_str().to_string()),
                    _ => {}
                }
            }
        }
        out
    }

    /// A human label for the trust-anchor UI: the subject CN, else a placeholder.
    pub fn label(&self) -> String {
        self.subject_cn()
            .unwrap_or_else(|| "(certificate without commonName)".to_string())
    }

    /// `true` if BasicConstraints marks this as a CA.
    pub fn is_ca(&self) -> bool {
        matches!(
            self.inner.tbs_certificate.get::<BasicConstraints>(),
            Ok(Some((_, bc))) if bc.ca
        )
    }

    pub fn not_before(&self) -> i64 {
        self.inner
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs() as i64
    }

    pub fn not_after(&self) -> i64 {
        self.inner
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64
    }

    /// Verify that this certificate's signature was produced by `issuer`'s key.
    pub fn verify_signed_by(&self, issuer: &Cert) -> Result<()> {
        if self.inner.signature_algorithm.oid != ECDSA_WITH_SHA256 {
            bail!(
                "unsupported certificate signature algorithm {} (only ecdsa-with-SHA256)",
                self.inner.signature_algorithm.oid
            );
        }
        let vk = issuer.verifying_key()?;
        // Certificate signatures are DER ECDSA-Sig-Value (two INTEGERs), NOT the
        // fixed 64-byte r||s form a JWS uses.
        let sig = Signature::from_der(self.inner.signature.raw_bytes())
            .map_err(|e| anyhow!("certificate signature is not DER ECDSA: {e}"))?;
        vk.verify(&self.tbs_der, &sig)
            .map_err(|_| anyhow!("certificate signature does not verify against the issuer key"))
    }
}

/// Parse the `x5c` JOSE header value (a JSON array of standard-base64 DER strings,
/// leaf first) into certificates.
pub fn parse_x5c(x5c: &Value) -> Result<Vec<Cert>> {
    let arr = x5c.as_array().ok_or_else(|| anyhow!("x5c header is not an array"))?;
    if arr.is_empty() {
        bail!("x5c header is empty");
    }
    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            let s = v
                .as_str()
                .ok_or_else(|| anyhow!("x5c[{i}] is not a string"))?;
            Cert::from_x5c_entry(s).with_context(|| format!("x5c[{i}]"))
        })
        .collect()
}

/// Validate a certificate chain (`leaf` .. `intermediate`, root excluded) up to a
/// trusted anchor:
/// - every certificate is within its validity window at `now_unix`;
/// - every certificate used as an issuer in the chain asserts `cA`;
/// - each certificate is signed by the next one in the chain;
/// - the topmost certificate is signed by some trusted (CA, in-validity) anchor.
pub fn validate_chain(chain: &[Cert], anchors: &[Cert], now_unix: i64) -> Result<()> {
    if chain.is_empty() {
        bail!("empty certificate chain (no x5c leaf)");
    }
    if anchors.is_empty() {
        bail!("no trusted anchors configured");
    }

    for (i, cert) in chain.iter().enumerate() {
        check_validity(cert, now_unix)
            .with_context(|| format!("chain[{i}] ({})", cert.label()))?;
        if i == 0 {
            // The leaf is the end-entity signing certificate (HAIP §6.1.1): it
            // must NOT be a CA, so a CA cert cannot be presented as a signer.
            if cert.is_ca() {
                bail!(
                    "chain[0] ({}) is a CA certificate, not an end-entity signer",
                    cert.label()
                );
            }
        } else if !cert.is_ca() {
            bail!(
                "chain[{i}] ({}) acts as an issuer but is not a CA",
                cert.label()
            );
        }
    }

    for i in 0..chain.len() - 1 {
        chain[i]
            .verify_signed_by(&chain[i + 1])
            .with_context(|| format!("chain[{i}] is not signed by chain[{}]", i + 1))?;
    }

    let top = chain.last().expect("chain is non-empty");
    let mut skipped_non_ca = 0usize;
    let mut skipped_expired = 0usize;
    for anchor in anchors {
        if !anchor.is_ca() {
            skipped_non_ca += 1;
            continue;
        }
        if check_validity(anchor, now_unix).is_err() {
            skipped_expired += 1;
            continue;
        }
        if top.verify_signed_by(anchor).is_ok() {
            return Ok(());
        }
    }
    // Distinguish "no anchor signed the chain" from "every anchor was unusable"
    // (e.g. the only configured root has expired) so a misconfigured trust store
    // doesn't masquerade as an untrusted-credential failure.
    let evaluated = anchors.len() - skipped_non_ca - skipped_expired;
    let mut skipped = Vec::new();
    if skipped_expired > 0 {
        skipped.push(format!("{skipped_expired} expired"));
    }
    if skipped_non_ca > 0 {
        skipped.push(format!("{skipped_non_ca} non-CA"));
    }
    let skipped_note = if skipped.is_empty() {
        String::new()
    } else {
        format!(", {} skipped ({})", skipped_non_ca + skipped_expired, skipped.join(", "))
    };
    bail!(
        "certificate chain does not terminate at a trusted anchor \
         ({evaluated} of {} anchor(s) evaluated{skipped_note})",
        anchors.len()
    )
}

fn check_validity(cert: &Cert, now: i64) -> Result<()> {
    let (nb, na) = (cert.not_before(), cert.not_after());
    if now < nb {
        bail!("certificate not yet valid (notBefore {nb} > now {now})");
    }
    if now > na {
        bail!("certificate expired (notAfter {na} < now {now})");
    }
    Ok(())
}

/// Bind the credential's `iss` (an https URL) to the leaf certificate by **string
/// comparison only** — the URL is never dereferenced (works offline / on
/// localhost). Matches against SAN URI/dNSName entries, the URL host, or the
/// subject CN.
pub fn iss_matches_leaf(iss: &str, leaf: &Cert) -> Result<()> {
    let sans = leaf.san_identifiers();
    if sans.iter().any(|s| s == iss) {
        return Ok(());
    }
    if let Ok(url) = url::Url::parse(iss)
        && let Some(host) = url.host_str()
        && (sans.iter().any(|s| s == host) || leaf.subject_cn().as_deref() == Some(host))
    {
        return Ok(());
    }
    if leaf.subject_cn().as_deref() == Some(iss) {
        return Ok(());
    }
    bail!(
        "iss '{iss}' is not present in the leaf certificate (SAN: {sans:?}, CN: {:?})",
        leaf.subject_cn()
    )
}

/// Bundled mock PKI material for the demo issuer (UFSC leaf, chaining to the mock
/// ICP-Brasil root the verifier trusts by default). **Prototype only** — a real
/// deployment loads its private key + certificate chain from a KMS/disk instead.
/// Exposed (not feature-gated) so the issuer crate can sign with it.
pub mod demo {
    pub const UFSC_LEAF_PEM: &str = include_str!("../fixtures/pki/ufsc_leaf.pem");
    pub const UFSC_LEAF_KEY_PKCS8_PEM: &str = include_str!("../fixtures/pki/ufsc_leaf.key");
    pub const MEC_INTERMEDIATE_PEM: &str = include_str!("../fixtures/pki/mec_intermediate.pem");
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Offline generator for the committed mock ICP-Brasil → MEC → UFSC PKI fixtures.
/// Native/tooling only (pulls `rcgen`); never compiled into the wasm verifier.
/// Regenerate with: `cargo test -p ssi-core --features mock-pki -- --ignored regenerate_pki_fixtures`.
#[cfg(feature = "mock-pki")]
pub mod mock {
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, Ia5String, IsCa,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType, date_time_ymd,
    };

    /// The full mock PKI as PEM strings.
    pub struct Pki {
        pub root_pem: String,
        pub intermediate_pem: String,
        pub leaf_pem: String,
        pub leaf_key_pem: String,
        /// A leaf with `notAfter` in the past, chained to the same MEC/root — for
        /// the "expired certificate" test.
        pub expired_leaf_pem: String,
        pub expired_leaf_key_pem: String,
        /// An independent self-signed root + leaf NOT in the default trust store —
        /// for the "untrusted root" test.
        pub rogue_root_pem: String,
        pub rogue_leaf_pem: String,
        pub rogue_leaf_key_pem: String,
    }

    fn keypair() -> rcgen::KeyPair {
        rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate P-256 keypair")
    }

    fn ca_params(cn: &str, org: &str, path_len: u8, not_after_year: i32) -> CertificateParams {
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CountryName, "BR");
        p.distinguished_name.push(DnType::OrganizationName, org);
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.not_before = date_time_ymd(2020, 1, 1);
        p.not_after = date_time_ymd(not_after_year, 1, 1);
        p
    }

    fn leaf_params(cn: &str, not_after_year: i32) -> CertificateParams {
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CountryName, "BR");
        p.distinguished_name.push(
            DnType::OrganizationName,
            "Universidade Federal de Santa Catarina",
        );
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.subject_alt_names = vec![
            SanType::DnsName(Ia5String::try_from("diploma.ufsc.br").unwrap()),
            SanType::URI(Ia5String::try_from("https://diploma.ufsc.br").unwrap()),
            // Localhost SANs so the live issuer / walkthrough bind on localhost.
            SanType::DnsName(Ia5String::try_from("localhost").unwrap()),
            SanType::URI(Ia5String::try_from("http://localhost:8080").unwrap()),
        ];
        p.not_before = date_time_ymd(2020, 1, 1);
        p.not_after = date_time_ymd(not_after_year, 1, 1);
        p
    }

    /// Generate a fresh mock PKI. Keys are random per call; the output is committed
    /// once as fixtures so tests are deterministic thereafter.
    pub fn generate() -> Pki {
        let root_key = keypair();
        let root = ca_params("AC Raiz ICP-Brasil v MOCK", "ICP-Brasil", 1, 2099)
            .self_signed(&root_key)
            .expect("self-sign root");

        let mec_key = keypair();
        let mec = ca_params("AC MEC MOCK", "Ministerio da Educacao", 0, 2099)
            .signed_by(&mec_key, &root, &root_key)
            .expect("sign MEC intermediate");

        let sign_leaf = |year: i32| -> (String, String) {
            let key = keypair();
            let cert: Certificate = leaf_params("UFSC Emissor de Diplomas MOCK", year)
                .signed_by(&key, &mec, &mec_key)
                .expect("sign UFSC leaf");
            (cert.pem(), key.serialize_pem())
        };
        let (leaf_pem, leaf_key_pem) = sign_leaf(2099);
        let (expired_leaf_pem, expired_leaf_key_pem) = sign_leaf(2021);

        let rogue_root_key = keypair();
        let rogue_root = ca_params("AC Raiz Nao Confiavel MOCK", "Untrusted CA", 0, 2099)
            .self_signed(&rogue_root_key)
            .expect("self-sign rogue root");
        let rogue_leaf_key = keypair();
        let rogue_leaf = leaf_params("UFSC Emissor de Diplomas MOCK", 2099)
            .signed_by(&rogue_leaf_key, &rogue_root, &rogue_root_key)
            .expect("sign rogue leaf");

        Pki {
            root_pem: root.pem(),
            intermediate_pem: mec.pem(),
            leaf_pem,
            leaf_key_pem,
            expired_leaf_pem,
            expired_leaf_key_pem,
            rogue_root_pem: rogue_root.pem(),
            rogue_leaf_pem: rogue_leaf.pem(),
            rogue_leaf_key_pem: rogue_leaf_key.serialize_pem(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = include_str!("../fixtures/pki/icp_brasil_root.pem");
    const MEC: &str = include_str!("../fixtures/pki/mec_intermediate.pem");
    const LEAF: &str = include_str!("../fixtures/pki/ufsc_leaf.pem");
    const LEAF_KEY: &str = include_str!("../fixtures/pki/ufsc_leaf.key");
    const EXPIRED_LEAF: &str = include_str!("../fixtures/pki/expired_leaf.pem");
    const ROGUE_ROOT: &str = include_str!("../fixtures/pki/rogue_root.pem");
    const ROGUE_LEAF: &str = include_str!("../fixtures/pki/rogue_leaf.pem");

    // A fixed "now" inside the 2020..2099 validity window of the mock certs.
    const NOW: i64 = 1_700_000_000; // 2023-11-14

    fn leaf() -> Cert {
        Cert::from_pem(LEAF).unwrap()
    }
    fn mec() -> Cert {
        Cert::from_pem(MEC).unwrap()
    }
    fn root() -> Cert {
        Cert::from_pem(ROOT).unwrap()
    }

    #[test]
    fn parses_subject_san_and_constraints() {
        let leaf = leaf();
        assert!(leaf.subject_cn().unwrap().contains("UFSC"));
        let sans = leaf.san_identifiers();
        assert!(sans.contains(&"diploma.ufsc.br".to_string()));
        assert!(sans.contains(&"https://diploma.ufsc.br".to_string()));
        assert!(!leaf.is_ca());
        assert!(mec().is_ca());
        assert!(root().is_ca());
        assert_eq!(leaf.fingerprint().len(), 64);
    }

    #[test]
    fn valid_chain_reaches_trusted_anchor() {
        let chain = vec![leaf(), mec()];
        validate_chain(&chain, &[root()], NOW).expect("chain should anchor at ICP-Brasil root");
    }

    #[test]
    fn untrusted_root_is_rejected() {
        let chain = vec![leaf(), mec()];
        let err = validate_chain(&chain, &[Cert::from_pem(ROGUE_ROOT).unwrap()], NOW).unwrap_err();
        assert!(err.to_string().contains("does not terminate at a trusted anchor"));
    }

    #[test]
    fn empty_anchor_set_is_rejected() {
        assert!(validate_chain(&[leaf(), mec()], &[], NOW).is_err());
    }

    #[test]
    fn broken_link_is_rejected() {
        // leaf is signed by MEC, not by the rogue root — the link must fail.
        let chain = vec![leaf(), Cert::from_pem(ROGUE_ROOT).unwrap()];
        let err = validate_chain(&chain, &[root()], NOW).unwrap_err();
        assert!(err.to_string().contains("not signed by"));
    }

    #[test]
    fn expired_leaf_is_rejected() {
        let chain = vec![Cert::from_pem(EXPIRED_LEAF).unwrap(), mec()];
        let err = validate_chain(&chain, &[root()], NOW).unwrap_err();
        // The "expired" detail lives in the anyhow source chain ({:#} renders it).
        assert!(format!("{err:#}").contains("expired"));
    }

    #[test]
    fn rogue_chain_anchors_only_at_its_own_root() {
        let chain = vec![Cert::from_pem(ROGUE_LEAF).unwrap()];
        // Rejected under the real trust store...
        assert!(validate_chain(&chain, &[root()], NOW).is_err());
        // ...accepted if its own root is explicitly trusted.
        validate_chain(&chain, &[Cert::from_pem(ROGUE_ROOT).unwrap()], NOW).unwrap();
    }

    #[test]
    fn ca_certificate_is_rejected_as_a_leaf_signer() {
        // Presenting the MEC intermediate (a CA) as the leaf must fail: the
        // signing certificate has to be an end-entity cert (HAIP §6.1.1).
        let err = validate_chain(&[mec()], &[root()], NOW).unwrap_err();
        assert!(err.to_string().contains("is a CA certificate"));
    }

    #[test]
    fn iss_binding_matches_san_and_rejects_others() {
        let leaf = leaf();
        iss_matches_leaf("https://diploma.ufsc.br", &leaf).unwrap();
        iss_matches_leaf("http://localhost:8080", &leaf).unwrap();
        assert!(iss_matches_leaf("https://evil.example", &leaf).is_err());
    }

    #[test]
    fn leaf_public_jwk_verifies_a_signature_from_its_key() {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::DecodePrivateKey;
        let key = SigningKey::from_pkcs8_pem(LEAF_KEY).unwrap();
        let header = serde_json::json!({ "alg": "ES256" });
        let payload = serde_json::json!({ "hello": "diploma" });
        let jws = crypto::sign_jws_es256(&header, &payload, &key);
        let jwk = leaf().public_jwk().unwrap();
        crypto::verify_jws_with_jwk(&jws, &jwk).expect("leaf JWK verifies its own signature");
    }

    #[test]
    fn x5c_entry_requires_standard_base64_not_base64url() {
        let der = leaf().der().to_vec();
        // Standard base64 (what x5c uses) parses.
        Cert::from_x5c_entry(&crypto::b64std(&der)).unwrap();
        // base64url (no padding, '-'/'_' alphabet) must NOT be accepted as an x5c entry.
        assert!(Cert::from_x5c_entry(&crypto::b64url(&der)).is_err());
    }

    #[test]
    fn parse_x5c_reads_a_json_array_leaf_first() {
        let arr = serde_json::json!([crypto::b64std(leaf().der()), crypto::b64std(mec().der())]);
        let chain = parse_x5c(&arr).unwrap();
        assert_eq!(chain.len(), 2);
        assert!(chain[0].subject_cn().unwrap().contains("UFSC"));
        assert!(chain[1].is_ca());
    }
}

#[cfg(all(test, feature = "mock-pki"))]
mod regen {
    //! Writes the committed PKI fixtures. Run explicitly:
    //! `cargo test -p ssi-core --features mock-pki -- --ignored regenerate_pki_fixtures`.
    use std::fs;
    use std::path::Path;

    #[test]
    #[ignore = "regenerates committed fixtures on demand"]
    fn regenerate_pki_fixtures() {
        let pki = super::mock::generate();
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/pki");
        fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, body: &str| fs::write(dir.join(name), body).unwrap();
        write("icp_brasil_root.pem", &pki.root_pem);
        write("mec_intermediate.pem", &pki.intermediate_pem);
        write("ufsc_leaf.pem", &pki.leaf_pem);
        write("ufsc_leaf.key", &pki.leaf_key_pem);
        write("expired_leaf.pem", &pki.expired_leaf_pem);
        write("expired_leaf.key", &pki.expired_leaf_key_pem);
        write("rogue_root.pem", &pki.rogue_root_pem);
        write("rogue_leaf.pem", &pki.rogue_leaf_pem);
        write("rogue_leaf.key", &pki.rogue_leaf_key_pem);
        eprintln!("wrote mock PKI fixtures to {}", dir.display());
    }
}
