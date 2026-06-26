//! Asserting end-to-end tests over the real relay (HTTP), plus the failure modes
//! and an issuer↔verifier interop check using the actual issuer crate.

mod common;

use common::{round_trip, spawn};
use serde_json::json;
use ssi_core::dcql::DcqlQuery;
use ssi_core::oid4vp;
use ssi_core::resolve::MapFetcher;
use ssi_core::testkit::{self, DEMO_VCT};
use ssi_core::wallet_sim::StoredCredential;

fn name_dcql() -> DcqlQuery {
    serde_json::from_value(json!({
        "credentials": [{
            "id": "diploma",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": [DEMO_VCT] },
            "claims": [ { "path": ["given_name"] }, { "path": ["family_name"] } ]
        }]
    }))
    .unwrap()
}

#[tokio::test]
async fn relay_round_trip_is_valid() {
    let relay = spawn().await;
    let demo = testkit::mint(false);
    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: demo.holder.clone(),
    }];
    let report = round_trip(&relay.base, &name_dcql(), &wallet, &demo.fetcher, &testkit::demo_trust_store())
        .await
        .unwrap();
    assert!(report.valid, "{report:?}");
}

#[tokio::test]
async fn revoked_credential_via_relay_is_invalid() {
    let relay = spawn().await;
    let demo = testkit::mint(true); // revoked
    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: demo.holder.clone(),
    }];
    let report = round_trip(&relay.base, &name_dcql(), &wallet, &demo.fetcher, &testkit::demo_trust_store())
        .await
        .unwrap();
    assert!(!report.valid);
    assert!(matches!(
        report.credentials[0].revocation,
        oid4vp::Check::Fail(_)
    ));
}

#[tokio::test]
async fn unsatisfiable_query_yields_no_presentation() {
    let relay = spawn().await;
    let demo = testkit::mint(false);
    let wallet = vec![StoredCredential {
        sd_jwt: demo.sd_jwt.clone(),
        holder: demo.holder.clone(),
    }];
    // Ask for a credential type the wallet does not hold → all-or-nothing: the
    // wallet returns no presentation (surfaced here as a create error).
    let dcql: DcqlQuery = serde_json::from_value(json!({
        "credentials": [{
            "id": "passport",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://example.com/passport"] }
        }]
    }))
    .unwrap();
    let result = round_trip(&relay.base, &dcql, &wallet, &demo.fetcher, &testkit::demo_trust_store()).await;
    assert!(result.is_err(), "wallet should refuse to present");
}

/// The real issuer crate mints a diploma carrying its x5c chain; the verifier
/// engine validates that chain to the bundled ICP-Brasil root and accepts it.
#[tokio::test]
async fn issuer_interop_real_diploma_verifies() {
    use issuer_backend::db::Student;
    use issuer_backend::identity::CertIdentity;
    use issuer_backend::{diploma, status as issuer_status};
    use ssi_core::holder::HolderKey;

    let relay = spawn().await;

    // The demo identity's `iss` is the cert-bound `DEMO_ISS` (a SAN the mock leaf
    // covers); reuse it for the vct/status URLs so they share one issuer identity.
    let identity = CertIdentity::demo().unwrap();
    let iss = CertIdentity::DEMO_ISS;
    let holder = HolderKey::generate();
    let vct = "https://diploma.ufsc.br/diploma";
    let status_uri = format!("{iss}/status-lists/{}", diploma::STATUS_LIST_ID);
    let status_index = 5;

    // Issue a real diploma SD-JWT VC via the issuer crate (no DB needed).
    let claims = diploma::build_claims(
        &Student::sample(),
        iss,
        vct,
        "urn:uuid:interop-1",
        &holder.public_jwk(),
        &status_uri,
        status_index,
    );
    let sd_jwt = diploma::issue(&identity, claims);

    // Publish a (valid) status list for the verifier. No DID document — the issuer
    // key comes from the x5c chain embedded in the credential.
    let bits = issuer_status::BitString::new(1024);
    let status_jwt =
        issuer_status::build_status_list_jwt(&identity, iss, diploma::STATUS_LIST_ID, &bits)
            .unwrap();
    let fetcher = MapFetcher::new().with(status_uri, status_jwt.into_bytes());

    // The verifier asks for the diploma holder's name (nested SD-JWT claims).
    let dcql: DcqlQuery = serde_json::from_value(json!({
        "credentials": [{
            "id": "diploma",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": [vct] },
            "claims": [
                { "path": ["student", "full_name"] },
                { "path": ["degree", "title"] }
            ]
        }]
    }))
    .unwrap();

    let wallet = vec![StoredCredential {
        sd_jwt,
        holder,
    }];
    let report = round_trip(&relay.base, &dcql, &wallet, &fetcher, &testkit::demo_trust_store())
        .await
        .unwrap();
    assert!(report.valid, "real diploma must verify: {report:?}");
    assert!(matches!(
        report.credentials[0].trusted_issuer,
        oid4vp::Check::Pass
    ));
    assert_eq!(
        report.credentials[0].disclosed_claims["student"]["full_name"],
        "Sample Student"
    );
}
