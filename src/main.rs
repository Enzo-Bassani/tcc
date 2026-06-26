//! University issuer backend entry point.
//!
//! Run the server:   `cargo run`
//! Offline demo:     `cargo run -- issue-test`  (prints a sample diploma SD-JWT)

use std::sync::Arc;

use issuer_backend::config::AppConfig;
use issuer_backend::identity::CertIdentity;
use issuer_backend::{AppState, IssuerIdentity, db, diploma, holder::HolderKey, router, sd_jwt, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init();
    let config = AppConfig::load()?;
    // Prototype: sign with the bundled mock UFSC leaf (chaining to the mock
    // ICP-Brasil root the verifier trusts). Its `iss` is the fixed, cert-bound
    // identity (`CertIdentity::DEMO_ISS`), decoupled from `issuer_url` (the
    // deployment address). Production loads a real key + chain from a KMS/HSM.
    let identity: Arc<dyn IssuerIdentity> = Arc::new(CertIdentity::demo()?);

    match std::env::args().nth(1).as_deref() {
        Some("issue-test") => return issue_test(identity.as_ref(), &config),
        Some("type-metadata") => return write_type_metadata(),
        _ => {}
    }

    let db = db::connect(&config.database_url).await?;
    db::migrate(&db).await?;
    db::seed_students(&db).await?;
    tracing::info!("issuer iss: {}", identity.iss());

    let state = AppState {
        db,
        config: Arc::new(config.clone()),
        identity,
    };
    let app = router::build(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("listening on http://{}", config.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Offline `type-metadata` subcommand: (re)generate the committed SD-JWT VC Type
/// Metadata artifact for the diploma `vct`. The `vct` is a non-dereferenceable URN, so
/// this document is shared as a static file rather than served over HTTP; a test keeps
/// it in sync with [`diploma::type_metadata`].
fn write_type_metadata() -> anyhow::Result<()> {
    let doc = diploma::type_metadata(diploma::VCT);
    let mut json = serde_json::to_string_pretty(&doc)?;
    json.push('\n');
    let path = std::path::Path::new(diploma::TYPE_METADATA_ABS);
    std::fs::create_dir_all(path.parent().expect("path has parent"))?;
    std::fs::write(path, json)?;
    println!("wrote {}", diploma::TYPE_METADATA_PATH);
    Ok(())
}

/// Offline `issue-test` subcommand: sign a sample diploma and print the SD-JWT.
fn issue_test(identity: &dyn IssuerIdentity, config: &AppConfig) -> anyhow::Result<()> {
    let holder = HolderKey::generate();
    let student = db::Student::sample();
    let jti = uuid::Uuid::new_v4().to_string();
    let status_uri = format!(
        "{}/status-lists/{}",
        config.issuer(),
        diploma::STATUS_LIST_ID
    );
    let claims = diploma::build_claims(
        &student,
        identity.iss(),
        diploma::VCT,
        &jti,
        &holder.public_jwk(),
        &status_uri,
        0,
    );
    let sd_jwt = diploma::issue(identity, claims);

    println!("=== Compact SD-JWT (base64url) ===");
    println!("{sd_jwt}");
    println!("\n=== Decoded SD-JWT ===");
    println!("{}", serde_json::to_string_pretty(&sd_jwt::explain(&sd_jwt)?)?);
    Ok(())
}
