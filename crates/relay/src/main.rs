//! Runs the OID4VP transport relay and serves the browser verifier app.
//!
//! ```sh
//! cargo run -p relay                 # serves http://localhost:8090 + ./web
//! RELAY_BIND=0.0.0.0:9000 RELAY_BASE_URL=https://relay.example \
//!     RELAY_WEB_DIR=web cargo run -p relay
//! ```

use axum::Json;
use relay::{RelayState, router};

/// The verifier app's credential catalogue is whatever Type Metadata the relay is
/// serving: this manifest lists the `*.json` artifacts in the metadata directory so
/// the browser can discover them (one source of truth — dropping a file in the
/// served directory is enough, no client edit needed).
async fn metadata_manifest(dir: String) -> Json<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    Json(names)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind = std::env::var("RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8090".into());
    let base_url = std::env::var("RELAY_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));
    let web_dir = std::env::var("RELAY_WEB_DIR").unwrap_or_else(|_| "web".into());
    // The verifier app is metadata-driven: it fetches SD-JWT VC Type Metadata to
    // build its credential catalogue and attribute picker, demonstrating that the
    // verifier is universal (not diploma-specific). Serve the static artifacts.
    let metadata_dir =
        std::env::var("RELAY_METADATA_DIR").unwrap_or_else(|_| "type-metadata".into());

    let state = RelayState::new(base_url.clone());
    // A nested service is matched before the `web/` fallback, so `/type-metadata/*`
    // serves the Type Metadata artifacts while everything else falls back to the app;
    // `/type-metadata.json` (a sibling, not under the nested prefix) lists them.
    let manifest_dir = metadata_dir.clone();
    let app = router(state, Some(&web_dir))
        .route(
            "/type-metadata.json",
            axum::routing::get(move || metadata_manifest(manifest_dir.clone())),
        )
        .nest_service("/type-metadata", tower_http::services::ServeDir::new(&metadata_dir));

    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    tracing::info!("relay listening on {bind} (base {base_url}), serving '{web_dir}/'");
    axum::serve(listener, app).await.unwrap();
}
