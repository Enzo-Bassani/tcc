//! A **dumb** OID4VP transport relay that stays *zero-knowledge about the holder*.
//!
//! Its only job is to bridge a verifier (e.g. a browser on a laptop) and a wallet
//! (e.g. an app on a phone) that cannot reach each other directly. It stores and
//! forwards opaque blobs per session and **never parses a credential, never holds a
//! key, and performs no validation** — all crypto happens locally in the verifier
//! (the `ssi-core` engine, compiled to WASM in the browser).
//!
//! The **Authorization Response is always encrypted** (a JWE the wallet seals to the
//! verifier's ephemeral key, authenticated by the QR-anchored `did:jwk`), so the
//! relay can never read the holder's disclosed claims — even actively.
//!
//! The **signed Authorization Request** is delivered one of two ways, chosen by the
//! verifier per the QR-size/privacy trade-off (both keep the request *signed*, so the
//! relay can never tamper with it):
//! - **By reference (default):** the verifier `PUT`s the signed request JWT here; the
//!   wallet `GET`s it. The QR is tiny (`client_id` + `request_uri`). The relay *can*
//!   read the request (the DCQL query — the verifier's question, not holder data).
//! - **By value:** the request rides in the QR itself; it never touches the relay
//!   (maximum privacy, but a large/dense QR). The request slot is simply unused.
//!
//! Endpoints:
//! - `POST   /sessions`                 → create a session → `{id, request_uri, response_uri}`
//! - `PUT    /sessions/{id}/request`    → verifier uploads the signed request (by-reference mode)
//! - `GET    /sessions/{id}/request`    → wallet fetches it
//! - `POST   /sessions/{id}/response`   → wallet posts the (encrypted) Authorization Response
//! - `GET    /sessions/{id}/response`   → verifier polls for the response (`204` until present)
//!
//! It also serves the static browser app from a `web/` directory.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{post, put};
use axum::Json;
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

#[derive(Default)]
struct Session {
    /// The signed request JWT, wrapped as `{"request": "<jwt>"}` (by-reference mode only).
    request: Option<Value>,
    response: Option<Value>,
}

#[derive(Clone)]
pub struct RelayState {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    /// Public base URL, used to build absolute request/response URIs.
    base_url: String,
}

impl RelayState {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            base_url: base_url.into(),
        }
    }
}

/// Build the relay router. `web_dir` (if present) is served at `/`.
pub fn router(state: RelayState, web_dir: Option<&str>) -> Router {
    let api = Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions/{id}/request", put(put_request).get(get_request))
        .route("/sessions/{id}/response", post(post_response).get(get_response))
        .with_state(state)
        .layer(CorsLayer::permissive());

    match web_dir {
        Some(dir) => api.fallback_service(ServeDir::new(dir)),
        None => api,
    }
}

async fn create_session(State(st): State<RelayState>) -> impl IntoResponse {
    let id = uuid::Uuid::new_v4().simple().to_string();
    st.sessions
        .lock()
        .unwrap()
        .insert(id.clone(), Session::default());
    let base = &st.base_url;
    Json(json!({
        "id": id,
        "request_uri": format!("{base}/sessions/{id}/request"),
        "response_uri": format!("{base}/sessions/{id}/response"),
    }))
}

async fn put_request(
    State(st): State<RelayState>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> StatusCode {
    let mut sessions = st.sessions.lock().unwrap();
    match sessions.get_mut(&id) {
        Some(session) => {
            session.request = Some(body);
            StatusCode::NO_CONTENT
        }
        None => StatusCode::NOT_FOUND,
    }
}

async fn get_request(State(st): State<RelayState>, Path(id): Path<String>) -> impl IntoResponse {
    let sessions = st.sessions.lock().unwrap();
    match sessions.get(&id).and_then(|s| s.request.clone()) {
        Some(req) => Json(req).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn post_response(
    State(st): State<RelayState>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> StatusCode {
    let mut sessions = st.sessions.lock().unwrap();
    match sessions.get_mut(&id) {
        Some(session) => {
            session.response = Some(body);
            StatusCode::NO_CONTENT
        }
        None => StatusCode::NOT_FOUND,
    }
}

async fn get_response(State(st): State<RelayState>, Path(id): Path<String>) -> impl IntoResponse {
    let sessions = st.sessions.lock().unwrap();
    match sessions.get(&id) {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(session) => match &session.response {
            Some(resp) => Json(resp.clone()).into_response(),
            None => StatusCode::NO_CONTENT.into_response(), // still waiting
        },
    }
}
