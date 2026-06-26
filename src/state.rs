//! Shared application state, cloned into every request handler.

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::AppConfig;
use crate::identity::IssuerIdentity;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<AppConfig>,
    pub identity: Arc<dyn IssuerIdentity>,
}
