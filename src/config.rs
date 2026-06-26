//! Application configuration, loaded from `config/default.toml` with optional
//! `ISSUER__*` environment overrides.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub bind_addr: String,
    pub issuer_url: String,
    pub database_url: String,
    pub admin_user: String,
    pub admin_password: String,
}

impl AppConfig {
    pub fn load() -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .set_default("bind_addr", "127.0.0.1:8080")?
            .set_default("issuer_url", "http://localhost:8080")?
            .set_default("admin_user", "admin")?
            .set_default("admin_password", "admin")?
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::Environment::with_prefix("ISSUER").separator("__"))
            .build()?;
        Ok(cfg.try_deserialize()?)
    }

    /// The issuer URL without a trailing slash.
    pub fn issuer(&self) -> &str {
        self.issuer_url.trim_end_matches('/')
    }
}
