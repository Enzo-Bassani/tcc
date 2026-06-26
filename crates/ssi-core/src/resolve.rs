//! Fetching external documents (DID documents, status lists) without hard-coding
//! an HTTP stack into the engine.
//!
//! On the server (and in tests) the [`HttpFetcher`] uses `reqwest`. In the
//! browser the engine never does HTTP itself: JavaScript pre-fetches the URLs
//! reported by [`crate::oid4vp::inspect`] and hands the bytes back via
//! [`MapFetcher`]. Both implement the same [`Fetcher`] trait, so the validation
//! code is identical in either environment.

use anyhow::{Result, anyhow};
use std::collections::HashMap;

/// A synchronous fetcher for `GET <url> -> bytes`.
pub trait Fetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>>;

    /// Convenience: fetch and parse as JSON.
    fn get_json(&self, url: &str) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.get(url)?)?)
    }
}

/// A fetcher backed by an in-memory `url -> bytes` map. Used in the browser
/// (JS supplies the bytes) and in tests (the harness supplies fixtures).
#[derive(Default, Clone)]
pub struct MapFetcher {
    docs: HashMap<String, Vec<u8>>,
}

impl MapFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, url: impl Into<String>, body: impl Into<Vec<u8>>) {
        self.docs.insert(url.into(), body.into());
    }

    pub fn with(mut self, url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        self.insert(url, body);
        self
    }

    /// Export the contents as a `{url: text}` map (lossily, as UTF-8). Used to
    /// hand the demo's in-memory issuer documents to the browser, which would
    /// otherwise fetch them over HTTP.
    pub fn as_text_map(&self) -> HashMap<String, String> {
        self.docs
            .iter()
            .map(|(k, v)| (k.clone(), String::from_utf8_lossy(v).into_owned()))
            .collect()
    }
}

impl Fetcher for MapFetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.docs
            .get(url)
            .cloned()
            .ok_or_else(|| anyhow!("no pre-fetched document for {url}"))
    }
}

/// A blocking HTTP fetcher (server / tests only).
#[cfg(feature = "native")]
#[derive(Default)]
pub struct HttpFetcher {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "native")]
impl HttpFetcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
        }
    }
}

#[cfg(feature = "native")]
impl Fetcher for HttpFetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self.client.get(url).send()?.error_for_status()?;
        Ok(resp.bytes()?.to_vec())
    }
}
