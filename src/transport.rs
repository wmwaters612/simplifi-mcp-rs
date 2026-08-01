//! HTTP transport abstraction.
//!
//! `Transport::Http` is a hardened reqwest client: rustls, `https_only`, redirects
//! disabled (`Policy::none()` — SA-05; upstream auth calls already required
//! `redirect: manual`), explicit timeouts. `Transport::Mock` (feature `mock`) serves
//! recorded fixtures so tests and demos run with zero live credentials.

use std::time::Duration;

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct ApiRequest {
    pub method: Method,
    pub url: Url,
    /// (header-name, value) pairs; callers build exact upstream header sets.
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct ApiResponse {
    pub status: u16,
    pub location: Option<String>,
    pub retry_after: Option<u64>,
    pub body: Vec<u8>,
}

impl ApiResponse {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    pub fn json_value(&self) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

pub enum Transport {
    Http(HttpTransport),
    #[cfg(feature = "mock")]
    Mock(crate::mock::MockTransport),
}

impl Transport {
    pub async fn execute(&self, req: ApiRequest) -> Result<ApiResponse> {
        match self {
            Transport::Http(t) => t.execute(req).await,
            #[cfg(feature = "mock")]
            Transport::Mock(t) => t.execute(req).await,
        }
    }
}

pub struct HttpTransport {
    client: reqwest::Client,
}

impl HttpTransport {
    pub fn new(timeout_ms: u64, user_agent: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(timeout_ms))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(user_agent)
            .build()
            .map_err(|e| Error::Transport(scrub_reqwest(e)))?;
        Ok(HttpTransport { client })
    }

    pub async fn execute(&self, req: ApiRequest) -> Result<ApiResponse> {
        let mut r = self.client.request(req.method, req.url);
        for (k, v) in &req.headers {
            r = r.header(*k, v);
        }
        if let Some(b) = &req.body {
            r = r.body(serde_json::to_vec(b)?);
        }
        let resp = r.send().await.map_err(|e| Error::Transport(scrub_reqwest(e)))?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Transport(scrub_reqwest(e)))?
            .to_vec();
        Ok(ApiResponse {
            status,
            location,
            retry_after,
            body,
        })
    }
}

/// Strip the URL (which may embed query material) from reqwest error text.
fn scrub_reqwest(e: reqwest::Error) -> String {
    e.without_url().to_string()
}

/// Validate an upstream-influenced URL before following it (SA-05): https only, host must
/// equal the allowlisted API host, no userinfo, no port override.
pub fn validate_upstream_url(url: &Url, allowed_host: &str) -> Result<()> {
    if url.scheme() != "https" {
        return Err(Error::UnsafeUrl(format!("non-https scheme: {}", url.scheme())));
    }
    match url.host_str() {
        Some(h) if h.eq_ignore_ascii_case(allowed_host) => {}
        other => {
            return Err(Error::UnsafeUrl(format!(
                "host {:?} not in allowlist [{allowed_host}]",
                other.unwrap_or("<none>")
            )))
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::UnsafeUrl("userinfo present".to_string()));
    }
    if url.port().is_some() {
        return Err(Error::UnsafeUrl("explicit port override".to_string()));
    }
    Ok(())
}
