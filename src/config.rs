//! Runtime configuration.
//!
//! Everything is overridable via `SIMPLIFI_*` environment variables (compatible with the
//! 1Password `op run` pattern). Per SA-18 the Quicken web-client secret is NOT baked into
//! source — it must be supplied via `SIMPLIFI_CLIENT_SECRET` (see README for how to read
//! it out of your own browser session).

use std::path::PathBuf;

use reqwest::Url;

use crate::error::{Error, Result};
use crate::secrets::{credentials_from_env, Credentials, KeySource};

pub const DEFAULT_BASE_URL: &str = "https://services.quicken.com";
pub const DEFAULT_REDIRECT_URI: &str = "https://simplifi.quicken.com/login";
pub const DEFAULT_CLIENT_ID: &str = "acme_web";
pub const DEFAULT_APP_RELEASE: &str = "6.5.0";
pub const DEFAULT_APP_BUILD: &str = "63580";
/// Stable browser-like UA: part of presenting one consistent device identity (SA-03).
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

pub struct Config {
    pub base_url: Url,
    pub redirect_uri: String,
    pub client_id: String,
    /// Quicken's web-app OAuth client secret. Required for token exchange/refresh.
    /// Never baked into source (SA-18); supply via SIMPLIFI_CLIENT_SECRET.
    pub client_secret: Option<String>,
    pub app_release: String,
    pub app_build: String,
    pub user_agent: String,
    /// Explicit dataset override (multi-dataset accounts). Auto-discovered otherwise.
    pub dataset_id: Option<String>,
    /// Explicit ThreatMetrix session id (paste a real browser value if needed).
    /// Otherwise one UUID is generated ONCE and persisted — stable device identity (SA-03).
    pub tm_session_id: Option<String>,
    pub data_dir: PathBuf,
    pub key_source: KeySource,
    pub http_timeout_ms: u64,
    /// Global pacing floor between upstream requests (SA-03/SA-13).
    pub min_request_interval_ms: u64,
    pub max_pages: usize,
    pub page_limit: u32,
    /// If true AND credentials are in the env, an expired/failed refresh may fall back to
    /// a (budgeted, backed-off) credential login. Default FALSE: interactive login only.
    pub auto_password_login: bool,
    /// Hard cap on credential logins per rolling 24 h (SA-03). Persisted in the cache.
    pub max_credential_logins_per_24h: u32,
    /// Gate for HAR-unverified write endpoints (create/delete). Default FALSE.
    pub enable_unverified_writes: bool,
    /// Simplifi credentials, if present in the environment.
    pub credentials: Option<Credentials>,
    /// MCP layer: allow mutating tools (update/categorize/create/bulk-import).
    /// Default FALSE — the server is read-only until explicitly enabled (SA-09).
    pub mcp_allow_writes: bool,
    /// MCP layer: cached data older than this is re-synced before answering.
    pub mcp_max_stale_secs: u64,
    /// MCP layer: hard floor between upstream syncs, honored even for `refresh:true`
    /// (SA-13 — a refresh loop cannot amplify into continuous upstream load).
    pub mcp_min_sync_interval_secs: u64,
    /// MCP layer: rolling per-hour cap on mutations (SA-09). Bulk imports count one
    /// per row. 0 disables the quota (not recommended).
    pub mcp_max_writes_per_hour: u32,
}

impl Config {
    /// Defaults with no environment reads (embedders/tests fill fields directly).
    pub fn defaults() -> Self {
        Config {
            base_url: Url::parse(DEFAULT_BASE_URL).expect("static url"),
            redirect_uri: DEFAULT_REDIRECT_URI.to_string(),
            client_id: DEFAULT_CLIENT_ID.to_string(),
            client_secret: None,
            app_release: DEFAULT_APP_RELEASE.to_string(),
            app_build: DEFAULT_APP_BUILD.to_string(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
            dataset_id: None,
            tm_session_id: None,
            data_dir: default_data_dir(),
            key_source: KeySource::Auto,
            http_timeout_ms: 30_000,
            min_request_interval_ms: 250,
            max_pages: 200,
            page_limit: 5_000,
            auto_password_login: false,
            max_credential_logins_per_24h: 3,
            enable_unverified_writes: false,
            credentials: None,
            mcp_allow_writes: false,
            mcp_max_stale_secs: 120,
            mcp_min_sync_interval_secs: 30,
            mcp_max_writes_per_hour: 60,
        }
    }

    /// Defaults + `SIMPLIFI_*` env overrides.
    pub fn from_env() -> Result<Self> {
        let mut c = Config::defaults();
        if let Ok(v) = std::env::var("SIMPLIFI_BASE_URL") {
            c.base_url = Url::parse(&v)
                .map_err(|e| Error::Config(format!("SIMPLIFI_BASE_URL invalid: {e}")))?;
            if c.base_url.scheme() != "https" {
                return Err(Error::Config(
                    "SIMPLIFI_BASE_URL must be https".to_string(),
                ));
            }
        }
        if let Ok(v) = std::env::var("SIMPLIFI_REDIRECT_URI") {
            c.redirect_uri = v;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_CLIENT_ID") {
            c.client_id = v;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_CLIENT_SECRET") {
            if !v.is_empty() {
                c.client_secret = Some(v);
            }
        }
        if let Ok(v) = std::env::var("SIMPLIFI_APP_RELEASE") {
            c.app_release = v;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_APP_BUILD") {
            c.app_build = v;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_USER_AGENT") {
            c.user_agent = v;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_DATASET_ID") {
            if !v.is_empty() {
                c.dataset_id = Some(v);
            }
        }
        for var in ["SIMPLIFI_TM_SESSION_ID", "SIMPLIFI_THREAT_METRIX_SESSION_ID"] {
            if let Ok(v) = std::env::var(var) {
                if !v.is_empty() {
                    c.tm_session_id = Some(v);
                    break;
                }
            }
        }
        if let Ok(v) = std::env::var("SIMPLIFI_DATA_DIR") {
            c.data_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("SIMPLIFI_HTTP_TIMEOUT_MS") {
            c.http_timeout_ms = parse_num(&v, "SIMPLIFI_HTTP_TIMEOUT_MS")?;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_MIN_REQUEST_INTERVAL_MS") {
            c.min_request_interval_ms = parse_num(&v, "SIMPLIFI_MIN_REQUEST_INTERVAL_MS")?;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_MAX_PAGES") {
            c.max_pages = parse_num::<usize>(&v, "SIMPLIFI_MAX_PAGES")?;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_PAGE_LIMIT") {
            c.page_limit = parse_num::<u32>(&v, "SIMPLIFI_PAGE_LIMIT")?;
        }
        c.auto_password_login = env_flag("SIMPLIFI_AUTO_PASSWORD_LOGIN");
        if let Ok(v) = std::env::var("SIMPLIFI_MAX_CREDENTIAL_LOGINS_PER_24H") {
            c.max_credential_logins_per_24h =
                parse_num::<u32>(&v, "SIMPLIFI_MAX_CREDENTIAL_LOGINS_PER_24H")?;
        }
        c.enable_unverified_writes = env_flag("SIMPLIFI_ENABLE_UNVERIFIED_WRITES");
        c.credentials = credentials_from_env();
        c.mcp_allow_writes = env_flag("SIMPLIFI_MCP_ALLOW_WRITES");
        if let Ok(v) = std::env::var("SIMPLIFI_MCP_MAX_STALE_SECS") {
            c.mcp_max_stale_secs = parse_num(&v, "SIMPLIFI_MCP_MAX_STALE_SECS")?;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_MCP_MIN_SYNC_INTERVAL_SECS") {
            c.mcp_min_sync_interval_secs = parse_num(&v, "SIMPLIFI_MCP_MIN_SYNC_INTERVAL_SECS")?;
        }
        if let Ok(v) = std::env::var("SIMPLIFI_MCP_MAX_WRITES_PER_HOUR") {
            c.mcp_max_writes_per_hour = parse_num(&v, "SIMPLIFI_MCP_MAX_WRITES_PER_HOUR")?;
        }
        Ok(c)
    }

    /// Host allowlist for every upstream URL we follow (SA-05): exactly the base host.
    pub fn allowed_host(&self) -> Result<&str> {
        self.base_url
            .host_str()
            .ok_or_else(|| Error::Config("base_url has no host".to_string()))
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    )
}

fn parse_num<T: std::str::FromStr>(v: &str, name: &str) -> Result<T> {
    v.parse::<T>()
        .map_err(|_| Error::Config(format!("{name} must be a number, got {v:?}")))
}

fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("simplifi-mcp")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The security posture of a fresh config IS the product (SECURITY-AUDIT):
    /// every dangerous capability must ship OFF.
    #[test]
    fn defaults_fail_closed() {
        let c = Config::defaults();
        assert!(!c.mcp_allow_writes, "MCP writes must default OFF (SA-09)");
        assert!(!c.auto_password_login, "auto password login must default OFF (SA-03)");
        assert!(!c.enable_unverified_writes, "unverified endpoints must default OFF");
        assert_eq!(c.max_credential_logins_per_24h, 3, "SA-03 budget");
        assert_eq!(c.mcp_max_writes_per_hour, 60, "SA-09 write quota");
        assert!(c.mcp_min_sync_interval_secs >= 30, "SA-13 sync floor");
        assert!(c.min_request_interval_ms > 0, "SA-03 pacing floor");
        assert!(c.client_secret.is_none(), "no bundled client secret (SA-18)");
        assert!(c.credentials.is_none());
        assert_eq!(c.base_url.scheme(), "https");
    }

    #[test]
    fn allowed_host_is_exactly_the_base_host() {
        let c = Config::defaults();
        assert_eq!(c.allowed_host().unwrap(), "services.quicken.com");
    }

    #[test]
    fn default_data_dir_is_outside_the_source_tree() {
        let c = Config::defaults();
        assert!(
            !c.data_dir.starts_with(env!("CARGO_MANIFEST_DIR")),
            "cache must not default into the repo (SA-01): {:?}",
            c.data_dir
        );
    }
}
