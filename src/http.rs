//! Optional Streamable-HTTP transport (feature `http`) with mandatory bearer auth.
//!
//! Downstream-auth hardening vs upstream (SECURITY-AUDIT / PORTING-SPEC section 9):
//! - **No anonymous surface**: a bearer token is REQUIRED; the server refuses to
//!   start without `SIMPLIFI_MCP_HTTP_TOKEN` (>= 32 chars — SA-07 entropy floor).
//!   There is no open `/oauth/register`, no allow-any redirect_uri, no HTML login
//!   form to brute-force (SA-02/SA-06/SA-19 removed by construction).
//! - **Constant-time verification**: SHA-256 both sides + `subtle::ConstantTimeEq`
//!   (SA-06).
//! - **Loopback by default**: binds `127.0.0.1`; non-loopback binds require
//!   `SIMPLIFI_MCP_HTTP_ALLOW_NONLOCAL=1` and are expected to sit behind TLS
//!   termination (SA-10). rmcp's Host validation (DNS-rebinding guard) stays on.
//! - **No CORS**: no `Access-Control-Allow-*` headers are ever emitted — the
//!   browser default-deny replaces upstream's `CORS *` (SA-10).
//! - **Stateless sessions**: legacy session mode is disabled, so there is no
//!   unbounded in-memory session map to leak or exhaust (SA-12).
//! - **401 hygiene**: failures return an empty body with a `WWW-Authenticate`
//!   challenge (RFC 6750) and `Cache-Control: no-store`; nothing about the
//!   expected token is leaked (SA-11/SA-16).
//! - **Security headers** on every response: `X-Content-Type-Options: nosniff`,
//!   `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
//!   `Cache-Control: no-store` (SA-21).
//!
//! The full per-user OAuth AS from upstream is intentionally NOT reimplemented
//! here — static-bearer keeps the attack surface reviewable for a single-user
//! server. See PORTING-SPEC section 7 for what a multi-user AS would need.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::server::SimplifiMcpServer;

/// Minimum accepted bearer-token length (SA-07: no weak shared secrets).
const MIN_TOKEN_LEN: usize = 32;
pub const DEFAULT_BIND: &str = "127.0.0.1:8787";

#[derive(Clone)]
struct AuthState {
    /// SHA-256 of the configured token — the plaintext is not retained.
    expected: Arc<[u8; 32]>,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

fn unauthorized() -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"simplifi-mcp\", error=\"invalid_token\""),
    );
    resp
}

async fn auth_and_headers(
    axum::extract::State(state): axum::extract::State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let authorized = match presented {
        Some(token) => sha256(token.as_bytes()).ct_eq(state.expected.as_ref()).into(),
        None => false,
    };
    let mut resp = if authorized {
        next.run(request).await
    } else {
        unauthorized()
    };
    let h = resp.headers_mut();
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    h.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    )
}

/// Serve the MCP server over Streamable HTTP at `/mcp`. Runs until ctrl-c.
pub async fn serve_http(server: SimplifiMcpServer, bind: Option<String>) -> Result<()> {
    let token = std::env::var("SIMPLIFI_MCP_HTTP_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            Error::Config(
                "HTTP mode requires SIMPLIFI_MCP_HTTP_TOKEN (a random secret, >= 32 chars); \
                 refusing to start an unauthenticated server"
                    .to_string(),
            )
        })?;
    if token.len() < MIN_TOKEN_LEN {
        return Err(Error::Config(format!(
            "SIMPLIFI_MCP_HTTP_TOKEN too short ({} chars, need >= {MIN_TOKEN_LEN}); \
             generate one with e.g. `openssl rand -base64 33`",
            token.len()
        )));
    }
    let state = AuthState {
        expected: Arc::new(sha256(token.as_bytes())),
    };
    drop(token);

    let bind = bind.unwrap_or_else(|| DEFAULT_BIND.to_string());
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| Error::Config(format!("invalid bind address {bind:?}: {e}")))?;
    if !addr.ip().is_loopback() && !env_flag("SIMPLIFI_MCP_HTTP_ALLOW_NONLOCAL") {
        return Err(Error::Config(format!(
            "refusing to bind non-loopback address {addr} (SA-10); set \
             SIMPLIFI_MCP_HTTP_ALLOW_NONLOCAL=1 only behind TLS termination"
        )));
    }

    // Stateless mode: no per-session server state is kept (SA-12).
    let http_config = StreamableHttpServerConfig::default().with_legacy_session_mode(false);
    let mcp_service: StreamableHttpService<SimplifiMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(server.clone()),
            LocalSessionManager::default().into(),
            http_config,
        );

    let router: axum::Router = axum::Router::new()
        .nest_service("/mcp", mcp_service)
        .layer(middleware::from_fn_with_state(state, auth_and_headers));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "simplifi-mcp streamable-http listening (bearer auth required)");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| Error::Transport(e.to_string()))?;
    Ok(())
}
