//! Secret sourcing (SA-01 mitigation).
//!
//! - Simplifi credentials come ONLY from the environment (house pattern: `op run` injects
//!   them from 1Password); they are never persisted by this crate.
//! - The token-cache encryption key is resolved through [`KeySource`]: env var, key file,
//!   or the macOS keychain (auto-created on first run). There is no plaintext fallback.

use std::path::PathBuf;
use std::process::Command;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use secrecy::SecretString;

use crate::error::{Error, Result};

pub const ENV_TOKEN_KEY: &str = "SIMPLIFI_MCP_TOKEN_KEY";
pub const ENV_TOKEN_KEY_FILE: &str = "SIMPLIFI_MCP_TOKEN_KEY_FILE";
pub const KEYCHAIN_SERVICE: &str = "simplifi-mcp-rs";
pub const KEYCHAIN_ACCOUNT: &str = "token-cache-key";

/// Simplifi login credentials. Password is held in a zeroize-on-drop container.
pub struct Credentials {
    pub username: String,
    pub password: SecretString,
}

/// Read `SIMPLIFI_EMAIL` / `SIMPLIFI_PASSWORD` from the environment (dev/op-run pattern).
pub fn credentials_from_env() -> Option<Credentials> {
    let username = std::env::var("SIMPLIFI_EMAIL").ok()?;
    let password = std::env::var("SIMPLIFI_PASSWORD").ok()?;
    if username.is_empty() || password.is_empty() {
        return None;
    }
    Some(Credentials {
        username,
        password: SecretString::from(password),
    })
}

/// Where the 32-byte XChaCha20-Poly1305 token-cache key comes from.
#[derive(Debug, Clone)]
pub enum KeySource {
    /// Try env var, then key file env var, then (macOS) the login keychain, creating a
    /// key there on first use. Fails closed if none are available.
    Auto,
    /// Base64 (standard alphabet) 32-byte key in the named env var.
    EnvVar(String),
    /// Base64 32-byte key in a file (must be chmod 0600).
    File(PathBuf),
    /// macOS login keychain generic password (base64 32-byte value).
    Keychain { service: String, account: String },
    /// Fixed key — tests only.
    Static([u8; 32]),
}

impl KeySource {
    pub fn resolve(&self) -> Result<[u8; 32]> {
        match self {
            KeySource::Static(k) => Ok(*k),
            KeySource::EnvVar(var) => {
                let v = std::env::var(var).map_err(|_| {
                    Error::Config(format!("token-cache key env var {var} not set"))
                })?;
                decode_key(v.trim())
            }
            KeySource::File(path) => {
                check_key_file_perms(path)?;
                let v = std::fs::read_to_string(path)?;
                decode_key(v.trim())
            }
            KeySource::Keychain { service, account } => {
                keychain_get_or_create(service, account)
            }
            KeySource::Auto => {
                if let Ok(v) = std::env::var(ENV_TOKEN_KEY) {
                    return decode_key(v.trim());
                }
                if let Ok(p) = std::env::var(ENV_TOKEN_KEY_FILE) {
                    return KeySource::File(PathBuf::from(p)).resolve();
                }
                if cfg!(target_os = "macos") {
                    return keychain_get_or_create(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
                }
                Err(Error::Config(format!(
                    "no token-cache key available: set {ENV_TOKEN_KEY} (base64 32 bytes), \
                     {ENV_TOKEN_KEY_FILE}, or run on macOS with keychain access"
                )))
            }
        }
    }
}

fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let bytes = B64
        .decode(b64)
        .map_err(|_| Error::Config("token-cache key is not valid base64".to_string()))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| Error::Config("token-cache key must decode to exactly 32 bytes".to_string()))
}

#[cfg(unix)]
fn check_key_file_perms(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::InsecurePermissions {
            path: path.to_path_buf(),
            mode: mode & 0o7777,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_file_perms(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

/// Fetch the cache key from the macOS login keychain, generating and storing a fresh
/// 32-byte key on first use.
///
/// Uses the `/usr/bin/security` CLI to avoid a native dependency. NOTE: on creation the
/// base64 key transits `security`'s argv (briefly visible in `ps`); acceptable for a
/// one-time local operation, and avoidable entirely by supplying SIMPLIFI_MCP_TOKEN_KEY
/// via `op run` instead.
fn keychain_get_or_create(service: &str, account: &str) -> Result<[u8; 32]> {
    if let Some(existing) = keychain_get(service, account)? {
        return decode_key(existing.trim());
    }
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut key);
    let b64 = B64.encode(key);
    let status = Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            service,
            "-a",
            account,
            "-w",
            &b64,
        ])
        .status()
        .map_err(|e| Error::Config(format!("failed to run security(1): {e}")))?;
    if !status.success() {
        return Err(Error::Config(
            "security add-generic-password failed; supply SIMPLIFI_MCP_TOKEN_KEY instead"
                .to_string(),
        ));
    }
    Ok(key)
}

fn keychain_get(service: &str, account: &str) -> Result<Option<String>> {
    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .output()
        .map_err(|e| Error::Config(format!("failed to run security(1): {e}")))?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).to_string()))
}
