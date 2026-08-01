//! Encrypted-at-rest token cache (SA-01 mitigation).
//!
//! Replaces upstream's plaintext `simplifi_tokens` SQLite table. State (Simplifi access +
//! refresh tokens, dataset id, the persisted ThreatMetrix session id, and the rolling
//! credential-login ledger) is serialized to JSON and sealed with XChaCha20-Poly1305
//! (random 24-byte nonce per write, file magic as AAD). The key comes from
//! [`crate::secrets::KeySource`] — env, key file, or macOS keychain. No plaintext
//! fallback exists; a wrong key or a tampered file fails closed.
//!
//! File hygiene: cache dir 0700, file 0600, atomic tmp+rename writes, permissions
//! re-verified at every open.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const MAGIC: &[u8; 5] = b"SMRS1";
const NONCE_LEN: usize = 24;
pub const CACHE_FILE: &str = "tokens.enc";

/// Full token payload as parsed from either upstream key style.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub access_expires_at_unix: i64,
    pub refresh_token: String,
    pub refresh_expires_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TokenState {
    access_token: Option<String>,
    access_expires_at_unix: Option<i64>,
    refresh_token: Option<String>,
    refresh_expires_at_unix: Option<i64>,
    dataset_id: Option<String>,
    /// Persisted ThreatMetrix session id — ONE stable device identity (SA-03).
    tm_session_id: Option<String>,
    /// Unix timestamps of credential logins in the rolling window (SA-03 budget).
    #[serde(default)]
    credential_logins: Vec<i64>,
}

/// Redacted cache summary for `simplifi-mcp status` — never contains secret material.
#[derive(Debug, Clone, Serialize)]
pub struct CacheStatus {
    pub has_access_token: bool,
    pub access_expires_in_secs: Option<i64>,
    pub has_refresh_token: bool,
    pub dataset_id: Option<String>,
    pub tm_session_id_set: bool,
    pub credential_logins_last_24h: usize,
}

pub struct TokenCache {
    path: PathBuf,
    key: [u8; 32],
    state: Mutex<TokenState>,
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl TokenCache {
    /// Open (or initialize) the cache at `data_dir/tokens.enc`.
    pub fn open(data_dir: &Path, key: [u8; 32]) -> Result<Self> {
        ensure_private_dir(data_dir)?;
        let path = data_dir.join(CACHE_FILE);
        let state = if path.exists() {
            check_file_perms(&path)?;
            let raw = std::fs::read(&path)?;
            decrypt_state(&key, &raw)?
        } else {
            TokenState::default()
        };
        let cache = TokenCache {
            path,
            key,
            state: Mutex::new(state),
        };
        cache.save()?; // creates the file with 0600 on first open
        Ok(cache)
    }

    fn save(&self) -> Result<()> {
        let state = self.state.lock().expect("token cache lock");
        let plaintext = serde_json::to_vec(&*state)?;
        drop(state);
        let sealed = encrypt_state(&self.key, &plaintext)?;
        write_atomic_private(&self.path, &sealed)
    }

    // ----- tokens -----

    pub fn valid_access_token(&self, skew_secs: i64) -> Option<String> {
        let s = self.state.lock().expect("token cache lock");
        match (&s.access_token, s.access_expires_at_unix) {
            (Some(tok), Some(exp)) if !tok.is_empty() && exp - skew_secs > now_unix() => {
                Some(tok.clone())
            }
            _ => None,
        }
    }

    pub fn refresh_token(&self) -> Option<String> {
        let s = self.state.lock().expect("token cache lock");
        s.refresh_token.clone().filter(|t| !t.is_empty())
    }

    pub fn store_tokens(&self, ts: &TokenSet) -> Result<()> {
        {
            let mut s = self.state.lock().expect("token cache lock");
            s.access_token = Some(ts.access_token.clone());
            s.access_expires_at_unix = Some(ts.access_expires_at_unix);
            s.refresh_token = Some(ts.refresh_token.clone());
            s.refresh_expires_at_unix = ts.refresh_expires_at_unix;
        }
        self.save()
    }

    pub fn clear_tokens(&self) -> Result<()> {
        {
            let mut s = self.state.lock().expect("token cache lock");
            s.access_token = None;
            s.access_expires_at_unix = None;
            s.refresh_token = None;
            s.refresh_expires_at_unix = None;
        }
        self.save()
    }

    // ----- dataset id -----

    pub fn dataset_id(&self) -> Option<String> {
        self.state
            .lock()
            .expect("token cache lock")
            .dataset_id
            .clone()
    }

    pub fn set_dataset_id(&self, id: &str) -> Result<()> {
        {
            let mut s = self.state.lock().expect("token cache lock");
            s.dataset_id = Some(id.to_string());
        }
        self.save()
    }

    // ----- ThreatMetrix session id -----

    /// Return the stable ThreatMetrix session id, honoring an explicit override
    /// (persisting it) and otherwise generating + persisting one UUIDv4 forever.
    pub fn tm_session_id(&self, preferred: Option<&str>) -> Result<String> {
        let mut changed = false;
        let id = {
            let mut s = self.state.lock().expect("token cache lock");
            match preferred {
                Some(p) if !p.is_empty() => {
                    if s.tm_session_id.as_deref() != Some(p) {
                        s.tm_session_id = Some(p.to_string());
                        changed = true;
                    }
                    p.to_string()
                }
                _ => match &s.tm_session_id {
                    Some(existing) if !existing.is_empty() => existing.clone(),
                    _ => {
                        let fresh = uuid::Uuid::new_v4().to_string();
                        s.tm_session_id = Some(fresh.clone());
                        changed = true;
                        fresh
                    }
                },
            }
        };
        if changed {
            self.save()?;
        }
        Ok(id)
    }

    // ----- credential-login budget (SA-03) -----

    /// Enforce the rolling-24h credential-login cap; on success records this attempt.
    pub fn check_and_record_credential_login(&self, max_per_24h: u32) -> Result<()> {
        let now = now_unix();
        {
            let mut s = self.state.lock().expect("token cache lock");
            s.credential_logins.retain(|t| now - *t < 24 * 3600);
            if s.credential_logins.len() >= max_per_24h as usize {
                let oldest = s.credential_logins.iter().min().copied().unwrap_or(now);
                let retry_after_secs = ((oldest + 24 * 3600) - now).max(0) as u64;
                return Err(Error::LoginQuarantined { retry_after_secs });
            }
            s.credential_logins.push(now);
        }
        self.save()
    }

    pub fn credential_logins_last_24h(&self) -> usize {
        let now = now_unix();
        let s = self.state.lock().expect("token cache lock");
        s.credential_logins
            .iter()
            .filter(|t| now - **t < 24 * 3600)
            .count()
    }

    pub fn status(&self) -> CacheStatus {
        let s = self.state.lock().expect("token cache lock");
        let now = now_unix();
        CacheStatus {
            has_access_token: s.access_token.as_deref().map(|t| !t.is_empty()).unwrap_or(false),
            access_expires_in_secs: s.access_expires_at_unix.map(|e| e - now),
            has_refresh_token: s.refresh_token.as_deref().map(|t| !t.is_empty()).unwrap_or(false),
            dataset_id: s.dataset_id.clone(),
            tm_session_id_set: s.tm_session_id.is_some(),
            credential_logins_last_24h: s
                .credential_logins
                .iter()
                .filter(|t| now - **t < 24 * 3600)
                .count(),
        }
    }
}

fn encrypt_state(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: MAGIC,
            },
        )
        .map_err(|_| Error::Crypto("encryption failed"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_state(key: &[u8; 32], raw: &[u8]) -> Result<TokenState> {
    if raw.len() < MAGIC.len() + NONCE_LEN + 16 || &raw[..MAGIC.len()] != MAGIC {
        return Err(Error::Crypto("unrecognized token cache format"));
    }
    let nonce = &raw[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let ct = &raw[MAGIC.len() + NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: MAGIC,
            },
        )
        .map_err(|_| Error::Crypto("wrong key or tampered token cache"))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

#[cfg(unix)]
fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let mode = std::fs::metadata(dir)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::InsecurePermissions {
            path: dir.to_path_buf(),
            mode: mode & 0o7777,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

#[cfg(unix)]
fn check_file_perms(path: &Path) -> Result<()> {
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
fn check_file_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("enc.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Belt-and-braces: the rename target keeps the tmp file's 0600 mode, but re-assert.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("enc.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sealed-blob format hardening; end-to-end cache behavior is covered in
    // tests/token_cache.rs.

    #[test]
    fn sealed_blob_roundtrips_and_nonces_differ() {
        let key = [9u8; 32];
        let state = br#"{"access_token":"secret-at"}"#;
        let a = encrypt_state(&key, state).unwrap();
        let b = encrypt_state(&key, state).unwrap();
        assert_ne!(a, b, "random nonce per write");
        assert!(
            !a.windows(9).any(|w| w == b"secret-at"),
            "ciphertext must not embed plaintext"
        );
        let parsed = decrypt_state(&key, &a).unwrap();
        assert_eq!(parsed.access_token.as_deref(), Some("secret-at"));
    }

    #[test]
    fn bad_magic_truncation_and_wrong_key_fail_closed() {
        let key = [9u8; 32];
        let sealed = encrypt_state(&key, b"{}").unwrap();

        let mut bad_magic = sealed.clone();
        bad_magic[0] ^= 0xff;
        assert!(matches!(decrypt_state(&key, &bad_magic), Err(Error::Crypto(_))));

        assert!(matches!(decrypt_state(&key, &sealed[..10]), Err(Error::Crypto(_))));
        assert!(matches!(decrypt_state(&key, b""), Err(Error::Crypto(_))));

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(matches!(decrypt_state(&key, &tampered), Err(Error::Crypto(_))));

        assert!(matches!(decrypt_state(&[0u8; 32], &sealed), Err(Error::Crypto(_))));
    }

    #[test]
    fn now_unix_is_sane() {
        // 2020-01-01 < now < 2100-01-01
        let n = now_unix();
        assert!(n > 1_577_836_800 && n < 4_102_444_800, "{n}");
    }
}
