//! Encrypted token-cache tests (no network, no mock feature needed).

use simplifi_mcp::token_cache::{now_unix, TokenCache, TokenSet};
use simplifi_mcp::Error;

const KEY_A: [u8; 32] = [1u8; 32];
const KEY_B: [u8; 32] = [2u8; 32];

fn sample_tokens() -> TokenSet {
    TokenSet {
        access_token: "access-abc".to_string(),
        access_expires_at_unix: now_unix() + 3600,
        refresh_token: "refresh-xyz".to_string(),
        refresh_expires_at_unix: Some(now_unix() + 30 * 24 * 3600),
    }
}

#[test]
fn roundtrip_encrypt_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    {
        let cache = TokenCache::open(dir.path(), KEY_A).unwrap();
        cache.store_tokens(&sample_tokens()).unwrap();
        cache.set_dataset_id("ds-1").unwrap();
    }
    // Reopen with the same key: state survives.
    let cache = TokenCache::open(dir.path(), KEY_A).unwrap();
    assert_eq!(cache.valid_access_token(60).as_deref(), Some("access-abc"));
    assert_eq!(cache.refresh_token().as_deref(), Some("refresh-xyz"));
    assert_eq!(cache.dataset_id().as_deref(), Some("ds-1"));
}

#[test]
fn ciphertext_is_not_plaintext_and_wrong_key_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    {
        let cache = TokenCache::open(dir.path(), KEY_A).unwrap();
        cache.store_tokens(&sample_tokens()).unwrap();
    }
    let raw = std::fs::read(dir.path().join("tokens.enc")).unwrap();
    let hay = String::from_utf8_lossy(&raw);
    assert!(!hay.contains("access-abc"), "token leaked in plaintext");
    assert!(!hay.contains("refresh-xyz"), "token leaked in plaintext");

    match TokenCache::open(dir.path(), KEY_B) {
        Err(Error::Crypto(_)) => {}
        other => panic!("expected Crypto error, got {:?}", other.err()),
    }
}

#[test]
fn tampered_file_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    {
        let cache = TokenCache::open(dir.path(), KEY_A).unwrap();
        cache.store_tokens(&sample_tokens()).unwrap();
    }
    let path = dir.path().join("tokens.enc");
    let mut raw = std::fs::read(&path).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    std::fs::write(&path, &raw).unwrap();
    // restore 0600 (fs::write may not change mode, but be explicit for the perms gate)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    match TokenCache::open(dir.path(), KEY_A) {
        Err(Error::Crypto(_)) => {}
        other => panic!("expected Crypto error, got {:?}", other.err()),
    }
}

#[cfg(unix)]
#[test]
fn loose_permissions_fail_closed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    {
        let cache = TokenCache::open(dir.path(), KEY_A).unwrap();
        cache.store_tokens(&sample_tokens()).unwrap();
    }
    let path = dir.path().join("tokens.enc");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    match TokenCache::open(dir.path(), KEY_A) {
        Err(Error::InsecurePermissions { .. }) => {}
        other => panic!("expected InsecurePermissions, got {:?}", other.err()),
    }
}

#[cfg(unix)]
#[test]
fn cache_file_and_dir_modes_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("nested");
    let cache = TokenCache::open(&data_dir, KEY_A).unwrap();
    cache.store_tokens(&sample_tokens()).unwrap();
    let dir_mode = std::fs::metadata(&data_dir).unwrap().permissions().mode();
    assert_eq!(dir_mode & 0o777, 0o700);
    let file_mode = std::fs::metadata(data_dir.join("tokens.enc"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(file_mode & 0o777, 0o600);
}

#[test]
fn credential_login_budget_rolls() {
    let dir = tempfile::tempdir().unwrap();
    let cache = TokenCache::open(dir.path(), KEY_A).unwrap();
    for _ in 0..3 {
        cache.check_and_record_credential_login(3).unwrap();
    }
    match cache.check_and_record_credential_login(3) {
        Err(Error::LoginQuarantined { retry_after_secs }) => assert!(retry_after_secs > 0),
        other => panic!("expected quarantine, got {:?}", other.err()),
    }
    assert_eq!(cache.credential_logins_last_24h(), 3);
}

#[test]
fn tm_session_id_is_stable_and_override_wins() {
    let dir = tempfile::tempdir().unwrap();
    let generated = {
        let cache = TokenCache::open(dir.path(), KEY_A).unwrap();
        let a = cache.tm_session_id(None).unwrap();
        let b = cache.tm_session_id(None).unwrap();
        assert_eq!(a, b, "tm session id must be stable within a process");
        a
    };
    // Stable across reopen.
    let cache = TokenCache::open(dir.path(), KEY_A).unwrap();
    assert_eq!(cache.tm_session_id(None).unwrap(), generated);
    // Explicit override is adopted and persisted.
    assert_eq!(cache.tm_session_id(Some("browser-tm-1")).unwrap(), "browser-tm-1");
    assert_eq!(cache.tm_session_id(None).unwrap(), "browser-tm-1");
}
