//! End-to-end client tests against the recorded-fixture mock transport.
//! Run with: cargo test --features mock
#![cfg(feature = "mock")]

use rust_decimal::Decimal;
use secrecy::SecretString;
use std::str::FromStr;

use simplifi_mcp::mock::{fixtures, MockTransport, Route};
use simplifi_mcp::transport::Transport;
use simplifi_mcp::{
    Config, Credentials, Error, KeySource, ListTransactionsParams, LoginFlow, NewTransaction,
    SimplifiClient, TransactionPatch,
};

fn test_config(dir: &std::path::Path) -> Config {
    let mut c = Config::defaults();
    c.data_dir = dir.to_path_buf();
    c.key_source = KeySource::Static([7u8; 32]);
    c.client_secret = Some("test-client-secret".to_string());
    c.min_request_interval_ms = 0;
    c.page_limit = 2;
    c
}

fn test_creds() -> Credentials {
    Credentials {
        username: "user@example.com".to_string(),
        password: SecretString::from("hunter2".to_string()),
    }
}

fn client_with(mock: MockTransport, dir: &std::path::Path) -> SimplifiClient {
    SimplifiClient::with_transport(test_config(dir), Transport::Mock(mock)).expect("client")
}

async fn logged_in_client(mock: MockTransport, dir: &std::path::Path) -> SimplifiClient {
    let client = client_with(mock, dir);
    match client.auth().login(&test_creds()).await.expect("login") {
        LoginFlow::Complete => {}
        LoginFlow::MfaRequired(_) => panic!("unexpected MFA in default fixtures"),
    }
    client
}

#[tokio::test]
async fn login_via_location_header_and_camel_token() {
    let dir = tempfile::tempdir().unwrap();
    let client = logged_in_client(MockTransport::with_default_fixtures(), dir.path()).await;
    let status = client.auth().cache().status();
    assert!(status.has_access_token);
    assert!(status.has_refresh_token);
    assert_eq!(status.credential_logins_last_24h, 1);
    assert!(status.tm_session_id_set, "tm session id must be persisted");
}

#[tokio::test]
async fn login_via_json_code_body_and_snake_token() {
    let dir = tempfile::tempdir().unwrap();
    // 2023-style: auth code in the JSON body, snake_case token payload with expires_in.
    let mock = MockTransport::new()
        .with(Route::new(
            "POST",
            "/oauth/authorize",
            200,
            fixtures::AUTHORIZE_CODE_BODY,
        ))
        .with(Route::new(
            "POST",
            "/oauth/token",
            200,
            fixtures::TOKEN_RESPONSE_SNAKE,
        ));
    let client = client_with(mock, dir.path());
    match client.auth().login(&test_creds()).await.unwrap() {
        LoginFlow::Complete => {}
        LoginFlow::MfaRequired(_) => panic!("unexpected MFA"),
    }
    let status = client.auth().cache().status();
    assert!(status.has_access_token);
    // expires_in=3600 → roughly an hour out.
    let expires_in = status.access_expires_in_secs.unwrap();
    assert!((3000..=3700).contains(&expires_in), "expires_in={expires_in}");
}

#[tokio::test]
async fn mfa_challenge_then_completion() {
    let dir = tempfile::tempdir().unwrap();
    let mock = MockTransport::new()
        // First attempt (mfaCode null) → 202 challenge.
        .with(
            Route::new("POST", "/oauth/authorize", 202, fixtures::MFA_CHALLENGE)
                .pred(|b| b.get("mfaCode").map(|v| v.is_null()).unwrap_or(true)),
        )
        // Retry with the code → success via Location header.
        .with(
            Route::new("POST", "/oauth/authorize", 200, "")
                .pred(|b| b.get("mfaCode").map(|v| v.is_string()).unwrap_or(false))
                .location("https://simplifi.quicken.com/login?code=mfa-code-ok"),
        )
        .with(Route::new(
            "POST",
            "/oauth/token",
            200,
            fixtures::TOKEN_RESPONSE_CAMEL,
        ));
    let client = client_with(mock, dir.path());
    let creds = test_creds();
    let challenge = match client.auth().login(&creds).await.unwrap() {
        LoginFlow::MfaRequired(c) => c,
        LoginFlow::Complete => panic!("expected MFA challenge"),
    };
    assert_eq!(challenge.mfa_id, "mfa-abc-123");
    assert_eq!(challenge.mfa_channel, "EMAIL");
    client
        .auth()
        .complete_mfa(&creds, &challenge, "123456")
        .await
        .unwrap();
    assert!(client.auth().cache().status().has_access_token);
    // MFA completion must NOT consume a second credential-login budget slot.
    assert_eq!(client.auth().cache().status().credential_logins_last_24h, 1);
}

#[tokio::test]
async fn credential_login_budget_quarantines() {
    let dir = tempfile::tempdir().unwrap();
    // Authorize always fails 401 → each login() consumes one budget slot.
    let mock = MockTransport::new().with(Route::new(
        "POST",
        "/oauth/authorize",
        401,
        r#"{"error":"invalid_credentials"}"#,
    ));
    let client = client_with(mock, dir.path());
    let creds = test_creds();
    for _ in 0..3 {
        match client.auth().login(&creds).await {
            Err(Error::Api { status: 401, .. }) => {}
            other => panic!("expected 401 api error, got {other:?}"),
        }
    }
    // Fourth attempt is blocked locally before any upstream traffic.
    match client.auth().login(&creds).await {
        Err(Error::LoginQuarantined { retry_after_secs }) => {
            assert!(retry_after_secs > 0);
        }
        other => panic!("expected quarantine, got {other:?}"),
    }
}

#[tokio::test]
async fn dataset_autodiscovery_persists_large_integer_id() {
    let dir = tempfile::tempdir().unwrap();
    let client = logged_in_client(MockTransport::with_default_fixtures(), dir.path()).await;
    let id = client.ensure_dataset_id().await.unwrap();
    assert_eq!(id, "123456789012345678"); // exact 18-digit integer, no f64 mangling
    assert_eq!(client.auth().cache().status().dataset_id.as_deref(), Some("123456789012345678"));
}

#[tokio::test]
async fn list_transactions_follows_next_link_with_decimal_amounts() {
    let dir = tempfile::tempdir().unwrap();
    let client = logged_in_client(MockTransport::with_default_fixtures(), dir.path()).await;
    let (txns, as_of) = client
        .list_transactions_all(&ListTransactionsParams::default())
        .await
        .unwrap();
    assert_eq!(txns.len(), 3);
    assert_eq!(as_of.as_deref(), Some("2026-07-30T12:00:00Z"));
    assert_eq!(txns[0].id, "txn-1");
    assert_eq!(txns[0].amount, Some(Decimal::from_str("-12.34").unwrap()));
    assert_eq!(txns[2].amount, Some(Decimal::from_str("1234.56").unwrap()));
    // Unknown fields round-trip through `extra`.
    assert!(txns[0].extra.contains_key("cpData"));
    let back = serde_json::to_value(&txns[0]).unwrap();
    assert_eq!(back["cpData"]["raw"], "STARBUCKS STORE 123");
    assert_eq!(back["amount"], serde_json::json!(-12.34));
}

#[tokio::test]
async fn next_link_to_foreign_host_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let evil_page = fixtures::TRANSACTIONS_PAGE1
        .replace("/transactions?limit=2&currentPage=2", "https://evil.example/steal");
    let mock = MockTransport::new()
        .with(
            Route::new("POST", "/oauth/authorize", 200, "")
                .location("https://simplifi.quicken.com/login?code=x"),
        )
        .with(Route::new("POST", "/oauth/token", 200, fixtures::TOKEN_RESPONSE_CAMEL))
        .with(Route::new("GET", "/datasets", 200, fixtures::DATASETS))
        .with(Route::new("GET", "/transactions", 200, &evil_page));
    let client = logged_in_client(mock, dir.path()).await;
    match client
        .list_transactions_all(&ListTransactionsParams::default())
        .await
    {
        Err(Error::UnsafeUrl(msg)) => assert!(msg.contains("evil.example"), "{msg}"),
        other => panic!("expected UnsafeUrl, got {:?}", other.map(|(t, _)| t.len())),
    }
}

#[tokio::test]
async fn update_transaction_validates_required_fields() {
    let dir = tempfile::tempdir().unwrap();
    let client = logged_in_client(MockTransport::with_default_fixtures(), dir.path()).await;
    let (txns, _) = client
        .list_transactions_all(&ListTransactionsParams::default())
        .await
        .unwrap();
    let mut broken = txns[0].clone();
    broken.coa = None;
    match client.update_transaction(&broken).await {
        Err(Error::MissingFields(fields)) => assert_eq!(fields, vec!["coa"]),
        other => panic!("expected MissingFields, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn patch_and_categorize_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let client = logged_in_client(MockTransport::with_default_fixtures(), dir.path()).await;
    let (txns, _) = client
        .list_transactions_all(&ListTransactionsParams::default())
        .await
        .unwrap();
    let base = &txns[0]; // txn-1: PUT route exists in fixtures
    let patch = TransactionPatch {
        memo: Some("patched memo".to_string()),
        ..Default::default()
    };
    let (updated, ack) = client.patch_transaction(base, &patch).await.unwrap();
    assert_eq!(updated.memo.as_deref(), Some("patched memo"));
    assert_eq!(updated.payee, base.payee); // untouched fields preserved
    assert_eq!(ack.status.as_deref(), Some("SUCCESS"));

    let (categorized, _) = client.categorize_transaction(base, "cat-9").await.unwrap();
    assert_eq!(
        categorized.coa.as_ref().and_then(|c| c.id.as_deref()),
        Some("cat-9")
    );
    assert_eq!(
        categorized.coa.as_ref().and_then(|c| c.coa_type.as_deref()),
        Some("CATEGORY")
    );
}

#[test]
fn transaction_patch_rejects_non_allowlisted_fields() {
    // deny_unknown_fields: a confused/compromised caller cannot flip isDeleted or move
    // accountId through the patch surface (SA-09/SA-14).
    for bad in [
        serde_json::json!({ "isDeleted": true }),
        serde_json::json!({ "accountId": "acc-elsewhere" }),
        serde_json::json!({ "__proto__": { "x": 1 } }),
    ] {
        assert!(
            serde_json::from_value::<TransactionPatch>(bad.clone()).is_err(),
            "patch accepted non-allowlisted field: {bad}"
        );
    }
}

#[tokio::test]
async fn create_transaction_is_gated_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let client = logged_in_client(MockTransport::with_default_fixtures(), dir.path()).await;
    let new = NewTransaction {
        account_id: "acc-1".to_string(),
        posted_on: "2026-07-15".to_string(),
        payee: "Backfill Coffee".to_string(),
        amount: Some(Decimal::from_str("-4.50").unwrap()),
        memo: None,
        coa: None,
        tags: None,
        state: None,
        match_state: None,
        source: None,
        txn_type: None,
        client_id: None,
    };
    match client.create_transaction(&new).await {
        Err(Error::UnverifiedEndpointDisabled(_)) => {}
        other => panic!("expected gate, got {:?}", other.map(|_| ())),
    }
    match client.create_transactions_bulk(std::slice::from_ref(&new)).await {
        Err(Error::UnverifiedEndpointDisabled(_)) => {}
        other => panic!("expected gate, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn create_and_bulk_create_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir.path());
    cfg.enable_unverified_writes = true;
    let client =
        SimplifiClient::with_transport(cfg, Transport::Mock(MockTransport::with_default_fixtures()))
            .unwrap();
    match client.auth().login(&test_creds()).await.unwrap() {
        LoginFlow::Complete => {}
        _ => panic!("login"),
    }
    let mk = |payee: &str, amount: &str| NewTransaction {
        account_id: "acc-1".to_string(),
        posted_on: "2026-07-15".to_string(),
        payee: payee.to_string(),
        amount: Some(Decimal::from_str(amount).unwrap()),
        memo: Some("backfill".to_string()),
        coa: None,
        tags: Some(vec!["backfill".to_string()]),
        state: None,
        match_state: None,
        source: None,
        txn_type: None,
        client_id: None,
    };
    let ack = client.create_transaction(&mk("Coffee", "-4.50")).await.unwrap();
    assert_eq!(ack.id.as_deref(), Some("txn-new-9"));

    let outcome = client
        .create_transactions_bulk(&[mk("A", "-1.00"), mk("B", "-2.25"), mk("C", "3.10")])
        .await
        .unwrap();
    assert!(!outcome.aborted);
    assert_eq!(outcome.results.len(), 3);
    assert!(outcome.results.iter().all(|r| r.is_ok()));
}

#[tokio::test]
async fn reference_data_and_accounts_and_whoami() {
    let dir = tempfile::tempdir().unwrap();
    let client = logged_in_client(MockTransport::with_default_fixtures(), dir.path()).await;
    let cats = client.list_categories_all().await.unwrap();
    assert_eq!(cats.len(), 3);
    assert_eq!(cats[1].name.as_deref(), Some("Coffee Shops"));
    let tags = client.list_tags_all().await.unwrap();
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0].number_of_uses, Some(12));
    let accounts = client.list_accounts().await.unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0].id_string().as_deref(), Some("acc-1"));
    let me = client.whoami().await.unwrap();
    assert!(me.id.is_some());
    let earliest = client.earliest_date_on(&[]).await.unwrap();
    assert_eq!(earliest.date_on.as_deref(), Some("2019-03-15"));
}

#[tokio::test]
async fn find_transaction_scans_pages() {
    let dir = tempfile::tempdir().unwrap();
    let client = logged_in_client(MockTransport::with_default_fixtures(), dir.path()).await;
    let found = client.find_transaction("txn-3", None).await.unwrap();
    assert_eq!(found.map(|t| t.id), Some("txn-3".to_string()));
    let missing = client.find_transaction("txn-nope", None).await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn local_helpers_match_upstream_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let client = logged_in_client(MockTransport::with_default_fixtures(), dir.path()).await;
    let (txns, _) = client
        .list_transactions_all(&ListTransactionsParams::default())
        .await
        .unwrap();
    let cats = client.list_categories_all().await.unwrap();

    // renamedPayee wins over payee (merchant identity COALESCE).
    let hits = simplifi_mcp::local::search_transactions(&txns, "starbucks", false);
    assert_eq!(hits.len(), 1);
    let merchants = simplifi_mcp::local::aggregate_merchants(&txns, None, 10, false);
    assert_eq!(merchants.len(), 3);
    assert!(merchants.iter().any(|m| m.merchant == "Starbucks"));

    let unc = simplifi_mcp::local::uncategorized(&txns, false);
    assert_eq!(unc.len(), 1);
    assert_eq!(unc[0].id, "txn-2");

    let sugg = simplifi_mcp::local::suggest_categories_for_merchant(
        &txns,
        &cats,
        "starbucks",
        simplifi_mcp::local::MatchMode::Contains,
        5,
    );
    assert_eq!(sugg.len(), 1);
    assert_eq!(sugg[0].coa_id, "cat-7");
    assert_eq!(sugg[0].category_name.as_deref(), Some("Coffee Shops"));
}

#[tokio::test]
async fn auto_password_login_disabled_by_default() {
    let dir = tempfile::tempdir().unwrap();
    // No cached tokens, creds present, but auto_password_login=false (default):
    // access-token acquisition must NOT hit /oauth/authorize (SA-03).
    let mut cfg = test_config(dir.path());
    cfg.credentials = Some(test_creds());
    let mock = MockTransport::with_default_fixtures();
    let client = SimplifiClient::with_transport(cfg, Transport::Mock(mock)).unwrap();
    match client.whoami().await {
        Err(Error::AuthRequired(_)) => {}
        other => panic!("expected AuthRequired, got {:?}", other.map(|_| ())),
    }
}
