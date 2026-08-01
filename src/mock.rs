//! Recorded-fixture transport (feature `mock`).
//!
//! Lets the full client stack — auth flow, dataset discovery, paging, mutations — run
//! against canned responses with zero live credentials. Fixtures live in `fixtures/`
//! and are embedded at compile time.

use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::transport::{ApiRequest, ApiResponse};

/// Embedded fixture bodies (compile-time copies of `fixtures/*.json`).
pub mod fixtures {
    pub const TOKEN_RESPONSE_CAMEL: &str = include_str!("../fixtures/token_response_camel.json");
    pub const TOKEN_RESPONSE_SNAKE: &str = include_str!("../fixtures/token_response_snake.json");
    pub const MFA_CHALLENGE: &str = include_str!("../fixtures/mfa_challenge.json");
    pub const AUTHORIZE_CODE_BODY: &str = include_str!("../fixtures/authorize_code_body.json");
    pub const DATASETS: &str = include_str!("../fixtures/datasets.json");
    pub const USERPROFILE: &str = include_str!("../fixtures/userprofile.json");
    pub const ACCOUNTS: &str = include_str!("../fixtures/accounts.json");
    pub const TRANSACTIONS_PAGE1: &str = include_str!("../fixtures/transactions_page1.json");
    pub const TRANSACTIONS_PAGE2: &str = include_str!("../fixtures/transactions_page2.json");
    pub const CATEGORIES: &str = include_str!("../fixtures/categories.json");
    pub const TAGS: &str = include_str!("../fixtures/tags.json");
    pub const EARLIEST_DATE_ON: &str = include_str!("../fixtures/earliest_date_on.json");
    pub const UPSERT_ACK: &str = include_str!("../fixtures/upsert_ack.json");
    pub const CREATE_ACK: &str = include_str!("../fixtures/create_ack.json");
}

type BodyPred = fn(&serde_json::Value) -> bool;

pub struct Route {
    pub method: &'static str,
    pub path: String,
    /// All listed (k, v) pairs must appear in the request query string.
    pub query: Vec<(&'static str, &'static str)>,
    pub body_pred: Option<BodyPred>,
    pub status: u16,
    pub location: Option<String>,
    pub body: String,
    pub retry_after: Option<u64>,
}

impl Route {
    pub fn new(method: &'static str, path: &str, status: u16, body: &str) -> Self {
        Route {
            method,
            path: path.to_string(),
            query: Vec::new(),
            body_pred: None,
            status,
            location: None,
            body: body.to_string(),
            retry_after: None,
        }
    }

    pub fn query(mut self, k: &'static str, v: &'static str) -> Self {
        self.query.push((k, v));
        self
    }

    pub fn pred(mut self, f: BodyPred) -> Self {
        self.body_pred = Some(f);
        self
    }

    pub fn location(mut self, l: &str) -> Self {
        self.location = Some(l.to_string());
        self
    }
}

#[derive(Debug, Clone)]
pub struct RecordedCall {
    pub method: String,
    pub path: String,
    pub query: String,
    pub body: Option<serde_json::Value>,
    pub headers: Vec<(String, String)>,
}

#[derive(Default)]
pub struct MockTransport {
    routes: Vec<Route>,
    calls: Mutex<Vec<RecordedCall>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, route: Route) {
        self.routes.push(route);
    }

    pub fn with(mut self, route: Route) -> Self {
        self.routes.push(route);
        self
    }

    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().expect("mock calls lock").clone()
    }

    /// Happy-path server: password login succeeds without MFA (Location-header code
    /// encoding), camelCase token payload, one dataset, three transactions over two
    /// pages, categories/tags/accounts, PUT ack, and the inferred POST create ack.
    ///
    /// Route order matters: more specific (query-matched) routes first.
    pub fn with_default_fixtures() -> Self {
        let mut m = MockTransport::new();
        m.push(
            Route::new("POST", "/oauth/authorize", 200, "")
                .pred(|b| b.get("mfaCode").map(|v| v.is_null()).unwrap_or(true))
                .location("https://simplifi.quicken.com/login?code=mock-auth-code"),
        );
        m.push(Route::new(
            "POST",
            "/oauth/token",
            200,
            fixtures::TOKEN_RESPONSE_CAMEL,
        ));
        m.push(Route::new("GET", "/datasets", 200, fixtures::DATASETS));
        m.push(Route::new(
            "GET",
            "/userprofiles/me",
            200,
            fixtures::USERPROFILE,
        ));
        m.push(Route::new("GET", "/accounts", 200, fixtures::ACCOUNTS));
        m.push(
            Route::new(
                "GET",
                "/transactions",
                200,
                fixtures::TRANSACTIONS_PAGE2,
            )
            .query("currentPage", "2"),
        );
        m.push(Route::new(
            "GET",
            "/transactions",
            200,
            fixtures::TRANSACTIONS_PAGE1,
        ));
        m.push(Route::new(
            "POST",
            "/transactions/earliest-date-on",
            200,
            fixtures::EARLIEST_DATE_ON,
        ));
        m.push(Route::new(
            "PUT",
            "/transactions/txn-1",
            200,
            fixtures::UPSERT_ACK,
        ));
        m.push(Route::new(
            "POST",
            "/transactions",
            200,
            fixtures::CREATE_ACK,
        ));
        m.push(Route::new("GET", "/categories", 200, fixtures::CATEGORIES));
        m.push(Route::new("GET", "/tags", 200, fixtures::TAGS));
        m
    }

    pub async fn execute(&self, req: ApiRequest) -> Result<ApiResponse> {
        let path = req.url.path().to_string();
        let query = req.url.query().unwrap_or("").to_string();
        self.calls.lock().expect("mock calls lock").push(RecordedCall {
            method: req.method.to_string(),
            path: path.clone(),
            query: query.clone(),
            body: req.body.clone(),
            headers: req
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        });

        let body_for_pred = req.body.clone().unwrap_or(serde_json::Value::Null);
        for route in &self.routes {
            if route.method != req.method.as_str() {
                continue;
            }
            if route.path != path {
                continue;
            }
            let pairs: Vec<(String, String)> = req
                .url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            if !route
                .query
                .iter()
                .all(|(k, v)| pairs.iter().any(|(pk, pv)| pk == k && pv == v))
            {
                continue;
            }
            if let Some(pred) = route.body_pred {
                if !pred(&body_for_pred) {
                    continue;
                }
            }
            return Ok(ApiResponse {
                status: route.status,
                location: route.location.clone(),
                retry_after: route.retry_after,
                body: route.body.clone().into_bytes(),
            });
        }
        Err(Error::Transport(format!(
            "mock: no route for {} {path}?{query}",
            req.method
        )))
    }
}
