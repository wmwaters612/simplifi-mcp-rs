//! Typed wire models for the Simplifi internal REST API.
//!
//! Source of truth: upstream `openapi.yaml:421-728` (HAR-derived) + `src/types.ts`.
//! Every upstream schema is `additionalProperties: true`, so every struct here
//! round-trips unknown fields via `#[serde(flatten)] extra` — a full-object PUT
//! re-serializes exactly what the server sent plus our edits.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

pub type Extra = serde_json::Map<String, serde_json::Value>;

/// Paging envelope: `{ metaData, resources }` (types.ts:74-87).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    #[serde(rename = "metaData", default)]
    pub meta_data: MetaData,
    #[serde(default = "Vec::new")]
    pub resources: Vec<T>,
}

/// `metaData` (types.ts:1-12, openapi.yaml:358-380).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ref_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_pages: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_size: Option<i64>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Chart-of-accounts reference `{ type, id }` (types.ts:44-48).
/// Category assignment = `{ type: "CATEGORY", id: <categoryId> }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoaRef {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub coa_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl CoaRef {
    pub fn category(category_id: impl Into<String>) -> Self {
        CoaRef {
            coa_type: Some("CATEGORY".to_string()),
            id: Some(category_id.into()),
            extra: Extra::new(),
        }
    }

    /// "Uncategorized" heuristic (upstream database.ts:469).
    pub fn is_uncategorized(coa: Option<&CoaRef>) -> bool {
        match coa {
            None => true,
            Some(c) => {
                c.coa_type.is_none()
                    || c.coa_type
                        .as_deref()
                        .map(|t| t.eq_ignore_ascii_case("UNCATEGORIZED"))
                        .unwrap_or(false)
                    || c.id.as_deref() == Some("0")
            }
        }
    }
}

/// Transaction (openapi.yaml:537-677). Promoted fields are typed; everything else
/// (cpData, splits, allocations, investment fields, bill fields, ...) rides in `extra`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_modified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_version: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// `YYYY-MM-DD`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posted_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_payee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coa: Option<CoaRef>,
    /// Money: JSON number on the wire, `Decimal` in Rust (never f64 arithmetic).
    #[serde(
        default,
        with = "crate::money::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub amount: Option<Decimal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_state: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub txn_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_category_id: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_known_category_id: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_inferred_payee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_deleted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_reviewed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_excluded_from_reports: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Required fields for `PUT /transactions/{id}` (openapi.yaml:679-694 + spec section 4.2).
pub const UPSERT_REQUIRED_FIELDS: [&str; 11] = [
    "id",
    "clientId",
    "accountId",
    "postedOn",
    "payee",
    "coa",
    "amount",
    "state",
    "matchState",
    "source",
    "type",
];

impl Transaction {
    /// Validate the full upsert-required field set (stricter than upstream's runtime
    /// check, which omits clientId; the HAR spec requires it).
    pub fn validate_upsert_required(&self) -> Result<(), Vec<&'static str>> {
        fn empty(v: &Option<String>) -> bool {
            v.as_deref().map(|s| s.is_empty()).unwrap_or(true)
        }
        let mut missing = Vec::new();
        if self.id.is_empty() {
            missing.push("id");
        }
        if empty(&self.client_id) {
            missing.push("clientId");
        }
        if empty(&self.account_id) {
            missing.push("accountId");
        }
        if empty(&self.posted_on) {
            missing.push("postedOn");
        }
        if self.payee.is_none() {
            missing.push("payee");
        }
        match &self.coa {
            Some(c) if !empty(&c.coa_type) && !empty(&c.id) => {}
            _ => missing.push("coa"),
        }
        if self.amount.is_none() {
            missing.push("amount");
        }
        if empty(&self.state) {
            missing.push("state");
        }
        if empty(&self.match_state) {
            missing.push("matchState");
        }
        if empty(&self.source) {
            missing.push("source");
        }
        if empty(&self.txn_type) {
            missing.push("type");
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

/// Typed, allowlisted patch for `update_transaction` — replaces upstream's free-form
/// deep-merge (SA-09/SA-14 mitigation). `deny_unknown_fields` rejects attempts to flip
/// `isDeleted`, move `accountId`, etc. at the schema boundary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_payee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coa: Option<CoaRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_reviewed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_excluded_from_reports: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posted_on: Option<String>,
    #[serde(
        default,
        with = "crate::money::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub amount: Option<Decimal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<serde_json::Value>,
}

impl TransactionPatch {
    /// Apply the patch onto a clone of `base`. Only allowlisted fields can change.
    pub fn apply(&self, base: &Transaction) -> Transaction {
        let mut t = base.clone();
        if let Some(v) = &self.payee {
            t.payee = Some(v.clone());
        }
        if let Some(v) = &self.renamed_payee {
            t.renamed_payee = Some(v.clone());
        }
        if let Some(v) = &self.memo {
            t.memo = Some(v.clone());
        }
        if let Some(v) = &self.coa {
            t.coa = Some(v.clone());
        }
        if let Some(v) = &self.tags {
            t.tags = Some(serde_json::Value::Array(
                v.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ));
        }
        if let Some(v) = self.is_reviewed {
            t.is_reviewed = Some(v);
        }
        if let Some(v) = self.is_excluded_from_reports {
            t.is_excluded_from_reports = Some(v);
        }
        if let Some(v) = &self.posted_on {
            t.posted_on = Some(v.clone());
        }
        if let Some(v) = self.amount {
            t.amount = Some(v);
        }
        if let Some(v) = &self.check {
            t.check = Some(v.clone());
        }
        t
    }
}

/// Input for the (unverified, config-gated) transaction-creation endpoint
/// (PORTING-SPEC section 8). Defaults marked UNVERIFIED must be confirmed by HAR capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewTransaction {
    pub account_id: String,
    /// `YYYY-MM-DD`
    pub posted_on: String,
    pub payee: String,
    #[serde(with = "crate::money::opt")]
    pub amount: Option<Decimal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coa: Option<CoaRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_type: Option<String>,
    /// Client-assigned identity; generated (UUIDv4) when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

// UNVERIFIED defaults for creation — to be confirmed against a HAR capture of the web
// app's "add manual transaction" flow before anyone relies on them.
pub const UNVERIFIED_DEFAULT_STATE: &str = "CLEARED";
pub const UNVERIFIED_DEFAULT_MATCH_STATE: &str = "NOT_MATCHED";
pub const UNVERIFIED_DEFAULT_SOURCE: &str = "MANUAL";
pub const UNVERIFIED_DEFAULT_TYPE: &str = "CASH_FLOW";

impl NewTransaction {
    /// Build the inferred `POST /transactions` body: upsert shape WITHOUT `id`,
    /// WITH a client-generated `clientId`.
    pub fn to_create_body(&self, client_id: &str) -> serde_json::Value {
        let coa = self.coa.clone().unwrap_or(CoaRef {
            coa_type: Some("UNCATEGORIZED".to_string()),
            id: Some("0".to_string()),
            extra: Extra::new(),
        });
        let mut body = serde_json::json!({
            "clientId": client_id,
            "accountId": self.account_id,
            "postedOn": self.posted_on,
            "payee": self.payee,
            "coa": serde_json::to_value(&coa).unwrap_or_default(),
            "state": self.state.clone().unwrap_or_else(|| UNVERIFIED_DEFAULT_STATE.to_string()),
            "matchState": self.match_state.clone().unwrap_or_else(|| UNVERIFIED_DEFAULT_MATCH_STATE.to_string()),
            "source": self.source.clone().unwrap_or_else(|| UNVERIFIED_DEFAULT_SOURCE.to_string()),
            "type": self.txn_type.clone().unwrap_or_else(|| UNVERIFIED_DEFAULT_TYPE.to_string()),
        });
        // Money serialized through the same decimal-safe path as Transaction.
        if let Some(amount) = self.amount {
            let n = if amount.scale() == 0 {
                use rust_decimal::prelude::ToPrimitive;
                amount
                    .to_i64()
                    .map(serde_json::Value::from)
                    .unwrap_or_else(|| serde_json::Value::from(amount.to_string()))
            } else {
                use rust_decimal::prelude::ToPrimitive;
                amount
                    .to_f64()
                    .map(serde_json::Value::from)
                    .unwrap_or_else(|| serde_json::Value::from(amount.to_string()))
            };
            body["amount"] = n;
        }
        if let Some(memo) = &self.memo {
            body["memo"] = serde_json::Value::String(memo.clone());
        }
        if let Some(tags) = &self.tags {
            body["tags"] = serde_json::Value::Array(
                tags.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            );
        }
        body
    }
}

/// Category (openapi.yaml:421-491).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Category {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_business: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_investment: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_not_editable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_not_user_assignable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_excluded_from_budgets: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_excluded_from_category_list: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_excluded_from_reports: Option<bool>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Tag (openapi.yaml:493-517).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tag {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub tag_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_modified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number_of_uses: Option<i64>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Account (rijn `GET /accounts`; field-by-field shape unverified — keep loose).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Account {
    pub fn id_string(&self) -> Option<String> {
        json_id_string(self.id.as_ref())
    }
}

/// Dataset (rijn `GET /datasets`). Id may arrive as a large JSON integer — kept exact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dataset {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Dataset {
    pub fn id_string(&self) -> Option<String> {
        json_id_string(self.id.as_ref())
    }
}

pub(crate) fn json_id_string(v: Option<&serde_json::Value>) -> Option<String> {
    match v {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// `GET /userprofiles/me` (rijn client.py:66-82).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `POST /transactions/earliest-date-on` response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EarliestDateOn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_on: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Mutation ack for PUT (and inferred POST) `/transactions` (types.ts:94-100).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertAck {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// 202 MFA challenge from `POST /oauth/authorize` (auth-service.ts:95-113).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenge {
    pub mfa_id: String,
    pub mfa_channel: String,
    pub email: Option<String>,
    pub phone: Option<String>,
}

impl MfaChallenge {
    pub fn from_body(v: &serde_json::Value) -> Self {
        MfaChallenge {
            mfa_id: v
                .get("mfaId")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            mfa_channel: v
                .get("mfaChannel")
                .and_then(|x| x.as_str())
                .unwrap_or("EMAIL")
                .to_string(),
            email: v
                .get("email")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            phone: v
                .get("phone")
                .and_then(|x| x.as_str())
                .map(str::to_string),
        }
    }
}

/// Upstream error envelope (openapi.yaml:730-744). Only the short `error` code is ever
/// surfaced (SA-11).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ErrorBody {
    #[serde(default)]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample_txn_json() -> serde_json::Value {
        serde_json::json!({
            "id": "txn-1",
            "clientId": "c-1",
            "accountId": "acc-1",
            "postedOn": "2026-07-01",
            "payee": "STARBUCKS #123",
            "coa": { "type": "CATEGORY", "id": "cat-7", "vendorCoaHint": true },
            "amount": -12.34,
            "state": "CLEARED",
            "matchState": "NOT_MATCHED",
            "source": "OFX",
            "type": "CASH_FLOW",
            // fields we do NOT model explicitly — must round-trip via `extra`
            "cpData": { "raw": "CHECKCARD 0701 STARBUCKS" },
            "splits": [{ "amount": -12.34 }],
            "futureUnknownField": 42,
        })
    }

    #[test]
    fn transaction_roundtrips_unknown_fields_exactly() {
        let input = sample_txn_json();
        let t: Transaction = serde_json::from_value(input.clone()).unwrap();
        // unknown fields live in extra ...
        assert_eq!(t.extra["futureUnknownField"], 42);
        assert_eq!(t.extra["cpData"]["raw"], "CHECKCARD 0701 STARBUCKS");
        // ... and a full re-serialization reproduces the upstream object (PUT safety)
        let out = serde_json::to_value(&t).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn money_survives_roundtrip_as_exact_decimal() {
        // 4.10 is a classic float-trap value
        let t: Transaction =
            serde_json::from_value(serde_json::json!({ "id": "x", "amount": 4.10 })).unwrap();
        assert_eq!(t.amount.unwrap(), Decimal::from_str("4.1").unwrap());
        let out = serde_json::to_value(&t).unwrap();
        assert_eq!(out["amount"], serde_json::json!(4.1));
        // integer amounts serialize as integers, not floats
        let t: Transaction =
            serde_json::from_value(serde_json::json!({ "id": "x", "amount": -1500 })).unwrap();
        assert_eq!(serde_json::to_value(&t).unwrap()["amount"], serde_json::json!(-1500));
    }

    #[test]
    fn patch_rejects_unknown_and_protected_fields() {
        // SA-09/SA-14: no free-form merge — unknown/protected keys die at the boundary
        for bad in [
            serde_json::json!({ "isDeleted": true }),
            serde_json::json!({ "accountId": "acc-2" }),
            serde_json::json!({ "state": "PENDING" }),
            serde_json::json!({ "__proto__": { "polluted": true } }),
            serde_json::json!({ "memo": "ok", "extraField": 1 }),
        ] {
            assert!(
                serde_json::from_value::<TransactionPatch>(bad.clone()).is_err(),
                "should reject {bad}"
            );
        }
        // allowlisted fields parse
        let p: TransactionPatch = serde_json::from_value(serde_json::json!({
            "memo": "new memo", "tags": ["tag-1"], "isReviewed": true
        }))
        .unwrap();
        assert_eq!(p.memo.as_deref(), Some("new memo"));
    }

    #[test]
    fn patch_apply_touches_only_allowlisted_fields() {
        let base: Transaction = serde_json::from_value(sample_txn_json()).unwrap();
        let patch = TransactionPatch {
            memo: Some("annotated".to_string()),
            amount: Some(Decimal::from_str("-13.00").unwrap()),
            ..Default::default()
        };
        let out = patch.apply(&base);
        assert_eq!(out.memo.as_deref(), Some("annotated"));
        assert_eq!(out.amount.unwrap(), Decimal::from_str("-13.00").unwrap());
        // everything else — including unknown-field baggage — is untouched
        assert_eq!(out.id, base.id);
        assert_eq!(out.account_id, base.account_id);
        assert_eq!(out.state, base.state);
        assert_eq!(out.extra, base.extra);
    }

    #[test]
    fn upsert_validation_reports_each_missing_field() {
        let t: Transaction = serde_json::from_value(serde_json::json!({ "id": "txn-1" })).unwrap();
        let missing = t.validate_upsert_required().unwrap_err();
        for f in [
            "clientId", "accountId", "postedOn", "payee", "coa", "amount", "state",
            "matchState", "source", "type",
        ] {
            assert!(missing.contains(&f), "expected {f} in {missing:?}");
        }
        let full: Transaction = serde_json::from_value(sample_txn_json()).unwrap();
        assert!(full.validate_upsert_required().is_ok());
    }

    #[test]
    fn uncategorized_heuristic_matches_upstream() {
        assert!(CoaRef::is_uncategorized(None));
        let untyped = CoaRef { coa_type: None, id: Some("5".into()), extra: Extra::new() };
        assert!(CoaRef::is_uncategorized(Some(&untyped)));
        let zero = CoaRef { coa_type: Some("CATEGORY".into()), id: Some("0".into()), extra: Extra::new() };
        assert!(CoaRef::is_uncategorized(Some(&zero)));
        let explicit = CoaRef { coa_type: Some("uncategorized".into()), id: Some("7".into()), extra: Extra::new() };
        assert!(CoaRef::is_uncategorized(Some(&explicit)));
        let real = CoaRef::category("cat-7");
        assert!(!CoaRef::is_uncategorized(Some(&real)));
    }

    #[test]
    fn dataset_ids_keep_large_integers_exact() {
        // Dataset ids can exceed 2^53 — f64 would corrupt them
        let d: Dataset =
            serde_json::from_value(serde_json::json!({ "id": 123456789012345678u64, "name": "My Finances" }))
                .unwrap();
        assert_eq!(d.id_string().unwrap(), "123456789012345678");
        let d: Dataset =
            serde_json::from_value(serde_json::json!({ "id": "ds-1" })).unwrap();
        assert_eq!(d.id_string().unwrap(), "ds-1");
        assert_eq!(json_id_string(Some(&serde_json::Value::String(String::new()))), None);
        assert_eq!(json_id_string(None), None);
    }

    #[test]
    fn mfa_challenge_parses_defaults() {
        let ch = MfaChallenge::from_body(&serde_json::json!({
            "mfaId": "m-1", "email": "a***@example.com"
        }));
        assert_eq!(ch.mfa_id, "m-1");
        assert_eq!(ch.mfa_channel, "EMAIL");
        assert_eq!(ch.email.as_deref(), Some("a***@example.com"));
        assert!(ch.phone.is_none());
    }
}
