//! Client-side (in-memory) query helpers over fetched transactions.
//!
//! These mirror upstream's SQLite-backed tool semantics (database.ts:458-550, 967-1064)
//! for use directly against wire results. The persistent cache layer (task B2) supplies
//! the SQL-backed equivalents; the merchant-identity and search rules here are the
//! reference implementations.

use std::collections::HashMap;

use serde::Serialize;

use crate::models::{Category, CoaRef, Transaction};

fn non_empty(v: &Option<String>) -> Option<&str> {
    match v.as_deref() {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Merchant identity: `COALESCE(NULLIF(renamed_payee,''), NULLIF(payee,''),
/// NULLIF(ml_inferred_payee,''))` (database.ts:986, 1032).
pub fn merchant_of(t: &Transaction) -> Option<&str> {
    non_empty(&t.renamed_payee)
        .or_else(|| non_empty(&t.payee))
        .or_else(|| non_empty(&t.ml_inferred_payee))
}

/// Case-insensitive search across payee / renamedPayee / memo / mlInferredPayee
/// (upstream `search_transactions` LIKE semantics, literal — no wildcard injection).
pub fn search_transactions<'a>(
    txns: &'a [Transaction],
    query: &str,
    include_deleted: bool,
) -> Vec<&'a Transaction> {
    let q = query.to_lowercase();
    txns.iter()
        .filter(|t| include_deleted || !t.is_deleted.unwrap_or(false))
        .filter(|t| {
            [&t.payee, &t.renamed_payee, &t.memo, &t.ml_inferred_payee]
                .into_iter()
                .flatten()
                .any(|s| s.to_lowercase().contains(&q))
        })
        .collect()
}

/// Uncategorized filter (upstream `list_uncategorized_transactions`).
pub fn uncategorized(txns: &[Transaction], include_deleted: bool) -> Vec<&Transaction> {
    txns.iter()
        .filter(|t| include_deleted || !t.is_deleted.unwrap_or(false))
        .filter(|t| CoaRef::is_uncategorized(t.coa.as_ref()))
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct MerchantCount {
    pub merchant: String,
    pub count: usize,
}

/// Upstream `search_merchants`: GROUP BY merchant identity with counts, filtered by a
/// case-insensitive contains query, ordered by count desc then name.
pub fn aggregate_merchants(
    txns: &[Transaction],
    query: Option<&str>,
    limit: usize,
    include_deleted: bool,
) -> Vec<MerchantCount> {
    let q = query.map(str::to_lowercase);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for t in txns {
        if !include_deleted && t.is_deleted.unwrap_or(false) {
            continue;
        }
        let Some(m) = merchant_of(t) else { continue };
        if let Some(q) = &q {
            if !m.to_lowercase().contains(q) {
                continue;
            }
        }
        *counts.entry(m.to_string()).or_insert(0) += 1;
    }
    let mut out: Vec<MerchantCount> = counts
        .into_iter()
        .map(|(merchant, count)| MerchantCount { merchant, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then(a.merchant.cmp(&b.merchant)));
    out.truncate(limit);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    Exact,
    Contains,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategorySuggestion {
    pub coa_type: String,
    pub coa_id: String,
    pub count: usize,
    pub category_name: Option<String>,
}

/// Upstream `suggest_categories_for_merchant`: GROUP BY (coa.type, coa.id) over the
/// merchant's transactions, joined to category names, ordered by count desc.
pub fn suggest_categories_for_merchant(
    txns: &[Transaction],
    categories: &[Category],
    merchant: &str,
    mode: MatchMode,
    limit: usize,
) -> Vec<CategorySuggestion> {
    let m = merchant.to_lowercase();
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for t in txns {
        if t.is_deleted.unwrap_or(false) {
            continue;
        }
        let Some(tm) = merchant_of(t) else { continue };
        let tm = tm.to_lowercase();
        let hit = match mode {
            MatchMode::Exact => tm == m,
            MatchMode::Contains => tm.contains(&m),
        };
        if !hit {
            continue;
        }
        let Some(coa) = &t.coa else { continue };
        let (Some(ct), Some(ci)) = (coa.coa_type.as_deref(), coa.id.as_deref()) else {
            continue;
        };
        *counts.entry((ct.to_string(), ci.to_string())).or_insert(0) += 1;
    }
    let name_by_id: HashMap<&str, &str> = categories
        .iter()
        .filter_map(|c| Some((c.id.as_deref()?, c.name.as_deref()?)))
        .collect();
    let mut out: Vec<CategorySuggestion> = counts
        .into_iter()
        .map(|((coa_type, coa_id), count)| CategorySuggestion {
            category_name: name_by_id.get(coa_id.as_str()).map(|s| s.to_string()),
            coa_type,
            coa_id,
            count,
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then(a.coa_id.cmp(&b.coa_id)));
    out.truncate(limit);
    out
}
