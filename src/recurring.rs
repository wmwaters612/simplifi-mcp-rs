//! Recurring-transaction detection (feature addition; no upstream equivalent).
//!
//! Groups transactions by a normalized merchant identity (lowercased, digits and
//! store-number noise stripped) and classifies the cadence of each group from the
//! median gap between consecutive posted dates. Pure function over a slice —
//! callers pass a store snapshot; nothing here touches the network.

use std::collections::HashMap;

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Serialize;

use crate::local::merchant_of;
use crate::models::Transaction;

/// Maximum transaction ids echoed per detected group (keeps tool output bounded).
const MAX_IDS_PER_GROUP: usize = 24;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecurringGroup {
    /// Most frequent raw merchant name in the group.
    pub merchant: String,
    /// Normalization key the group was built on.
    pub normalized_payee: String,
    /// weekly | biweekly | monthly | bimonthly | quarterly | semiannual | annual
    pub cadence: &'static str,
    pub occurrences: usize,
    pub median_interval_days: i64,
    /// Median absolute deviation of the intervals, in days (regularity measure).
    pub interval_mad_days: i64,
    /// Decimal strings — never floats.
    pub average_amount: String,
    pub last_amount: Option<String>,
    /// True when max-min amount spread is within 20% of |average| (or $1).
    pub amount_consistent: bool,
    /// ISO dates.
    pub first_date: String,
    pub last_date: String,
    pub next_expected_date: String,
    pub account_ids: Vec<String>,
    /// Transaction ids (most recent first, capped).
    pub transaction_ids: Vec<String>,
}

/// Normalize a payee into a merchant-identity key: lowercase, digits and `#`
/// dropped, punctuation collapsed to spaces, whitespace collapsed.
/// "STARBUCKS STORE #123" and "Starbucks Store 456" both -> "starbucks store".
pub fn normalize_payee(payee: &str) -> String {
    let mut out = String::with_capacity(payee.len());
    let mut last_space = true;
    for ch in payee.chars() {
        let mapped = if ch.is_alphabetic() {
            Some(ch.to_ascii_lowercase())
        } else if ch.is_ascii_digit() || ch == '#' || ch == '*' {
            None // store numbers / card-processor noise
        } else {
            Some(' ')
        };
        match mapped {
            Some(' ') => {
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            Some(c) => {
                out.push(c);
                last_space = false;
            }
            None => {}
        }
    }
    out.trim().to_string()
}

fn cadence_for(median_gap: i64) -> Option<(&'static str, i64)> {
    match median_gap {
        6..=8 => Some(("weekly", 7)),
        12..=16 => Some(("biweekly", 14)),
        26..=35 => Some(("monthly", 30)),
        55..=70 => Some(("bimonthly", 61)),
        80..=100 => Some(("quarterly", 91)),
        165..=200 => Some(("semiannual", 182)),
        330..=400 => Some(("annual", 365)),
        _ => None,
    }
}

fn median(sorted: &[i64]) -> i64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

/// Detect recurring merchant groups. `min_occurrences` >= 2; regular cadence is
/// required (interval MAD bounded relative to the expected gap), amount spread is
/// reported but does not disqualify (subscription price changes stay detected).
pub fn detect_recurring(
    txns: &[Transaction],
    min_occurrences: usize,
    account_id: Option<&str>,
    date_from: Option<&str>,
) -> Vec<RecurringGroup> {
    let min_occurrences = min_occurrences.max(2);
    // key -> [(date, txn)]
    let mut groups: HashMap<String, Vec<(&Transaction, NaiveDate)>> = HashMap::new();
    for t in txns {
        if t.is_deleted.unwrap_or(false) {
            continue;
        }
        if let Some(acc) = account_id {
            if t.account_id.as_deref() != Some(acc) {
                continue;
            }
        }
        let Some(posted) = t.posted_on.as_deref() else {
            continue;
        };
        if let Some(from) = date_from {
            if posted < from {
                continue;
            }
        }
        let Ok(date) = NaiveDate::parse_from_str(posted, "%Y-%m-%d") else {
            continue;
        };
        let Some(merchant) = merchant_of(t) else {
            continue;
        };
        let key = normalize_payee(merchant);
        if key.is_empty() {
            continue;
        }
        groups.entry(key).or_default().push((t, date));
    }

    let mut out = Vec::new();
    for (key, mut members) in groups {
        if members.len() < min_occurrences {
            continue;
        }
        members.sort_by_key(|(_, d)| *d);
        // Gaps between consecutive occurrences (same-day repeats collapse to gap 0
        // and are dropped — duplicates aren't cadence evidence).
        let mut gaps: Vec<i64> = members
            .windows(2)
            .map(|w| (w[1].1 - w[0].1).num_days())
            .filter(|g| *g > 0)
            .collect();
        if gaps.len() + 1 < min_occurrences {
            continue;
        }
        gaps.sort_unstable();
        let med = median(&gaps);
        let Some((cadence, expected_gap)) = cadence_for(med) else {
            continue;
        };
        let mut deviations: Vec<i64> = gaps.iter().map(|g| (g - med).abs()).collect();
        deviations.sort_unstable();
        let mad = median(&deviations);
        // Regularity: MAD within 20% of the expected gap (floor 2, cap 20 days).
        let tolerance = (expected_gap / 5).clamp(2, 20);
        if mad > tolerance {
            continue;
        }

        let amounts: Vec<Decimal> = members.iter().filter_map(|(t, _)| t.amount).collect();
        let (average_amount, amount_consistent) = if amounts.is_empty() {
            ("0".to_string(), false)
        } else {
            let sum: Decimal = amounts.iter().copied().sum();
            let avg = sum / Decimal::from(amounts.len());
            let min = amounts.iter().copied().min().unwrap_or_default();
            let max = amounts.iter().copied().max().unwrap_or_default();
            let spread_limit = (avg.abs() / Decimal::from(5)).max(Decimal::ONE);
            (avg.round_dp(2).to_string(), (max - min) <= spread_limit)
        };

        // Most frequent raw merchant string.
        let mut name_counts: HashMap<&str, usize> = HashMap::new();
        for (t, _) in &members {
            if let Some(m) = merchant_of(t) {
                *name_counts.entry(m).or_insert(0) += 1;
            }
        }
        let merchant = name_counts
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(m, _)| m.to_string())
            .unwrap_or_else(|| key.clone());

        let first = members.first().expect("non-empty").1;
        let (last_txn, last) = members.last().expect("non-empty");
        let mut account_ids: Vec<String> = members
            .iter()
            .filter_map(|(t, _)| t.account_id.clone())
            .collect();
        account_ids.sort();
        account_ids.dedup();
        let mut transaction_ids: Vec<String> =
            members.iter().rev().map(|(t, _)| t.id.clone()).collect();
        transaction_ids.truncate(MAX_IDS_PER_GROUP);

        out.push(RecurringGroup {
            merchant,
            normalized_payee: key,
            cadence,
            occurrences: members.len(),
            median_interval_days: med,
            interval_mad_days: mad,
            average_amount,
            last_amount: last_txn.amount.map(|a| a.to_string()),
            amount_consistent,
            first_date: first.format("%Y-%m-%d").to_string(),
            last_date: last.format("%Y-%m-%d").to_string(),
            next_expected_date: (*last + chrono::Duration::days(med))
                .format("%Y-%m-%d")
                .to_string(),
            account_ids,
            transaction_ids,
        });
    }
    out.sort_by(|a, b| {
        b.occurrences
            .cmp(&a.occurrences)
            .then_with(|| a.merchant.cmp(&b.merchant))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn txn(id: &str, payee: &str, date: &str, amount: &str) -> Transaction {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "payee": payee,
            "accountId": "acc-1",
            "postedOn": date,
            "amount": f64::from_str(amount).unwrap(),
        }))
        .unwrap()
    }

    #[test]
    fn normalizes_store_numbers_away() {
        assert_eq!(normalize_payee("STARBUCKS STORE #123"), "starbucks store");
        assert_eq!(normalize_payee("Starbucks   Store 456"), "starbucks store");
        assert_eq!(normalize_payee("NETFLIX.COM*8891"), "netflix com");
    }

    #[test]
    fn detects_monthly_subscription() {
        let txns = vec![
            txn("a", "NETFLIX.COM", "2026-01-15", "-15.49"),
            txn("b", "NETFLIX.COM", "2026-02-15", "-15.49"),
            txn("c", "NETFLIX.COM", "2026-03-15", "-15.49"),
            txn("d", "NETFLIX.COM", "2026-04-14", "-15.49"),
            // noise: two one-off purchases
            txn("x", "HOME DEPOT 991", "2026-02-02", "-89.10"),
            txn("y", "HOME DEPOT 991", "2026-02-03", "-12.00"),
        ];
        let groups = detect_recurring(&txns, 3, None, None);
        assert_eq!(groups.len(), 1, "{groups:?}");
        let g = &groups[0];
        assert_eq!(g.cadence, "monthly");
        assert_eq!(g.occurrences, 4);
        assert_eq!(g.average_amount, "-15.49");
        assert!(g.amount_consistent);
        assert_eq!(g.last_date, "2026-04-14");
        assert_eq!(g.next_expected_date, "2026-05-14");
        assert_eq!(g.transaction_ids[0], "d");
    }

    #[test]
    fn irregular_gaps_are_not_recurring() {
        let txns = vec![
            txn("a", "RANDOM SHOP", "2026-01-01", "-10.00"),
            txn("b", "RANDOM SHOP", "2026-01-29", "-10.00"),
            txn("c", "RANDOM SHOP", "2026-05-20", "-10.00"),
            txn("d", "RANDOM SHOP", "2026-05-25", "-10.00"),
        ];
        assert!(detect_recurring(&txns, 3, None, None).is_empty());
    }

    #[test]
    fn weekly_cadence_detected() {
        let txns: Vec<Transaction> = (0..5)
            .map(|i| {
                let d = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap()
                    + chrono::Duration::days(7 * i);
                txn(
                    &format!("w{i}"),
                    "GYM CLASS",
                    &d.format("%Y-%m-%d").to_string(),
                    "-25.00",
                )
            })
            .collect();
        let groups = detect_recurring(&txns, 3, None, None);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].cadence, "weekly");
        assert_eq!(groups[0].median_interval_days, 7);
    }
}
