//! CSV import parsing and CSV/JSON export.
//!
//! The import template is Simplifi's own web-app CSV-import format
//! (apderosso `docs/CSV_CONVERSION.md`): columns `Date, Payee, Amount, Tags`,
//! date `M/D/YYYY` non-zero-padded, amount plain decimal (no `$`/commas).
//! We additionally accept ISO `YYYY-MM-DD` dates, an optional `Memo` column,
//! `$`/comma/parentheses amount decoration, and a header row in any casing.
//! The default CSV *export* emits the same template so exports re-import cleanly.

use std::collections::HashMap;

use chrono::{Datelike, NaiveDate};
use rust_decimal::Decimal;
use serde::Serialize;

use crate::models::{NewTransaction, Transaction};

/// Hard cap on rows accepted by one bulk import (abuse/bulk-hammer bound).
pub const MAX_IMPORT_ROWS: usize = 1000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowError {
    /// 1-based data-row number (header excluded).
    pub row: usize,
    pub message: String,
}

#[derive(Debug)]
pub struct ParsedImport {
    pub rows: Vec<NewTransaction>,
    pub errors: Vec<RowError>,
}

fn parse_import_date(s: &str) -> Result<String, String> {
    let s = s.trim();
    for fmt in ["%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"] {
        if let Ok(d) = NaiveDate::parse_from_str(s, fmt) {
            return Ok(d.format("%Y-%m-%d").to_string());
        }
    }
    Err(format!(
        "unparseable date {s:?} (expected M/D/YYYY or YYYY-MM-DD)"
    ))
}

/// Parse an amount cell: strips `$`, `,`, whitespace; `(x)` means negative.
fn parse_import_amount(s: &str) -> Result<Decimal, String> {
    let mut t = s.trim().to_string();
    let mut negate = false;
    if t.starts_with('(') && t.ends_with(')') {
        negate = true;
        t = t[1..t.len() - 1].to_string();
    }
    let cleaned: String = t
        .chars()
        .filter(|c| !matches!(c, '$' | ',' | ' '))
        .collect();
    if cleaned.is_empty() {
        return Err("empty amount".to_string());
    }
    let d = crate::money::parse_decimal(&cleaned)?;
    Ok(if negate { -d } else { d })
}

fn split_tags(cell: &str) -> Option<Vec<String>> {
    let tags: Vec<String> = cell
        .split(['|', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if tags.is_empty() {
        None
    } else {
        Some(tags)
    }
}

/// Parse Simplifi-template CSV into creation candidates for `account_id`.
///
/// Header row (`Date,Payee,Amount[,Tags][,Memo]`, any casing/order) is detected
/// and used for column mapping; headerless input is read positionally as
/// `Date,Payee,Amount[,Tags]`. Per-row failures are collected, not fatal.
pub fn parse_import_csv(csv_text: &str, account_id: &str) -> Result<ParsedImport, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(csv_text.as_bytes());

    let mut records: Vec<csv::StringRecord> = Vec::new();
    for (i, rec) in reader.records().enumerate() {
        if i > MAX_IMPORT_ROWS {
            return Err(format!("too many rows (max {MAX_IMPORT_ROWS})"));
        }
        records.push(rec.map_err(|e| format!("csv parse error: {e}"))?);
    }
    if records.is_empty() {
        return Err("empty csv".to_string());
    }

    // Column map: default positional (Date,Payee,Amount,Tags), overridden by a
    // recognized header row.
    let mut col: HashMap<&'static str, usize> =
        [("date", 0), ("payee", 1), ("amount", 2), ("tags", 3)]
            .into_iter()
            .collect();
    let first = &records[0];
    let header_hit = first
        .iter()
        .any(|c| matches!(c.to_ascii_lowercase().as_str(), "date" | "payee" | "amount"));
    let mut data_start = 0usize;
    if header_hit {
        col.clear();
        for (idx, cell) in first.iter().enumerate() {
            match cell.to_ascii_lowercase().as_str() {
                "date" => {
                    col.insert("date", idx);
                }
                "payee" | "description" => {
                    col.insert("payee", idx);
                }
                "amount" => {
                    col.insert("amount", idx);
                }
                "tags" | "tag" => {
                    col.insert("tags", idx);
                }
                "memo" | "notes" => {
                    col.insert("memo", idx);
                }
                _ => {}
            }
        }
        for required in ["date", "payee", "amount"] {
            if !col.contains_key(required) {
                return Err(format!("header row is missing a {required:?} column"));
            }
        }
        data_start = 1;
    }

    let cell = |rec: &csv::StringRecord, name: &str| -> Option<String> {
        col.get(name)
            .and_then(|i| rec.get(*i))
            .map(|s| s.trim().to_string())
    };

    let mut rows = Vec::new();
    let mut errors = Vec::new();
    if records.len() - data_start > MAX_IMPORT_ROWS {
        return Err(format!("too many rows (max {MAX_IMPORT_ROWS})"));
    }
    for (i, rec) in records.iter().enumerate().skip(data_start) {
        let row_no = i - data_start + 1;
        // Skip fully blank lines.
        if rec.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let mut fail = |msg: String| {
            errors.push(RowError {
                row: row_no,
                message: msg,
            })
        };
        let Some(date_raw) = cell(rec, "date").filter(|s| !s.is_empty()) else {
            fail("missing date".to_string());
            continue;
        };
        let Some(payee) = cell(rec, "payee").filter(|s| !s.is_empty()) else {
            fail("missing payee".to_string());
            continue;
        };
        let Some(amount_raw) = cell(rec, "amount").filter(|s| !s.is_empty()) else {
            fail("missing amount".to_string());
            continue;
        };
        let posted_on = match parse_import_date(&date_raw) {
            Ok(d) => d,
            Err(e) => {
                fail(e);
                continue;
            }
        };
        let amount = match parse_import_amount(&amount_raw) {
            Ok(a) => a,
            Err(e) => {
                fail(e);
                continue;
            }
        };
        rows.push(NewTransaction {
            account_id: account_id.to_string(),
            posted_on,
            payee,
            amount: Some(amount),
            memo: cell(rec, "memo").filter(|s| !s.is_empty()),
            coa: None,
            tags: cell(rec, "tags").as_deref().and_then(split_tags),
            state: None,
            match_state: None,
            source: None,
            txn_type: None,
            client_id: None,
        });
    }
    Ok(ParsedImport { rows, errors })
}

// ---------------------------------------------------------------------- export

/// Formula-injection guard for spreadsheet consumers: cells starting with
/// `=`, `+`, `@` or a tab get a leading `'`. `-` is left alone (amounts).
fn sanitize_cell(s: &str) -> String {
    if s.starts_with(['=', '+', '@', '\t']) {
        format!("'{s}")
    } else {
        s.to_string()
    }
}

fn iso_to_mdy(iso: &str) -> String {
    match NaiveDate::parse_from_str(iso, "%Y-%m-%d") {
        Ok(d) => format!("{}/{}/{}", d.month(), d.day(), d.year()),
        Err(_) => iso.to_string(),
    }
}

/// Resolve `Transaction.tags` (array of tag ids or objects) into names.
fn tag_cell(t: &Transaction, tag_names: &HashMap<String, String>) -> String {
    let Some(serde_json::Value::Array(items)) = &t.tags else {
        return String::new();
    };
    let names: Vec<String> = items
        .iter()
        .map(|v| match v {
            serde_json::Value::String(s) => tag_names.get(s).cloned().unwrap_or_else(|| s.clone()),
            serde_json::Value::Number(n) => {
                let k = n.to_string();
                tag_names.get(&k).cloned().unwrap_or(k)
            }
            serde_json::Value::Object(o) => o
                .get("name")
                .or_else(|| o.get("id"))
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            _ => String::new(),
        })
        .filter(|s| !s.is_empty())
        .collect();
    names.join("|")
}

fn write_csv(rows: Vec<Vec<String>>) -> Result<String, String> {
    let mut w = csv::WriterBuilder::new().from_writer(Vec::new());
    for row in rows {
        w.write_record(&row).map_err(|e| e.to_string())?;
    }
    let bytes = w.into_inner().map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// Simplifi-import-template CSV: `Date,Payee,Amount,Tags`, M/D/YYYY dates.
/// Multi-tag cells join with `|` (NOTE: the exact multi-tag separator Simplifi's
/// importer accepts is unverified; single-tag rows are safe).
pub fn export_import_template_csv(
    txns: &[&Transaction],
    tag_names: &HashMap<String, String>,
) -> Result<String, String> {
    let mut rows = vec![vec![
        "Date".to_string(),
        "Payee".to_string(),
        "Amount".to_string(),
        "Tags".to_string(),
    ]];
    for t in txns {
        rows.push(vec![
            iso_to_mdy(t.posted_on.as_deref().unwrap_or_default()),
            sanitize_cell(t.payee.as_deref().unwrap_or_default()),
            t.amount.map(|a| a.to_string()).unwrap_or_default(),
            sanitize_cell(&tag_cell(t, tag_names)),
        ]);
    }
    write_csv(rows)
}

/// Archival CSV: full column set, ISO dates, decimal-string amounts.
pub fn export_full_csv(
    txns: &[&Transaction],
    tag_names: &HashMap<String, String>,
    category_names: &HashMap<String, String>,
) -> Result<String, String> {
    let mut rows = vec![vec![
        "Id".to_string(),
        "AccountId".to_string(),
        "PostedOn".to_string(),
        "Payee".to_string(),
        "RenamedPayee".to_string(),
        "Memo".to_string(),
        "Amount".to_string(),
        "Category".to_string(),
        "CategoryId".to_string(),
        "State".to_string(),
        "Tags".to_string(),
        "IsDeleted".to_string(),
    ]];
    for t in txns {
        let coa_id = t.coa.as_ref().and_then(|c| c.id.clone()).unwrap_or_default();
        rows.push(vec![
            t.id.clone(),
            t.account_id.clone().unwrap_or_default(),
            t.posted_on.clone().unwrap_or_default(),
            sanitize_cell(t.payee.as_deref().unwrap_or_default()),
            sanitize_cell(t.renamed_payee.as_deref().unwrap_or_default()),
            sanitize_cell(t.memo.as_deref().unwrap_or_default()),
            t.amount.map(|a| a.to_string()).unwrap_or_default(),
            category_names.get(&coa_id).cloned().unwrap_or_default(),
            coa_id,
            t.state.clone().unwrap_or_default(),
            sanitize_cell(&tag_cell(t, tag_names)),
            t.is_deleted.unwrap_or(false).to_string(),
        ]);
    }
    write_csv(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parses_template_with_header() {
        let csv = "Date,Payee,Amount,Tags\n7/4/2026,Coffee Cart,-4.50,work|travel\n2026-07-05,\"Acme, Inc\",\"1,200.00\",\n";
        let p = parse_import_csv(csv, "acc-1").unwrap();
        assert!(p.errors.is_empty(), "{:?}", p.errors);
        assert_eq!(p.rows.len(), 2);
        assert_eq!(p.rows[0].posted_on, "2026-07-04");
        assert_eq!(p.rows[0].tags.as_deref(), Some(&["work".to_string(), "travel".to_string()][..]));
        assert_eq!(p.rows[1].payee, "Acme, Inc");
        assert_eq!(p.rows[1].amount, Some(Decimal::from_str("1200.00").unwrap()));
    }

    #[test]
    fn collects_row_errors_headerless() {
        let csv = "7/4/2026,Coffee,-4.50\nnot-a-date,Broken,-1.00\n7/6/2026,,\n(12.00),x,y\n";
        let p = parse_import_csv(csv, "acc-1").unwrap();
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.errors.len(), 3);
        assert!(p.errors[0].message.contains("unparseable date"));
    }

    #[test]
    fn parenthesized_amounts_are_negative() {
        assert_eq!(
            parse_import_amount("($1,234.56)").unwrap(),
            Decimal::from_str("-1234.56").unwrap()
        );
    }

    #[test]
    fn export_roundtrips_through_import() {
        let t: Transaction = serde_json::from_value(serde_json::json!({
            "id": "t1", "accountId": "acc-1", "postedOn": "2026-07-04",
            "payee": "Coffee Cart", "amount": -4.5, "tags": ["tag-1"]
        }))
        .unwrap();
        let names = HashMap::from([("tag-1".to_string(), "vacation".to_string())]);
        let out = export_import_template_csv(&[&t], &names).unwrap();
        assert!(out.starts_with("Date,Payee,Amount,Tags"));
        assert!(out.contains("7/4/2026,Coffee Cart,-4.5,vacation"), "{out}");
        let back = parse_import_csv(&out, "acc-1").unwrap();
        assert_eq!(back.rows.len(), 1);
        assert_eq!(back.rows[0].posted_on, "2026-07-04");
    }

    #[test]
    fn formula_cells_are_neutralized() {
        assert_eq!(sanitize_cell("=HYPERLINK(x)"), "'=HYPERLINK(x)");
        assert_eq!(sanitize_cell("normal"), "normal");
        assert_eq!(sanitize_cell("-4.50"), "-4.50");
    }
}
