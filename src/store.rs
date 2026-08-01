//! In-memory sync store backing the MCP tools.
//!
//! Freshness-gated mirror of the Simplifi ledger: first access does a full fetch
//! (transactions + categories + tags + accounts), later accesses do incremental
//! transaction syncs keyed on the server-reported `asOf` watermark
//! (`modifiedAfter` param). Tombstoned (`isDeleted`) rows are kept and filtered
//! at query time so incremental deletes propagate.
//!
//! SA-13 mitigation: a hard minimum interval between upstream syncs is enforced
//! even when a caller passes `refresh: true` — a refresh loop degrades to cache
//! reads instead of amplifying into continuous upstream load. Sync execution is
//! single-flight (one mutex) so concurrent tools cannot stampede upstream.
//!
//! This is the B2 in-memory replacement for upstream's SQLite cache; a
//! persistent store can slot in behind the same accessors later.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::client::{ListTransactionsParams, SimplifiClient};
use crate::error::Result;
use crate::models::{Account, Category, Tag, Transaction};

/// Reference data (categories/tags/accounts) re-fetch TTL when not forced.
const REFERENCE_TTL: Duration = Duration::from_secs(900);
/// Overlap subtracted from the local-clock fallback watermark so a missing
/// server `asOf` cannot open a gap between syncs.
const WATERMARK_OVERLAP_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Cache was fresh enough (or the sync floor applied); no upstream traffic.
    CacheHit,
    /// An upstream sync ran.
    Synced,
}

#[derive(Default)]
struct StoreState {
    transactions: HashMap<String, Transaction>,
    categories: Vec<Category>,
    tags: Vec<Tag>,
    accounts: Vec<Account>,
    /// `modifiedAfter` watermark for the next incremental transaction sync.
    watermark: Option<String>,
    txn_synced_once: bool,
    ref_synced_once: bool,
    last_txn_sync: Option<Instant>,
    last_ref_sync: Option<Instant>,
}

pub struct SyncStore {
    client: Arc<SimplifiClient>,
    state: tokio::sync::RwLock<StoreState>,
    /// Single-flight guard for sync execution (SA-03/SA-13).
    sync_gate: tokio::sync::Mutex<()>,
    max_stale: Duration,
    min_sync_interval: Duration,
}

impl SyncStore {
    pub fn new(client: Arc<SimplifiClient>) -> Self {
        let cfg = client.config();
        let max_stale = Duration::from_secs(cfg.mcp_max_stale_secs);
        let min_sync_interval = Duration::from_secs(cfg.mcp_min_sync_interval_secs);
        SyncStore {
            client,
            state: tokio::sync::RwLock::new(StoreState::default()),
            sync_gate: tokio::sync::Mutex::new(()),
            max_stale,
            min_sync_interval,
        }
    }

    pub fn client(&self) -> &SimplifiClient {
        &self.client
    }

    /// Ensure the transaction mirror is usable. `force` requests a sync now
    /// (still subject to the minimum-interval floor).
    pub async fn ensure_transactions(&self, force: bool) -> Result<SyncOutcome> {
        let _flight = self.sync_gate.lock().await;
        let (synced_once, age, watermark) = {
            let s = self.state.read().await;
            (
                s.txn_synced_once,
                s.last_txn_sync.map(|t| t.elapsed()),
                s.watermark.clone(),
            )
        };
        if synced_once {
            let age = age.unwrap_or(Duration::MAX);
            if age < self.min_sync_interval {
                return Ok(SyncOutcome::CacheHit); // SA-13 floor, even when forced
            }
            if !force && age < self.max_stale {
                return Ok(SyncOutcome::CacheHit);
            }
        }
        let params = ListTransactionsParams {
            modified_after: if synced_once { watermark } else { None },
            ..Default::default()
        };
        let (txns, as_of) = self.client.list_transactions_all(&params).await?;
        let fallback_watermark = (chrono::Utc::now()
            - chrono::Duration::seconds(WATERMARK_OVERLAP_SECS))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut s = self.state.write().await;
        for t in txns {
            s.transactions.insert(t.id.clone(), t);
        }
        s.watermark = as_of.or(s.watermark.take()).or(Some(fallback_watermark));
        s.txn_synced_once = true;
        s.last_txn_sync = Some(Instant::now());
        Ok(SyncOutcome::Synced)
    }

    /// Ensure categories/tags/accounts are loaded (TTL-refreshed; `force` re-fetches
    /// subject to the same minimum-interval floor as transactions).
    pub async fn ensure_reference(&self, force: bool) -> Result<SyncOutcome> {
        let _flight = self.sync_gate.lock().await;
        let (synced_once, age) = {
            let s = self.state.read().await;
            (s.ref_synced_once, s.last_ref_sync.map(|t| t.elapsed()))
        };
        if synced_once {
            let age = age.unwrap_or(Duration::MAX);
            if age < self.min_sync_interval {
                return Ok(SyncOutcome::CacheHit);
            }
            if !force && age < REFERENCE_TTL {
                return Ok(SyncOutcome::CacheHit);
            }
        }
        let categories = self.client.list_categories_all().await?;
        let tags = self.client.list_tags_all().await?;
        let accounts = self.client.list_accounts().await?;
        let mut s = self.state.write().await;
        s.categories = categories;
        s.tags = tags;
        s.accounts = accounts;
        s.ref_synced_once = true;
        s.last_ref_sync = Some(Instant::now());
        Ok(SyncOutcome::Synced)
    }

    /// All cached transactions, postedOn (then id) descending. Includes tombstones —
    /// callers filter with their own `includeDeleted` semantics.
    pub async fn transactions_snapshot(&self) -> Vec<Transaction> {
        let s = self.state.read().await;
        let mut v: Vec<Transaction> = s.transactions.values().cloned().collect();
        v.sort_by(|a, b| {
            b.posted_on
                .cmp(&a.posted_on)
                .then_with(|| b.id.cmp(&a.id))
        });
        v
    }

    pub async fn get_transaction(&self, id: &str) -> Option<Transaction> {
        self.state.read().await.transactions.get(id).cloned()
    }

    /// Write-through after a successful PUT: keep the mirror consistent without
    /// waiting for the next sync.
    pub async fn upsert_local(&self, txn: Transaction) {
        self.state
            .write()
            .await
            .transactions
            .insert(txn.id.clone(), txn);
    }

    pub async fn categories(&self) -> Vec<Category> {
        self.state.read().await.categories.clone()
    }

    pub async fn tags(&self) -> Vec<Tag> {
        self.state.read().await.tags.clone()
    }

    pub async fn accounts(&self) -> Vec<Account> {
        self.state.read().await.accounts.clone()
    }

    /// Map of tag id -> tag name (export joins ids to names).
    pub async fn tag_names(&self) -> HashMap<String, String> {
        self.state
            .read()
            .await
            .tags
            .iter()
            .filter_map(|t| Some((t.id.clone()?, t.name.clone()?)))
            .collect()
    }

    /// Map of category id -> category name.
    pub async fn category_names(&self) -> HashMap<String, String> {
        self.state
            .read()
            .await
            .categories
            .iter()
            .filter_map(|c| Some((c.id.clone()?, c.name.clone()?)))
            .collect()
    }
}
