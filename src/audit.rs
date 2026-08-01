//! Append-only mutation audit journal (SA-09 mitigation).
//!
//! Upstream had **no** record of what an MCP client changed: the local row was
//! overwritten by the post-write resync and nothing else was kept. Here every
//! mutating tool call writes two JSONL records to `data_dir/audit.jsonl`:
//!
//! 1. an `attempt` record BEFORE any upstream traffic (tool, target id, argument
//!    summary, before-image when one exists), and
//! 2. a `result` record after the upstream response (outcome, after-image,
//!    upstream ack).
//!
//! Records share a random `op_id` so they can be joined. The file is append-only
//! from this process (`O_APPEND`), created `0600` inside the `0700` data dir, and
//! is never read, rewritten, or pruned by the server — rotation is the operator's
//! choice. Sync never touches it.
//!
//! Fail-closed contract: if the journal cannot be opened at server start, writes
//! are disabled entirely; if the `attempt` record cannot be written, the mutation
//! is refused before any upstream call. (A `result` write failure is logged but
//! cannot un-send the upstream request.)
//!
//! The journal intentionally contains before/after images — that is financial
//! PII of the same class as the token cache, which is why it lives under the same
//! permission regime. It contains no credentials or tokens.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::json;

use crate::error::{Error, Result};

pub const AUDIT_FILE: &str = "audit.jsonl";

#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl AuditLog {
    /// Open (or create, `0600`) the append-only journal at `data_dir/audit.jsonl`.
    /// Loose permissions on an existing file fail closed, like the token cache.
    pub fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(AUDIT_FILE);
        let existed = path.exists();
        let file = open_append_private(&path)?;
        if existed {
            check_private(&path)?;
        }
        Ok(AuditLog {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the `attempt` record and return the `op_id` joining it to the later
    /// [`AuditLog::finish`] record. An `Err` here MUST abort the mutation.
    pub fn begin(
        &self,
        tool: &str,
        target: Option<&str>,
        args: serde_json::Value,
        before: Option<serde_json::Value>,
    ) -> Result<String> {
        let op_id = uuid::Uuid::new_v4().to_string();
        self.append(json!({
            "ts": now_rfc3339(),
            "opId": op_id,
            "phase": "attempt",
            "tool": tool,
            "target": target,
            "args": args,
            "before": before,
        }))?;
        Ok(op_id)
    }

    /// Write the `result` record. Failure is logged, not propagated — the upstream
    /// mutation already happened and hiding its outcome would help nobody.
    pub fn finish(
        &self,
        op_id: &str,
        tool: &str,
        outcome: &str,
        after: Option<serde_json::Value>,
        ack: Option<serde_json::Value>,
    ) {
        let rec = json!({
            "ts": now_rfc3339(),
            "opId": op_id,
            "phase": "result",
            "tool": tool,
            "outcome": outcome,
            "after": after,
            "ack": ack,
        });
        if let Err(e) = self.append(rec) {
            tracing::error!(error = %e, op_id, tool, "failed to write audit result record");
        }
    }

    fn append(&self, record: serde_json::Value) -> Result<()> {
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        let mut f = self.file.lock().expect("audit lock");
        f.write_all(&line)?;
        f.flush()?;
        Ok(())
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(unix)]
fn open_append_private(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_append_private(path: &Path) -> Result<std::fs::File> {
    Ok(std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?)
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<()> {
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
fn check_private(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_and_result_records_are_joined_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        let op = log
            .begin(
                "update_transaction",
                Some("txn-1"),
                json!({"patch": {"memo": "x"}}),
                Some(json!({"id": "txn-1", "memo": "old"})),
            )
            .unwrap();
        log.finish(&op, "update_transaction", "ok", Some(json!({"memo": "x"})), None);

        let raw = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<serde_json::Value> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["phase"], "attempt");
        assert_eq!(lines[0]["before"]["memo"], "old");
        assert_eq!(lines[1]["phase"], "result");
        assert_eq!(lines[1]["outcome"], "ok");
        assert_eq!(lines[0]["opId"], lines[1]["opId"]);
    }

    #[test]
    fn journal_appends_across_reopens_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        {
            let log = AuditLog::open(dir.path()).unwrap();
            log.begin("a", None, json!({}), None).unwrap();
        }
        {
            let log = AuditLog::open(dir.path()).unwrap();
            log.begin("b", None, json!({}), None).unwrap();
        }
        let path = dir.path().join(AUDIT_FILE);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw.lines().count(), 2, "append-only across reopens");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn loose_permissions_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_FILE);
        std::fs::write(&path, b"{}\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = AuditLog::open(dir.path()).unwrap_err();
        assert!(matches!(err, Error::InsecurePermissions { .. }));
    }
}
