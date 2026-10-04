use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::paths::TinyPaths;
use crate::users;

/// Result of a successful read.
#[derive(Debug)]
pub struct ReadResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

/// Result of a successful write.
#[derive(Debug)]
pub struct WriteResult {
    pub rows_affected: usize,
    pub last_insert_rowid: i64,
}

fn apply_pragmas(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
    Ok(())
}

/// Register `hash_password(text)` scalar function used for user management
/// via `#users` (so passwords never hit disk in plaintext).
fn register_hash_fn(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.create_scalar_function(
        "hash_password",
        1,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx: &rusqlite::functions::Context| {
            let pw: String = ctx.get(0)?;
            users::hash_password(&pw)
                .map_err(|e| rusqlite::Error::UserFunctionError(e.to_string().into()))
        },
    )
}

/// Reject empty SQL and multi-statement payloads (each call = one statement).
fn single_statement(sql: &str) -> anyhow::Result<String> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty sql");
    }
    // Allow one trailing semicolon; reject anything after a statement terminator.
    let mut without_trailing = trimmed.to_string();
    while without_trailing.ends_with(';') {
        without_trailing.pop();
    }
    let body = without_trailing.trim_end();
    if body.is_empty() {
        anyhow::bail!("empty sql");
    }
    // Crude but effective: sqlite statement separators are `;`.
    // Quoted semicolons (inside '...' or "...") are ignored.
    if contains_unquoted_semicolon(body) {
        anyhow::bail!("only a single SQL statement is allowed per call");
    }
    Ok(trimmed.to_string())
}

fn contains_unquoted_semicolon(s: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_backslash = false;
    for c in s.chars() {
        if in_single {
            if c == '\'' && !prev_backslash {
                // handle '' escape: peek not available, treat doubled quote as staying inside
                in_single = false;
            }
            prev_backslash = false;
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            }
            continue;
        }
        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            ';' => return true,
            _ => {}
        }
        prev_backslash = c == '\\';
    }
    false
}

fn value_to_json(v: rusqlite::types::Value) -> Value {
    match v {
        rusqlite::types::Value::Null => Value::Null,
        rusqlite::types::Value::Integer(i) => Value::from(i),
        rusqlite::types::Value::Real(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        rusqlite::types::Value::Text(s) => Value::String(s),
        rusqlite::types::Value::Blob(b) => Value::String(B64.encode(b)),
    }
}

/// Queue-less read: open a short-lived read connection per call.
///
/// Enforces `stmt.readonly()`: SELECT/WITH.../EXPLAIN pass, everything
/// mutating is rejected even if disguised.
pub fn do_read(db_path: PathBuf, sql: String, is_users_db: bool) -> anyhow::Result<ReadResult> {
    let _ = is_users_db;
    if !db_path.exists() {
        anyhow::bail!("database does not exist");
    }
    let sql = single_statement(&sql)?;
    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| format!("open {} readonly", db_path.display()))?;
    // Read-only connection: no WAL switch needed, but busy timeout helps.
    conn.execute_batch("PRAGMA busy_timeout=5000;")?;

    let stmt_sql = sql.clone();
    let mut stmt = conn.prepare(&stmt_sql).context("prepare")?;
    if !stmt.readonly() {
        anyhow::bail!("read endpoint only accepts readonly statements (SELECT/WITH/EXPLAIN)");
    }
    let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let n = columns.len();
    let mut rows: Vec<Vec<Value>> = Vec::new();
    let mut q = stmt.query([]).context("query")?;
    while let Some(row) = q.next().context("fetch row")? {
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let v: rusqlite::types::Value = row.get(i).context("decode value")?;
            out.push(value_to_json(v));
        }
        rows.push(out);
    }
    Ok(ReadResult {
        columns,
        rows,
    })
}

/// Execute one write statement inside its own transaction.
/// Caller must have resolved ACL + path already.
fn do_write_once(db_path: &PathBuf, sql: &str, is_users_db: bool) -> anyhow::Result<WriteResult> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("open {}", db_path.display()))?;
    apply_pragmas(&conn)?;
    if is_users_db {
        register_hash_fn(&conn)?;
    }
    let sql = single_statement(sql)?;
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> anyhow::Result<WriteResult> {
        let mut stmt = conn.prepare(&sql).context("prepare")?;
        let rows_affected = stmt.execute([]).context("execute")? as usize;
        let last_insert_rowid = conn.last_insert_rowid();
        Ok(WriteResult {
            rows_affected,
            last_insert_rowid,
        })
    })();
    match result {
        Ok(r) => {
            conn.execute_batch("COMMIT").context("commit")?;
            Ok(r)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Per-DB write queues: one writer task per open DB, FIFO, each statement in
// its own transaction.
// ---------------------------------------------------------------------------

struct WriteJob {
    sql: String,
    reply: oneshot::Sender<Result<WriteResult, String>>,
}

#[derive(Clone, Default)]
pub struct WriteRegistry {
    inner: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<WriteJob>>>>,
    paths: Option<Arc<TinyPaths>>,
}

impl WriteRegistry {
    pub fn new(paths: Arc<TinyPaths>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            paths: Some(paths),
        }
    }

    #[cfg(test)]
    fn test_registry(root: std::path::PathBuf) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            paths: Some(Arc::new(TinyPaths::from_root(root))),
        }
    }

    fn sender_for(&self, db: &str) -> anyhow::Result<mpsc::UnboundedSender<WriteJob>> {
        let paths = self
            .paths
            .clone()
            .ok_or_else(|| anyhow::anyhow!("write registry has no paths"))?;
        let mut map = self.inner.lock().unwrap();
        if let Some(tx) = map.get(db) {
            return Ok(tx.clone());
        }
        let (tx, rx) = mpsc::unbounded_channel::<WriteJob>();
        let db_name = db.to_string();
        map.insert(db.to_string(), tx.clone());
        drop(map);
        tokio::spawn(writer_loop(paths, db_name, rx));
        Ok(tx)
    }

    /// Enqueue a write for `db` and wait for its own-transaction result.
    pub async fn submit(&self, db: &str, sql: String) -> anyhow::Result<WriteResult> {
        // Resolve path eagerly so typos fail fast before queueing.
        let paths = self
            .paths
            .clone()
            .ok_or_else(|| anyhow::anyhow!("write registry has no paths"))?;
        paths.db_path(db)?;
        let tx = self.sender_for(db)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(WriteJob { sql, reply: reply_tx })
            .map_err(|_| anyhow::anyhow!("write queue closed"))?;
        let inner = reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("write worker dropped"))?;
        inner.map_err(|e| anyhow::anyhow!("{e}"))
    }
}

async fn writer_loop(
    paths: Arc<TinyPaths>,
    db: String,
    mut rx: mpsc::UnboundedReceiver<WriteJob>,
) {
    let db_path = match paths.db_path(&db) {
        Ok(p) => p,
        Err(_) => return,
    };
    let is_users_db = db == "#users";
    while let Some(job) = rx.recv().await {
        let path = db_path.clone();
        let sql = job.sql.clone();
        // Run the blocking sqlite work off the async executor, preserving
        // FIFO order by awaiting each job before taking the next.
        let res = tokio::task::spawn_blocking(move || {
            do_write_once(&path, &sql, is_users_db).map_err(|e| format!("{e:#}"))
        })
        .await
        .unwrap_or_else(|e| Err(format!("worker join error: {e}")));
        let _ = job.reply.send(res);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_multi_statement() {
        assert!(single_statement("SELECT 1").is_ok());
        assert!(single_statement("SELECT 1;").is_ok());
        assert!(single_statement("SELECT 1; SELECT 2").is_err());
        assert!(single_statement("").is_err());
        assert!(single_statement("  ; ").is_err());
    }

    #[test]
    fn quoted_semicolons_allowed() {
        assert!(single_statement("SELECT 'a;b'").is_ok());
    }

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let root: PathBuf = std::env::temp_dir().join(format!(
            "tinydb-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let paths = TinyPaths::from_root(root.clone());
        paths.ensure_dirs().unwrap();
        let reg = WriteRegistry::test_registry(root.clone());

        reg.submit("shop", "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)".into())
            .await
            .unwrap();
        let w = reg
            .submit("shop", "INSERT INTO t(v) VALUES('x')".into())
            .await
            .unwrap();
        assert_eq!(w.rows_affected, 1);

        let db_path = paths.db_path("shop").unwrap();
        let r = do_read(db_path, "SELECT v FROM t".into(), false).unwrap();
        assert_eq!(r.columns, vec!["v".to_string()]);
        assert_eq!(r.rows.len(), 1);

        // read endpoint rejects writes
        let db_path = paths.db_path("shop").unwrap();
        assert!(do_read(db_path, "DELETE FROM t".into(), false).is_err());

        // failing write doesn't poison the queue
        assert!(
            reg.submit("shop", "INSERT INTO nope_missing (a) VALUES(1)".into())
                .await
                .is_err()
        );
        let w2 = reg
            .submit("shop", "INSERT INTO t(v) VALUES('y')".into())
            .await
            .unwrap();
        assert_eq!(w2.rows_affected, 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn concurrent_writes_serialized() {
        let root: PathBuf = std::env::temp_dir().join(format!(
            "tinydb-conc-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let paths = TinyPaths::from_root(root.clone());
        paths.ensure_dirs().unwrap();
        let reg = WriteRegistry::test_registry(root.clone());
        reg.submit("c", "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)".into())
            .await
            .unwrap();
        let mut handles = Vec::new();
        for i in 0..20 {
            let reg = reg.clone();
            handles.push(tokio::spawn(async move {
                reg.submit("c", format!("INSERT INTO t(v) VALUES('v{i}')"))
                    .await
                    .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let db_path = paths.db_path("c").unwrap();
        let r = do_read(db_path, "SELECT COUNT(*) FROM t".into(), false).unwrap();
        assert_eq!(r.rows[0][0], Value::from(20));
        let _ = std::fs::remove_dir_all(&root);
    }
}
