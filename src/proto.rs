use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Client -> server. One JSON object per line.
#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: u64,
    pub op: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub db: Option<String>,
    pub sql: Option<String>,
}

/// Server -> client. Always carries the request `id`.
#[derive(Debug, Serialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<Vec<Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_affected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_insert_rowid: Option<i64>,
}

impl Response {
    pub fn ok(id: u64) -> Self {
        Self {
            id,
            ok: true,
            error: None,
            role: None,
            columns: None,
            rows: None,
            row_count: None,
            rows_affected: None,
            last_insert_rowid: None,
        }
    }

    pub fn err(id: u64, msg: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            error: Some(msg.into()),
            role: None,
            columns: None,
            rows: None,
            row_count: None,
            rows_affected: None,
            last_insert_rowid: None,
        }
    }
}
