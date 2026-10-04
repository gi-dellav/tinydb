use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::db::{self, WriteRegistry};
use crate::paths::TinyPaths;
use crate::proto::{Request, Response};
use crate::users::{self, Role, access_for};

#[derive(Clone)]
pub struct ServerState {
    pub paths: Arc<TinyPaths>,
    pub writes: WriteRegistry,
}

#[derive(Debug, Default)]
struct Session {
    username: Option<String>,
    role: Option<Role>,
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
    state: ServerState,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &acceptor, &state).await {
                eprintln!("connection {peer} closed with error: {e:#}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    acceptor: &TlsAcceptor,
    state: &ServerState,
) -> anyhow::Result<()> {
    let tls: TlsStream<TcpStream> = acceptor.accept(stream).await?;
    let (reader, mut writer) = tokio::io::split(tls);
    let mut lines = BufReader::new(reader).lines();
    let mut session = Session::default();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => dispatch(req, &mut session, state).await,
            Err(e) => Response::err(0, format!("invalid request: {e}")),
        };
        let mut out = serde_json::to_string(&resp).unwrap();
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
    }
    Ok(())
}

async fn dispatch(req: Request, session: &mut Session, state: &ServerState) -> Response {
    match req.op.as_str() {
        "login" => op_login(req, session, state),
        "read" => op_read(req, session, state).await,
        "write" => op_write(req, session, state).await,
        other => Response::err(req.id, format!("unknown op '{other}' (want login|read|write)")),
    }
}

fn op_login(req: Request, session: &mut Session, state: &ServerState) -> Response {
    let (Some(username), Some(password)) = (req.username, req.password) else {
        return Response::err(req.id, "login requires username and password");
    };
    match users::verify_login(&state.paths.users_db, &username, &password) {
        Some(role) => {
            session.username = Some(username);
            session.role = Some(role);
            let mut r = Response::ok(req.id);
            r.role = Some(role.as_str().to_string());
            r
        }
        None => Response::err(req.id, "invalid credentials"),
    }
}

fn require_auth(req: &Request, session: &Session) -> Result<Role, Response> {
    match session.role {
        Some(role) => Ok(role),
        None => Err(Response::err(req.id, "not authenticated: call login first")),
    }
}

fn check_access(
    req: &Request,
    role: Role,
    is_read: bool,
) -> Result<String, Response> {
    let db = req.db.clone().unwrap_or_default();
    if db.is_empty() {
        return Err(Response::err(req.id, "missing db"));
    }
    let access = access_for(&db, role);
    match access {
        crate::users::Access::Allow => Ok(db),
        crate::users::Access::ReadOnly if is_read => Ok(db),
        crate::users::Access::ReadOnly => Err(Response::err(
            req.id,
            format!("forbidden: ~dbs are readonly for Standard"),
        )),
        crate::users::Access::Deny => Err(Response::err(
            req.id,
            format!("forbidden: #{db} is admin-only"),
        )),
    }
}

async fn op_read(req: Request, session: &Session, state: &ServerState) -> Response {
    let role = match require_auth(&req, session) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let db = match check_access(&req, role, true) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(sql) = req.sql else {
        return Response::err(req.id, "read requires sql");
    };
    let db_path = match state.paths.db_path(&db) {
        Ok(p) => p,
        Err(e) => return Response::err(req.id, format!("{e:#}")),
    };
    let is_users = db == "#users";
    // Blocking sqlite read on a blocking thread; reads never touch the write queue.
    let id = req.id;
    match tokio::task::spawn_blocking(move || db::do_read(db_path, sql, is_users)).await {
        Ok(Ok(r)) => {
            let mut resp = Response::ok(id);
            let row_count = r.rows.len();
            resp.columns = Some(r.columns);
            resp.rows = Some(r.rows);
            resp.row_count = Some(row_count);
            resp
        }
        Ok(Err(e)) => Response::err(id, format!("{e:#}")),
        Err(e) => Response::err(id, format!("read task failed: {e}")),
    }
}

async fn op_write(req: Request, session: &Session, state: &ServerState) -> Response {
    let role = match require_auth(&req, session) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let db = match check_access(&req, role, false) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(sql) = req.sql else {
        return Response::err(req.id, "write requires sql");
    };
    match state.writes.submit(&db, sql).await {
        Ok(w) => {
            let mut resp = Response::ok(req.id);
            resp.rows_affected = Some(w.rows_affected);
            resp.last_insert_rowid = Some(w.last_insert_rowid);
            resp
        }
        Err(e) => Response::err(req.id, format!("{e:#}")),
    }
}
