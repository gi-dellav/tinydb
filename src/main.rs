mod db;
mod paths;
mod proto;
mod server;
mod tls;
mod users;

use std::sync::Arc;

use crate::db::WriteRegistry;
use crate::paths::TinyPaths;
use crate::server::{ServerState, serve};

fn usage() -> &'static str {
    "usage: tinydb [--port PORT] [--cert FILE] [--key FILE] [--bootstrap-admin USER:PASS]"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut port: u16 = 4777;
    let mut cert_override: Option<String> = None;
    let mut key_override: Option<String> = None;
    let mut bootstrap: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => {
                let v = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("{}\n--port needs a value", usage()))?;
                port = v.parse().map_err(|_| anyhow::anyhow!("invalid --port '{v}'"))?;
            }
            "--cert" => {
                cert_override = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("{}\n--cert needs a value", usage()))?,
                );
            }
            "--key" => {
                key_override = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("{}\n--key needs a value", usage()))?,
                );
            }
            "--bootstrap-admin" => {
                bootstrap = Some(
                    args.next().ok_or_else(|| {
                        anyhow::anyhow!("{}\n--bootstrap-admin needs USER:PASS", usage())
                    })?,
                );
            }
            "-h" | "--help" => {
                println!("{}", usage());
                return Ok(());
            }
            other => anyhow::bail!("{}\nunknown arg '{other}'", usage()),
        }
    }

    let mut paths = TinyPaths::resolve()?;
    if let Some(c) = cert_override {
        paths.cert_file = c.into();
    }
    if let Some(k) = key_override {
        paths.key_file = k.into();
    }
    paths.ensure_dirs()?;

    // Init users.db (schema + pragmas).
    users::open_users_db(&paths.users_db)?;

    // Bootstrap admin on empty users table.
    if users::user_count(&paths.users_db)? == 0 {
        if let Some(spec) = bootstrap {
            let (u, p) = spec
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("--bootstrap-admin wants USER:PASS"))?;
            users::create_user_direct(&paths.users_db, u, p, users::Role::Admin)?;
            println!("bootstrapped admin '{u}'");
        } else {
            let pw = users::random_password(20);
            users::create_user_direct(&paths.users_db, "admin", &pw, users::Role::Admin)?;
            println!("created initial admin user 'admin' with password: {pw}");
        }
    }

    let tls_config = tls::load_or_generate(&paths)?;
    let acceptor = tls::acceptor(tls_config);

    let paths = Arc::new(paths);
    let state = ServerState {
        writes: WriteRegistry::new(paths.clone()),
        paths: paths.clone(),
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    println!(
        "tinydb listening on 0.0.0.0:{port} (root {})",
        paths.root.display()
    );
    serve(listener, acceptor, state).await
}
