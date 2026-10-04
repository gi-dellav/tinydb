use std::path::PathBuf;

/// All on-disk locations for the server, rooted at `~/.tinydb`
/// (overridable via `TINYDB_ROOT` env var, mainly for tests).
#[derive(Debug, Clone)]
pub struct TinyPaths {
    pub root: PathBuf,
    pub users_db: PathBuf,
    pub dbs_dir: PathBuf,
    pub certs_dir: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

impl TinyPaths {
    pub fn resolve() -> anyhow::Result<Self> {
        if let Ok(root) = std::env::var("TINYDB_ROOT") {
            return Ok(Self::from_root(PathBuf::from(root)));
        }
        let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot resolve home dir"))?;
        Ok(Self::from_root(home.join(".tinydb")))
    }

    pub fn from_root(root: PathBuf) -> Self {
        let users_db = root.join("users.db");
        let dbs_dir = root.join("dbs");
        let certs_dir = root.join("certs");
        let cert_file = certs_dir.join("cert.pem");
        let key_file = certs_dir.join("key.pem");
        Self {
            root,
            users_db,
            dbs_dir,
            certs_dir,
            cert_file,
            key_file,
        }
    }

    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.dbs_dir)?;
        std::fs::create_dir_all(&self.certs_dir)?;
        if let Some(parent) = self.users_db.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    /// Map a logical db name to a filesystem path.
    /// `#users` is an alias for the users.db file itself.
    pub fn db_path(&self, name: &str) -> anyhow::Result<PathBuf> {
        validate_db_name(name)?;
        if name == "#users" {
            return Ok(self.users_db.clone());
        }
        Ok(self.dbs_dir.join(format!("{name}.db")))
    }

    #[allow(dead_code)]
    pub fn is_users_alias(name: &str) -> bool {
        name == "#users"
    }
}

/// Validate a logical database name.
///
/// Rules:
/// - non-empty, max 64 chars
/// - no `/`, `\`, NUL bytes, no `..` sequences
/// - first char: alphanumeric, `#`, `~`, `_`
/// - rest: alphanumeric, `_`, `-`, `.`, `#`, `~`
pub fn validate_db_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("empty database name");
    }
    if name.len() > 64 {
        anyhow::bail!("database name too long (max 64)");
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        anyhow::bail!("invalid database name: path separators not allowed");
    }
    if name.contains("..") {
        anyhow::bail!("invalid database name: '..' not allowed");
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !(first.is_alphanumeric() || first == '#' || first == '~' || first == '_') {
        anyhow::bail!("invalid database name: bad first character '{first}'");
    }
    for c in chars {
        if !(c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '#' || c == '~') {
            anyhow::bail!("invalid database name: bad character '{c}'");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        for n in ["shop", "#secrets", "~public", "#users", "my-db_1", "a.b"] {
            assert!(validate_db_name(n).is_ok(), "{n}");
        }
    }

    #[test]
    fn invalid_names() {
        for n in [
            "",
            "../evil",
            "a/b",
            "a\\b",
            "..",
            "foo;bar",
            "foo bar",
            ".hidden",
            "/abs",
        ] {
            assert!(validate_db_name(n).is_err(), "{n}");
        }
    }

    #[test]
    fn users_alias_maps_to_users_db() {
        let p = TinyPaths::from_root(PathBuf::from("/tmp/x"));
        assert_eq!(p.db_path("#users").unwrap(), PathBuf::from("/tmp/x/users.db"));
        assert_eq!(
            p.db_path("shop").unwrap(),
            PathBuf::from("/tmp/x/dbs/shop.db")
        );
        // `#`/`~` prefixes are kept literally in the filename
        assert_eq!(
            p.db_path("#s").unwrap(),
            PathBuf::from("/tmp/x/dbs/#s.db")
        );
    }
}
