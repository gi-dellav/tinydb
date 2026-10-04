use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Standard,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "Standard" => Some(Role::Standard),
            "Admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Standard => "Standard",
            Role::Admin => "Admin",
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

/// Access policy for a logical db name + role.
///
/// - `#...` (incl. `#users`): admin only, read+write.
/// - `~...`: admin read+write, Standard read-only.
/// - else: everyone read+write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Allow,
    ReadOnly,
    Deny,
}

pub fn access_for(db: &str, role: Role) -> Access {
    if role.is_admin() {
        return Access::Allow;
    }
    if db.starts_with('#') {
        Access::Deny
    } else if db.starts_with('~') {
        Access::ReadOnly
    } else {
        Access::Allow
    }
}

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('Standard','Admin'))
)";

/// Open (creating if needed) the users DB and ensure schema + pragmas.
pub fn open_users_db(path: &std::path::Path) -> anyhow::Result<rusqlite::Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = rusqlite::Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!("hash password: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Verify a username/password against users.db.
/// Returns the role on success.
pub fn verify_login(users_db: &std::path::Path, username: &str, password: &str) -> Option<Role> {
    let conn = rusqlite::Connection::open_with_flags(
        users_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .ok()?;
    let (hash, role): (String, String) = conn
        .query_row(
            "SELECT password_hash, role FROM users WHERE username = ?1",
            rusqlite::params![username],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok()?;
    if !verify_password(password, &hash) {
        return None;
    }
    Role::parse(&role)
}

/// Number of users in users.db (for bootstrap check).
pub fn user_count(users_db: &std::path::Path) -> anyhow::Result<i64> {
    let conn = open_users_db(users_db)?;
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
    Ok(n)
}

/// Insert a user directly (used for bootstrap + tests).
pub fn create_user_direct(
    users_db: &std::path::Path,
    username: &str,
    password: &str,
    role: Role,
) -> anyhow::Result<()> {
    let conn = open_users_db(users_db)?;
    let hash = hash_password(password)?;
    conn.execute(
        "INSERT INTO users(username, password_hash, role) VALUES(?1, ?2, ?3)",
        rusqlite::params![username, hash, role.as_str()],
    )?;
    Ok(())
}

/// Generate a random alphanumeric password for bootstrap.
pub fn random_password(len: usize) -> String {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            let i = rng.random_range(0..ALPHABET.len());
            ALPHABET[i] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_matrix() {
        use Access::*;
        // admin: everything allowed
        assert_eq!(access_for("#users", Role::Admin), Allow);
        assert_eq!(access_for("#s", Role::Admin), Allow);
        assert_eq!(access_for("~p", Role::Admin), Allow);
        assert_eq!(access_for("shop", Role::Admin), Allow);
        // standard
        assert_eq!(access_for("#users", Role::Standard), Deny);
        assert_eq!(access_for("#s", Role::Standard), Deny);
        assert_eq!(access_for("~p", Role::Standard), ReadOnly);
        assert_eq!(access_for("shop", Role::Standard), Allow);
    }

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash_password("secret").unwrap();
        assert!(verify_password("secret", &h));
        assert!(!verify_password("wrong", &h));
    }
}
