//! A small forward-only migration runner.
//!
//! We don't use `sqlx::migrate!` — the `turso` crate is the native datastore API, not sqlx.
//! Migrations are ordered SQL files embedded at build time; applied versions are tracked in a
//! `schema_version` table so re-running is a no-op. Files are immutable once committed: a new
//! schema change lands as a new file with the next version number.

use chrono::Utc;
use turso::Connection;

use buh_core::CoreError;

use crate::error::repo;

/// The ordered set of embedded migrations: `(version, sql)`.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/0001_init.sql")),
    (2, include_str!("../migrations/0002_peer_trust.sql")),
];

/// Apply any migrations not yet recorded in `schema_version`, in order.
pub async fn run(conn: &Connection) -> Result<(), CoreError> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (\
            version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)",
        (),
    )
    .await
    .map_err(repo)?;

    for (version, sql) in MIGRATIONS {
        if is_applied(conn, *version).await? {
            continue;
        }
        for stmt in split_statements(sql) {
            conn.execute(stmt.as_str(), ()).await.map_err(repo)?;
        }
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
            (*version, Utc::now().timestamp_millis()),
        )
        .await
        .map_err(repo)?;
        tracing::info!(version, "applied migration");
    }
    Ok(())
}

/// Whether a migration version has already been applied.
async fn is_applied(conn: &Connection, version: i64) -> Result<bool, CoreError> {
    let mut rows = conn
        .query(
            "SELECT 1 FROM schema_version WHERE version = ?1",
            (version,),
        )
        .await
        .map_err(repo)?;
    Ok(rows.next().await.map_err(repo)?.is_some())
}

/// Split a migration file into individual statements: strip line comments, split on `;`,
/// drop empties. Sufficient for DDL (no `;` or `--` inside string literals here).
fn split_statements(sql: &str) -> Vec<String> {
    let stripped: String = sql
        .lines()
        .map(|line| match line.find("--") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");

    stripped
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::split_statements;

    #[test]
    fn splits_ddl_and_strips_comments() {
        let sql =
            "-- a comment\nCREATE TABLE t (id INTEGER);\n-- another\nCREATE INDEX i ON t (id);\n";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].starts_with("CREATE TABLE"));
        assert!(stmts[1].starts_with("CREATE INDEX"));
    }
}
