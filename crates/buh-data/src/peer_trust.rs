//! [`PeerTrustRegistry`] over the embedded Turso datastore (`doc/design.md` §5.1).
//!
//! The set of peer-node CA fingerprints this node will accept on a PQ-mTLS handshake. Trust is
//! per-CA (pinned fingerprints), never a shared root: a peer is refused the moment its CA is
//! distrusted. The transport layer loads a cached snapshot of this set into its synchronous
//! certificate verifiers and refreshes it when the operator changes trust.

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use turso::{Database, Value};

use buh_core::{CoreError, PeerTrustRegistry, TrustedPeer};

use crate::error::repo;

/// Peer-CA trust registry backed by Turso.
pub struct TursoPeerTrust {
    db: Database,
}

impl TursoPeerTrust {
    /// Build a registry over an already-opened database handle.
    #[must_use]
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

/// Normalise a CA fingerprint to the canonical form stored and compared: lowercase hex with any
/// `:` separators and surrounding whitespace stripped (so `AA:BB…` from a CLI flag matches).
fn normalize(fingerprint: &str) -> String {
    fingerprint
        .trim()
        .chars()
        .filter(|c| *c != ':')
        .flat_map(char::to_lowercase)
        .collect()
}

#[async_trait]
impl PeerTrustRegistry for TursoPeerTrust {
    async fn trust(&self, ca_fingerprint: &str, note: Option<&str>) -> Result<(), CoreError> {
        let fp = normalize(ca_fingerprint);
        let conn = self.db.connect().map_err(repo)?;
        conn.execute(
            "INSERT INTO peer_trust (ca_fingerprint, note, trusted_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(ca_fingerprint) DO UPDATE SET note = excluded.note",
            (
                fp,
                note.map_or(Value::Null, |n| Value::Text(n.to_string())),
                Utc::now().timestamp_millis(),
            ),
        )
        .await
        .map_err(repo)?;
        Ok(())
    }

    async fn distrust(&self, ca_fingerprint: &str) -> Result<bool, CoreError> {
        let fp = normalize(ca_fingerprint);
        let conn = self.db.connect().map_err(repo)?;
        let affected = conn
            .execute("DELETE FROM peer_trust WHERE ca_fingerprint = ?1", (fp,))
            .await
            .map_err(repo)?;
        Ok(affected > 0)
    }

    async fn is_trusted(&self, ca_fingerprint: &str) -> Result<bool, CoreError> {
        let fp = normalize(ca_fingerprint);
        let conn = self.db.connect().map_err(repo)?;
        let mut rows = conn
            .query("SELECT 1 FROM peer_trust WHERE ca_fingerprint = ?1", (fp,))
            .await
            .map_err(repo)?;
        Ok(rows.next().await.map_err(repo)?.is_some())
    }

    async fn list(&self) -> Result<Vec<TrustedPeer>, CoreError> {
        let conn = self.db.connect().map_err(repo)?;
        let mut rows = conn
            .query(
                "SELECT ca_fingerprint, note, trusted_at FROM peer_trust ORDER BY trusted_at DESC",
                (),
            )
            .await
            .map_err(repo)?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(repo)? {
            let ca_fingerprint = match row.get_value(0).map_err(repo)? {
                Value::Text(s) => s,
                other => return Err(CoreError::Repo(format!("ca_fingerprint: {other:?}"))),
            };
            let note = match row.get_value(1).map_err(repo)? {
                Value::Text(s) => Some(s),
                Value::Null => None,
                other => return Err(CoreError::Repo(format!("note: {other:?}"))),
            };
            let trusted_at = match row.get_value(2).map_err(repo)? {
                Value::Integer(ms) => Utc
                    .timestamp_millis_opt(ms)
                    .single()
                    .ok_or_else(|| CoreError::Repo(format!("bad trusted_at: {ms}")))?,
                other => return Err(CoreError::Repo(format!("trusted_at: {other:?}"))),
            };
            out.push(TrustedPeer {
                ca_fingerprint,
                note,
                trusted_at,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use turso::Builder;

    async fn registry() -> TursoPeerTrust {
        let db = Builder::new_local(":memory:").build().await.unwrap();
        let conn = db.connect().unwrap();
        crate::migrate::run(&conn).await.unwrap();
        // `db.connect()` returns connections to the same in-memory store, so the registry sees
        // the schema migrated above.
        TursoPeerTrust::new(db)
    }

    #[tokio::test]
    async fn trust_then_distrust_roundtrip() {
        let reg = registry().await;
        let fp = "ab".repeat(32);
        assert!(!reg.is_trusted(&fp).await.unwrap());
        reg.trust(&fp, Some("peer one")).await.unwrap();
        assert!(reg.is_trusted(&fp).await.unwrap());
        assert!(reg.distrust(&fp).await.unwrap());
        assert!(!reg.is_trusted(&fp).await.unwrap());
        assert!(
            !reg.distrust(&fp).await.unwrap(),
            "second distrust is false"
        );
    }

    #[tokio::test]
    async fn fingerprint_is_normalized() {
        let reg = registry().await;
        reg.trust("AA:BB:CC", None).await.unwrap();
        assert!(reg.is_trusted("aabbcc").await.unwrap());
        assert!(reg.is_trusted(" aa:bb:cc ").await.unwrap());
    }

    #[tokio::test]
    async fn trust_is_idempotent_and_updates_note() {
        let reg = registry().await;
        let fp = "cd".repeat(32);
        reg.trust(&fp, Some("first")).await.unwrap();
        reg.trust(&fp, Some("second")).await.unwrap();
        let list = reg.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].note.as_deref(), Some("second"));
    }
}
