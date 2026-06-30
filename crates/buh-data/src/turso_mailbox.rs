//! [`MailboxRepo`] implemented over an embedded Turso datastore.
//!
//! All SQL for the relay lives here — centralised, since the `turso` crate gives no
//! compile-time query checking the way sqlx would. The integration test suite is the guard.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::Notify;
use turso::{Database, Row, Value};

use buh_core::{CoreError, MailboxRepo};
use buh_entities::{EnvelopeId, NewEnvelope, QueueId, StoredEnvelope, queue::QUEUE_ID_LEN};

use crate::error::repo;

/// Relay/mailbox persistence backed by Turso, plus an in-process per-queue notifier used to
/// wake long-polling pulls (a node is a single process, so no cross-process pub/sub is needed).
pub struct TursoMailboxRepo {
    db: Database,
    notifiers: Arc<Mutex<HashMap<[u8; QUEUE_ID_LEN], Arc<Notify>>>>,
}

impl TursoMailboxRepo {
    /// Build a repo over an already-opened database handle.
    #[must_use]
    pub fn new(db: Database) -> Self {
        Self {
            db,
            notifiers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get (or create) the notifier for a queue.
    fn notifier(&self, queue_id: &QueueId) -> Arc<Notify> {
        let mut map = self.notifiers.lock().expect("notifier mutex poisoned");
        map.entry(*queue_id.as_bytes())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }
}

#[async_trait]
impl MailboxRepo for TursoMailboxRepo {
    async fn push(
        &self,
        queue_id: &QueueId,
        envelope: &NewEnvelope,
    ) -> Result<EnvelopeId, CoreError> {
        let conn = self.db.connect().map_err(repo)?;
        let envelope_id = EnvelopeId::new();
        let now = Utc::now().timestamp_millis();
        let expires = now.saturating_add(envelope.ttl_seconds.saturating_mul(1000));

        conn.execute(
            "INSERT INTO envelopes \
                (queue_id, envelope_id, payload, received_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                queue_id.as_bytes().to_vec(),
                envelope_id.to_string(),
                envelope.payload.clone(),
                now,
                expires,
            ),
        )
        .await
        .map_err(repo)?;

        // Wake any long-poller waiting on this queue.
        self.notifier(queue_id).notify_waiters();
        Ok(envelope_id)
    }

    async fn pull(&self, queue_id: &QueueId, limit: i64) -> Result<Vec<StoredEnvelope>, CoreError> {
        let conn = self.db.connect().map_err(repo)?;
        let now = Utc::now().timestamp_millis();

        let mut rows = conn
            .query(
                "SELECT envelope_id, payload, received_at, expires_at \
                 FROM envelopes \
                 WHERE queue_id = ?1 AND delivered_at IS NULL AND expires_at > ?2 \
                 ORDER BY received_at ASC, id ASC \
                 LIMIT ?3",
                (queue_id.as_bytes().to_vec(), now, limit),
            )
            .await
            .map_err(repo)?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(repo)? {
            out.push(row_to_envelope(&row)?);
        }
        Ok(out)
    }

    async fn ack(
        &self,
        queue_id: &QueueId,
        envelope_id: EnvelopeId,
        at: DateTime<Utc>,
    ) -> Result<bool, CoreError> {
        let conn = self.db.connect().map_err(repo)?;
        let at_ms = at.timestamp_millis();

        let affected = conn
            .execute(
                "UPDATE envelopes SET delivered_at = ?3 \
                 WHERE queue_id = ?1 AND envelope_id = ?2 AND delivered_at IS NULL",
                (queue_id.as_bytes().to_vec(), envelope_id.to_string(), at_ms),
            )
            .await
            .map_err(repo)?;

        if affected == 0 {
            return Ok(false);
        }

        conn.execute(
            "INSERT INTO delivery_receipts (queue_id, envelope_id, pulled_at) \
             VALUES (?1, ?2, ?3)",
            (queue_id.as_bytes().to_vec(), envelope_id.to_string(), at_ms),
        )
        .await
        .map_err(repo)?;

        Ok(true)
    }

    async fn expire(&self, now: DateTime<Utc>) -> Result<u64, CoreError> {
        let conn = self.db.connect().map_err(repo)?;
        let n = conn
            .execute(
                "DELETE FROM envelopes WHERE expires_at <= ?1",
                (now.timestamp_millis(),),
            )
            .await
            .map_err(repo)?;
        Ok(n)
    }

    async fn wait_for_envelope(
        &self,
        queue_id: &QueueId,
        timeout: Duration,
    ) -> Result<bool, CoreError> {
        let notifier = self.notifier(queue_id);
        match tokio::time::timeout(timeout, notifier.notified()).await {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Convert a result row (`envelope_id, payload, received_at, expires_at`) into a
/// [`StoredEnvelope`].
fn row_to_envelope(row: &Row) -> Result<StoredEnvelope, CoreError> {
    let envelope_id: EnvelopeId = value_text(row, 0)?
        .parse()
        .map_err(|e| CoreError::Repo(format!("bad envelope_id: {e}")))?;
    let payload = value_blob(row, 1)?;
    let received_at = ms_to_dt(value_int(row, 2)?)?;
    let expires_at = ms_to_dt(value_int(row, 3)?)?;

    Ok(StoredEnvelope {
        envelope_id,
        payload,
        received_at,
        expires_at,
    })
}

fn value_text(row: &Row, idx: usize) -> Result<String, CoreError> {
    match row.get_value(idx).map_err(repo)? {
        Value::Text(s) => Ok(s),
        other => Err(CoreError::Repo(format!(
            "col {idx}: expected text, got {other:?}"
        ))),
    }
}

fn value_blob(row: &Row, idx: usize) -> Result<Vec<u8>, CoreError> {
    match row.get_value(idx).map_err(repo)? {
        Value::Blob(b) => Ok(b),
        other => Err(CoreError::Repo(format!(
            "col {idx}: expected blob, got {other:?}"
        ))),
    }
}

fn value_int(row: &Row, idx: usize) -> Result<i64, CoreError> {
    match row.get_value(idx).map_err(repo)? {
        Value::Integer(i) => Ok(i),
        other => Err(CoreError::Repo(format!(
            "col {idx}: expected integer, got {other:?}"
        ))),
    }
}

fn ms_to_dt(ms: i64) -> Result<DateTime<Utc>, CoreError> {
    DateTime::from_timestamp_millis(ms)
        .ok_or_else(|| CoreError::Repo(format!("timestamp out of range: {ms}")))
}
