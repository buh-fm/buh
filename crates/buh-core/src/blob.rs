//! Blob-role orchestration (`doc/design.md` §3.2).
//!
//! Like [`crate::mailbox`], deliberately thin: the node stores and returns opaque,
//! client-encrypted bytes it cannot read. What lives here is the role gate (a node not running
//! the blob role answers `Unimplemented`), size clamping, and delegation to the [`BlobStore`]
//! port. The locator (`bucket`/`key`) is the only capability — there is no per-blob auth, the
//! same sealed-sender stance the relay takes.

use buh_entities::EntityError;

use crate::context::Ctx;
use crate::error::CoreError;

/// Resolve the blob backend, or fail if this node does not run the blob role.
fn store(ctx: &Ctx) -> Result<&dyn crate::ports::BlobStore, CoreError> {
    ctx.blob
        .as_deref()
        .ok_or(CoreError::Unimplemented("node does not run the blob role"))
}

/// Store opaque ciphertext at `bucket`/`key`. The payload must be non-empty and within the
/// configured size limit.
pub async fn put(ctx: &Ctx, bucket: &str, key: &str, bytes: Vec<u8>) -> Result<(), CoreError> {
    if bytes.is_empty() {
        return Err(EntityError::InvalidPayload("empty").into());
    }
    if bytes.len() > ctx.config.max_blob_bytes {
        return Err(EntityError::InvalidPayload("exceeds size limit").into());
    }
    store(ctx)?.put(bucket, key, bytes).await
}

/// Fetch the opaque ciphertext at `bucket`/`key`. `NotFound` if absent.
pub async fn get(ctx: &Ctx, bucket: &str, key: &str) -> Result<Vec<u8>, CoreError> {
    store(ctx)?.get(bucket, key).await
}

/// Whether an object exists at `bucket`/`key`.
pub async fn exists(ctx: &Ctx, bucket: &str, key: &str) -> Result<bool, CoreError> {
    store(ctx)?.exists(bucket, key).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::context::CoreConfig;
    use crate::ports::{BlobStore, MailboxRepo};

    // A no-op mailbox so a `Ctx` can be built for the blob-role-gate tests.
    struct NoMailbox;
    #[async_trait]
    impl MailboxRepo for NoMailbox {
        async fn push(
            &self,
            _: &buh_entities::QueueId,
            _: &buh_entities::NewEnvelope,
        ) -> Result<buh_entities::EnvelopeId, CoreError> {
            unimplemented!()
        }
        async fn pull(
            &self,
            _: &buh_entities::QueueId,
            _: i64,
        ) -> Result<Vec<buh_entities::StoredEnvelope>, CoreError> {
            unimplemented!()
        }
        async fn ack(
            &self,
            _: &buh_entities::QueueId,
            _: buh_entities::EnvelopeId,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, CoreError> {
            unimplemented!()
        }
        async fn expire(&self, _: chrono::DateTime<chrono::Utc>) -> Result<u64, CoreError> {
            unimplemented!()
        }
        async fn wait_for_envelope(
            &self,
            _: &buh_entities::QueueId,
            _: std::time::Duration,
        ) -> Result<bool, CoreError> {
            unimplemented!()
        }
    }

    // An in-memory blob store, enough to exercise the orchestration.
    #[derive(Default)]
    struct MemBlob(std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>);
    #[async_trait]
    impl BlobStore for MemBlob {
        async fn exists(&self, bucket: &str, key: &str) -> Result<bool, CoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .contains_key(&format!("{bucket}/{key}")))
        }
        async fn put(&self, bucket: &str, key: &str, bytes: Vec<u8>) -> Result<(), CoreError> {
            self.0
                .lock()
                .unwrap()
                .insert(format!("{bucket}/{key}"), bytes);
            Ok(())
        }
        async fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, CoreError> {
            self.0
                .lock()
                .unwrap()
                .get(&format!("{bucket}/{key}"))
                .cloned()
                .ok_or(CoreError::NotFound)
        }
        async fn presign_get(&self, _: &str, _: &str, _: u64) -> Result<String, CoreError> {
            Err(CoreError::Unimplemented("no presign"))
        }
    }

    fn ctx(blob: Option<Arc<dyn BlobStore>>) -> Ctx {
        Ctx {
            mailbox: Arc::new(NoMailbox),
            blob,
            config: CoreConfig::default(),
        }
    }

    #[tokio::test]
    async fn without_blob_role_is_unimplemented() {
        let ctx = ctx(None);
        assert!(matches!(
            put(&ctx, "m", "k", b"x".to_vec()).await,
            Err(CoreError::Unimplemented(_))
        ));
        assert!(matches!(
            get(&ctx, "m", "k").await,
            Err(CoreError::Unimplemented(_))
        ));
    }

    #[tokio::test]
    async fn put_get_roundtrip_and_limits() {
        let ctx = ctx(Some(Arc::new(MemBlob::default())));
        assert!(put(&ctx, "m", "k", vec![]).await.is_err(), "empty rejected");

        let mut cfg = ctx.clone();
        cfg.config.max_blob_bytes = 4;
        assert!(
            put(&cfg, "m", "k", b"toolong".to_vec()).await.is_err(),
            "oversize rejected"
        );

        put(&ctx, "m", "k", b"sealed".to_vec()).await.unwrap();
        assert!(exists(&ctx, "m", "k").await.unwrap());
        assert_eq!(get(&ctx, "m", "k").await.unwrap(), b"sealed");
        assert!(matches!(
            get(&ctx, "m", "absent").await,
            Err(CoreError::NotFound)
        ));
    }
}
