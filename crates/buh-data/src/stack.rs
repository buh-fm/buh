//! Wiring: open the embedded Turso datastore and assemble a [`Ctx`] of port adapters.

use std::path::PathBuf;
use std::sync::Arc;

use turso::Builder;

use buh_core::CoreError;
use buh_core::context::{CoreConfig, Ctx};

use crate::error::repo;
use crate::fs_blob::FsBlobStore;
use crate::turso_mailbox::TursoMailboxRepo;

/// The assembled data stack: the database handle (for migrations) and a ready-to-use [`Ctx`].
pub struct DataStack {
    /// The embedded Turso database handle.
    pub db: turso::Database,
    /// The wired-up business-logic context.
    pub ctx: Ctx,
}

impl DataStack {
    /// Open (creating if absent) the local datastore at `db_path` and assemble the adapters.
    /// Use `":memory:"` for an ephemeral store (tests).
    pub async fn connect(db_path: &str, core_config: CoreConfig) -> Result<Self, CoreError> {
        let db = Builder::new_local(db_path).build().await.map_err(repo)?;

        let mailbox = Arc::new(TursoMailboxRepo::new(db.clone()));
        let ctx = Ctx {
            mailbox,
            blob: None,
            config: core_config,
        };

        Ok(Self { db, ctx })
    }

    /// Attach a filesystem blob backend rooted at `root`, enabling the node's blob role.
    #[must_use]
    pub fn with_fs_blob(mut self, root: impl Into<PathBuf>) -> Self {
        self.ctx.blob = Some(Arc::new(FsBlobStore::new(root)));
        self
    }

    /// Attach an S3/MinIO blob backend, enabling the node's blob role (`s3` feature).
    #[cfg(feature = "s3")]
    #[must_use]
    pub fn with_s3_blob(mut self, settings: &crate::s3_blob::S3Settings) -> Self {
        self.ctx.blob = Some(Arc::new(crate::s3_blob::S3BlobStore::new(settings)));
        self
    }

    /// Run the embedded migrations.
    pub async fn migrate(&self) -> Result<(), CoreError> {
        let conn = self.db.connect().map_err(repo)?;
        crate::migrate::run(&conn).await
    }
}
