//! Wiring: open the embedded Turso datastore and assemble a [`Ctx`] of port adapters.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use turso::Builder;

use buh_core::CoreError;
use buh_core::context::{CoreConfig, Ctx};

use crate::error::repo;
use crate::fs_blob::FsBlobStore;
use crate::node_ca::RcgenNodeCa;
use crate::peer_trust::TursoPeerTrust;
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
            pki: None,
            peer_trust: None,
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

    /// Enable PQ-mTLS: load (or generate) this node's CA under `pki_dir`, issuing leaves valid
    /// for `leaf_ttl` and stamped with `sans`, and attach the Turso-backed peer-trust registry.
    /// Both ports are set together — a node serving PQ-mTLS also needs a trust registry.
    pub fn with_node_pki(
        mut self,
        pki_dir: impl Into<PathBuf>,
        sans: Vec<String>,
        leaf_ttl: Duration,
    ) -> Result<Self, CoreError> {
        let pki = RcgenNodeCa::load_or_init(pki_dir, sans, leaf_ttl)?;
        self.ctx.pki = Some(Arc::new(pki));
        self.ctx.peer_trust = Some(Arc::new(TursoPeerTrust::new(self.db.clone())));
        Ok(self)
    }

    /// Run the embedded migrations.
    pub async fn migrate(&self) -> Result<(), CoreError> {
        let conn = self.db.connect().map_err(repo)?;
        crate::migrate::run(&conn).await
    }
}
