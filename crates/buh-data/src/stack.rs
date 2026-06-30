//! Wiring: open the embedded Turso datastore and assemble a [`Ctx`] of port adapters.

use std::sync::Arc;

use turso::Builder;

use buh_core::CoreError;
use buh_core::context::{CoreConfig, Ctx};

use crate::error::repo;
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
            config: core_config,
        };

        Ok(Self { db, ctx })
    }

    /// Run the embedded migrations.
    pub async fn migrate(&self) -> Result<(), CoreError> {
        let conn = self.db.connect().map_err(repo)?;
        crate::migrate::run(&conn).await
    }
}
