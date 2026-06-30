//! Shared application state handed to every handler.

use std::time::Duration;

use buh_core::Ctx;

/// Cheaply-cloneable handler state (the inner [`Ctx`] is all `Arc`s).
#[derive(Clone)]
pub struct AppState {
    /// The wired-up business-logic context.
    pub ctx: Ctx,
    /// Maximum long-poll wait a client may request.
    pub max_wait: Duration,
}
