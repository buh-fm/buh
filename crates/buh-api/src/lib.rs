//! buh node daemon library: configuration, state, error mapping, handlers, and the router.
//!
//! The binary (`main.rs`) is a thin wrapper that loads config, wires the datastore, and serves
//! [`router`]. Exposing these as a library lets integration tests drive the real router.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod handlers;
pub mod router;
pub mod state;

pub use config::AppConfig;
pub use router::router;
pub use state::AppState;
