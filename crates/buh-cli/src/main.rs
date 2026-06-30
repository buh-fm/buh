//! buh operator/admin CLI.
//!
//! Milestone 1 covers datastore migration and the TTL sweep. Phase 6 adds `ca init|rotate`
//! and `peer trust|distrust`; later phases add queue stats and blob verification.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use buh_core::{CoreConfig, mailbox};
use buh_data::DataStack;

/// buh operator/admin CLI.
#[derive(Debug, Parser)]
#[command(name = "buh-cli", version, about = "buh operator/admin CLI")]
struct Cli {
    /// Path to the embedded Turso datastore.
    #[arg(long, env = "BUH_DB_PATH", default_value = "buh-relay.db")]
    db_path: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Apply pending datastore migrations.
    Migrate,
    /// Delete expired envelopes (TTL sweep). Prints the number removed.
    Sweep,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,buh_cli=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    let stack = DataStack::connect(&cli.db_path, CoreConfig::default()).await?;

    match cli.command {
        Command::Migrate => {
            stack.migrate().await?;
            println!("migrations applied");
        }
        Command::Sweep => {
            stack.migrate().await?;
            let removed = mailbox::sweep(&stack.ctx).await?;
            println!("swept {removed} expired envelope(s)");
        }
    }

    Ok(())
}
