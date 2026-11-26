//! Orchestrator entry point: loads the configuration, supervises the modules
//! listed in it and stops them on Ctrl+C.

use std::path::Path;

use anyhow::{Context, Result};
use avscan_orchestrator::config::Config;
use avscan_orchestrator::supervisor::{load_specs, Orchestrator, RunOptions};
use tracing::info;
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("AVSCAN_CONFIG").ok())
        .unwrap_or_else(|| "orchestrator.json".to_string());
    let config = Config::from_file(Path::new(&path))?;
    info!(config = %path, modules = config.modules.len(), "config loaded");

    let specs = load_specs(&config)?;
    let orchestrator = Orchestrator::start(specs, RunOptions::default());
    info!(
        modules = orchestrator.statuses().len(),
        "orchestrator running, press Ctrl+C to stop"
    );
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl+C")?;
    info!("shutdown requested");
    orchestrator.shutdown().await;
    Ok(())
}
