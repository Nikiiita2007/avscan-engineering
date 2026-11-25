//! Orchestrator entry point (stage 1 skeleton: load config, validate manifests).

use std::path::Path;

use anyhow::{Context, Result};
use avscan_manifest::{parse_manifest, HOST_API_VERSION};
use avscan_orchestrator::config::Config;
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
    for entry in &config.modules {
        let shown = entry.manifest.display();
        let text = std::fs::read_to_string(&entry.manifest)
            .with_context(|| format!("reading manifest {shown}"))?;
        let manifest = parse_manifest(&text, HOST_API_VERSION)
            .with_context(|| format!("manifest {shown}"))?;
        info!(
            module = %manifest.id,
            version = %manifest.version,
            enabled = entry.enabled,
            "manifest validated"
        );
    }
    info!("supervisor is not implemented yet (stage 2)");
    Ok(())
}
