//! CLI entry point. Bind HTTP before spawning modules and stop on Ctrl+C.
//! Client commands (modules, start, stop, exec) only talk to a running server.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::sync::{oneshot, Mutex};
use tracing::info;
use tracing_subscriber::EnvFilter;

use avscan_orchestrator::api;
use avscan_orchestrator::cli::{Cli, Command};
use avscan_orchestrator::client;
use avscan_orchestrator::config::Config;
use avscan_orchestrator::hosted::{split_hosted, HostedRunner};
use avscan_orchestrator::supervisor::{load_specs, Orchestrator, RunOptions};

/// Shorter tokens are too easy to guess; the API is reachable by every local user.
const MIN_TOKEN_LEN: usize = 16;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if !matches!(cli.command, Command::Validate | Command::Serve { .. }) {
        return client::run(&cli.command, cli.token.as_deref()).await;
    }
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    let config = Config::from_file(&cli.config)?;
    let specs = load_specs(&config)?;
    let (hosted, specs) = split_hosted(specs, &config.pipes)?;
    let listen = match cli.command {
        Command::Serve { listen } => listen.unwrap_or(config.listen_addr()?),
        _ => {
            let total = specs.len() + hosted.len();
            info!(modules = total, hosted = hosted.len(), "configuration validated");
            return Ok(());
        }
    };
    if !listen.ip().is_loopback() {
        bail!("HTTP API must bind a loopback address");
    }
    if cli
        .token
        .as_deref()
        .is_some_and(|t| t.len() < MIN_TOKEN_LEN)
    {
        bail!("the API token must be at least {MIN_TOKEN_LEN} characters");
    }
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let auth = cli.token.is_some();
    info!(address = %listener.local_addr()?, auth, "HTTP API listening");
    let orchestrator = Orchestrator::start(specs, RunOptions::default());
    let hosted = HostedRunner::start(hosted, RunOptions::default());
    let shared = Arc::new(Mutex::new(orchestrator));
    let app = api::router_with_token(Arc::clone(&shared), cli.token.clone());
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = stop_rx.await;
    });
    let mut task = tokio::spawn(async move { server.await });
    let outcome: Result<()> = tokio::select! {
        result = &mut task => {
            match result {
                Ok(result) => result.context("HTTP server failed"),
                Err(error) => Err(error.into()),
            }
        }
        signal = tokio::signal::ctrl_c() => {
            let result = signal.context("waiting for Ctrl+C");
            let _ = stop_tx.send(());
            // SSE clients can keep a graceful shutdown open indefinitely.
            task.abort();
            let _ = task.await;
            result
        }
    };
    // No request handler holds this mutex while streaming SSE.
    let mutex = Arc::try_unwrap(shared).map_err(|_| anyhow::anyhow!("API state still shared"))?;
    mutex.into_inner().shutdown().await;
    hosted.shutdown().await;
    outcome
}
