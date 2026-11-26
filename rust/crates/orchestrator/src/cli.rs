//! Command-line configuration. Relative paths follow the current directory.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about = "AVScan module orchestrator")]
pub struct Cli {
    #[arg(long, env = "AVSCAN_CONFIG", default_value = "orchestrator.json")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate enabled module manifests without starting processes.
    Validate,
    /// Start modules and expose HTTP health, status and SSE endpoints.
    Serve {
        #[arg(long, env = "AVSCAN_LISTEN")]
        listen: Option<SocketAddr>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config_and_listen() {
        let cli = Cli::try_parse_from([
            "orchestrator",
            "--config",
            "demo.json",
            "serve",
            "--listen",
            "127.0.0.1:0",
        ])
        .unwrap();
        assert_eq!(cli.config, PathBuf::from("demo.json"));
        assert!(matches!(cli.command, Command::Serve { listen: Some(_) }));
    }

    #[test]
    fn rejects_invalid_address() {
        let args = ["orchestrator", "serve", "--listen", "invalid"];
        assert!(Cli::try_parse_from(args).is_err());
    }
}
