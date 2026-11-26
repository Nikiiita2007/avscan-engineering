//! Command-line configuration. Relative paths follow the current directory.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about = "AVScan module orchestrator")]
pub struct Cli {
    #[arg(long, env = "AVSCAN_CONFIG", default_value = "orchestrator.json")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

/// Address of a running orchestrator for the client commands.
#[derive(Debug, Args)]
pub struct ApiArgs {
    #[arg(long = "api", env = "AVSCAN_API", default_value = "127.0.0.1:8787")]
    pub addr: SocketAddr,
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
    /// Print the state of every module of a running orchestrator.
    Modules {
        #[command(flatten)]
        api: ApiArgs,
    },
    /// Start a stopped or failed module.
    Start {
        id: String,
        #[command(flatten)]
        api: ApiArgs,
    },
    /// Ask a running module to stop.
    Stop {
        id: String,
        #[command(flatten)]
        api: ApiArgs,
    },
    /// Send a command (a declared capability) to a module and print the result.
    Exec {
        id: String,
        name: String,
        /// JSON object with the command arguments.
        #[arg(long, default_value = "{}")]
        args: String,
        #[command(flatten)]
        api: ApiArgs,
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

    #[test]
    fn parses_stop_with_api_address() {
        let args = ["orchestrator", "stop", "log_hunter", "--api", "127.0.0.1:9000"];
        let cli = Cli::try_parse_from(args).unwrap();
        match cli.command {
            Command::Stop { id, api } => {
                assert_eq!(id, "log_hunter");
                assert_eq!(api.addr.port(), 9000);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn exec_defaults_to_empty_arguments() {
        let args = ["orchestrator", "exec", "log_hunter", "log.hunt"];
        let cli = Cli::try_parse_from(args).unwrap();
        match cli.command {
            Command::Exec { name, args, api, .. } => {
                assert_eq!(name, "log.hunt");
                assert_eq!(args, "{}");
                assert_eq!(api.addr.port(), 8787);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }
}
