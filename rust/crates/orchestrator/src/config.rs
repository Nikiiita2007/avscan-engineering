//! Orchestrator configuration (JSON file). Every path and port is configurable.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8787";
pub const DEFAULT_LOG_DIR: &str = "logs";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read config {}: {source}", .path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// One module known to the orchestrator.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModuleEntry {
    /// Path to the module's `module.json`.
    pub manifest: PathBuf,
    /// Path to the module executable (overrides `entry.exe` of the manifest).
    pub binary: PathBuf,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Extra command-line arguments appended after the manifest arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Module settings sent in `start`. Keys given here replace the keys of
    /// the manifest `config`, for example `command_roots`.
    #[serde(default)]
    pub config: Map<String, Value>,
}

/// Top-level orchestrator configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// HTTP API listen address, e.g. `127.0.0.1:8787`.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Directory for JSON log files.
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,
    #[serde(default)]
    pub modules: Vec<ModuleEntry>,
}

fn default_true() -> bool {
    true
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

fn default_log_dir() -> PathBuf {
    PathBuf::from(DEFAULT_LOG_DIR)
}

impl Config {
    /// Parses and validates a configuration from JSON text.
    pub fn from_json_str(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = serde_json::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reads and validates a configuration file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json_str(&text)
    }

    /// The parsed API listen address.
    pub fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.listen
            .parse()
            .map_err(|_| ConfigError::Invalid(format!("bad listen address '{}'", self.listen)))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.listen_addr()?;
        let mut seen = HashSet::new();
        for module in &self.modules {
            if module.binary.as_os_str().is_empty() {
                return Err(ConfigError::Invalid(
                    "module binary path is empty".to_string(),
                ));
            }
            if !seen.insert(module.manifest.clone()) {
                let msg = format!("duplicate manifest {}", module.manifest.display());
                return Err(ConfigError::Invalid(msg));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_applied() {
        let cfg = Config::from_json_str("{}").unwrap();
        assert_eq!(cfg.listen, DEFAULT_LISTEN);
        assert_eq!(cfg.log_dir, PathBuf::from(DEFAULT_LOG_DIR));
        assert!(cfg.modules.is_empty());
    }

    #[test]
    fn parses_modules_and_overrides() {
        let text = r#"{
            "listen": "127.0.0.1:9000",
            "log_dir": "/var/log/avscan",
            "modules": [
                {"manifest": "modules/net_analyzer/module.json", "binary": "bin/net-analyzer"}
            ]
        }"#;
        let cfg = Config::from_json_str(text).unwrap();
        assert_eq!(cfg.listen_addr().unwrap().port(), 9000);
        assert_eq!(cfg.modules.len(), 1);
        assert!(cfg.modules[0].enabled);
        assert!(cfg.modules[0].args.is_empty());
    }

    #[test]
    fn module_settings_are_parsed() {
        let text = r#"{"modules": [
            {"manifest": "a.json", "binary": "a", "config": {"command_roots": ["/srv"]}}
        ]}"#;
        let cfg = Config::from_json_str(text).unwrap();
        assert_eq!(cfg.modules[0].config["command_roots"][0], "/srv");
        let text = r#"{"modules": [{"manifest": "b.json", "binary": "b"}]}"#;
        let plain = Config::from_json_str(text).unwrap();
        assert!(plain.modules[0].config.is_empty());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Config::from_json_str(r#"{"bogus": 1}"#).is_err());
    }

    #[test]
    fn rejects_bad_listen_address() {
        let err = Config::from_json_str(r#"{"listen": "nope"}"#).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn rejects_duplicate_manifests_and_empty_binary() {
        let dup = r#"{"modules": [
            {"manifest": "a.json", "binary": "a"},
            {"manifest": "a.json", "binary": "b"}
        ]}"#;
        assert!(Config::from_json_str(dup).is_err());
        let empty = r#"{"modules": [{"manifest": "a.json", "binary": ""}]}"#;
        assert!(Config::from_json_str(empty).is_err());
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let err = Config::from_file(Path::new("definitely/missing.json")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }
}
