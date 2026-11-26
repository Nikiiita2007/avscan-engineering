//! Process supervisor: spawns module executables, runs the handshake and
//! restarts failed modules according to their manifest restart policy.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use avscan_manifest::{parse_manifest, Manifest, RestartPolicy, HOST_API_VERSION};
use serde_json::{Map, Value};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::bus::{new_bus, BusEvent};
use crate::config::Config;
use crate::session::{Connection, Session, SessionEnd, Timeouts};

/// Lifecycle state of one supervised module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleStatus {
    Starting,
    Running,
    Restarting { attempt: u32 },
    Stopped,
    Failed(String),
}

/// Everything needed to launch one module.
#[derive(Debug, Clone)]
pub struct ModuleSpec {
    pub manifest: Manifest,
    pub binary: PathBuf,
    pub extra_args: Vec<String>,
    pub config_override: Map<String, Value>,
}

/// Exponential restart delay: `base * 2^attempt`, capped at `max`.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub base: Duration,
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::from_millis(500),
            max: Duration::from_secs(30),
        }
    }
}

impl Backoff {
    /// Delay before restart number `attempt` (0-based).
    pub fn delay(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.max)
    }
}

/// Tunables of the supervision loop.
#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    pub timeouts: Timeouts,
    pub backoff: Backoff,
    /// Idle time before the supervisor pings a silent module.
    pub ping_interval: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            backoff: Backoff::default(),
            ping_interval: Duration::from_secs(5),
        }
    }
}

/// Reads and validates the manifests listed in the configuration.
pub fn load_specs(config: &Config) -> Result<Vec<ModuleSpec>> {
    let mut specs = Vec::new();
    for entry in config.modules.iter().filter(|m| m.enabled) {
        let shown = entry.manifest.display();
        let text = std::fs::read_to_string(&entry.manifest)
            .with_context(|| format!("reading manifest {shown}"))?;
        let manifest =
            parse_manifest(&text, HOST_API_VERSION).with_context(|| format!("manifest {shown}"))?;
        specs.push(ModuleSpec {
            manifest,
            binary: entry.binary.clone(),
            extra_args: entry.args.clone(),
            config_override: Map::new(),
        });
    }
    Ok(specs)
}

enum Outcome {
    Shutdown,
    Failed(String),
}

fn spawn(spec: &ModuleSpec) -> std::io::Result<Child> {
    Command::new(&spec.binary)
        .args(&spec.manifest.args)
        .args(&spec.extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
}

/// One launch of a module: spawn, handshake, serve until shutdown or failure.
async fn run_once(
    spec: &ModuleSpec,
    bus: &broadcast::Sender<BusEvent>,
    status: &watch::Sender<ModuleStatus>,
    shutdown: &mut watch::Receiver<bool>,
    opts: &RunOptions,
) -> Outcome {
    let mut child = match spawn(spec) {
        Ok(child) => child,
        Err(e) => {
            let reason = format!("cannot spawn {}: {e}", spec.binary.display());
            return Outcome::Failed(reason);
        }
    };
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill().await;
        return Outcome::Failed("child stdio is not piped".to_string());
    };
    let conn = Connection::new(stdout, stdin);
    let mut session = Session::new(conn, spec.manifest.clone(), bus.clone(), opts.timeouts);
    if let Err(e) = session.start(&spec.config_override).await {
        let _ = child.kill().await;
        return Outcome::Failed(format!("handshake failed: {e}"));
    }
    let _ = status.send(ModuleStatus::Running);
    match session.run(shutdown, opts.ping_interval).await {
        SessionEnd::Shutdown { graceful } => {
            let exited = tokio::time::timeout(opts.timeouts.stop, child.wait()).await;
            if !graceful || exited.is_err() {
                let _ = child.kill().await;
            }
            Outcome::Shutdown
        }
        SessionEnd::Failed(reason) => {
            let _ = child.kill().await;
            Outcome::Failed(reason)
        }
    }
}

/// Supervises one module until shutdown or until it fails for good.
pub async fn run_module(
    spec: ModuleSpec,
    bus: broadcast::Sender<BusEvent>,
    status: watch::Sender<ModuleStatus>,
    mut shutdown: watch::Receiver<bool>,
    opts: RunOptions,
) {
    let id = spec.manifest.id.clone();
    let mut restarts: u32 = 0;
    loop {
        if *shutdown.borrow() {
            let _ = status.send(ModuleStatus::Stopped);
            return;
        }
        let _ = status.send(ModuleStatus::Starting);
        match run_once(&spec, &bus, &status, &mut shutdown, &opts).await {
            Outcome::Shutdown => {
                info!(module = %id, "module stopped");
                let _ = status.send(ModuleStatus::Stopped);
                return;
            }
            Outcome::Failed(reason) => {
                let policy_allows = spec.manifest.restart_policy == RestartPolicy::OnFailure;
                if !policy_allows || restarts >= spec.manifest.max_restarts {
                    error!(module = %id, %reason, "module failed permanently");
                    let _ = status.send(ModuleStatus::Failed(reason));
                    return;
                }
                restarts += 1;
                warn!(module = %id, %reason, attempt = restarts, "module failed, restarting");
                let _ = status.send(ModuleStatus::Restarting { attempt: restarts });
                let delay = opts.backoff.delay(restarts - 1);
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown.changed() => {}
                }
            }
        }
    }
}

/// Owns the supervision tasks of all modules.
pub struct Orchestrator {
    bus: broadcast::Sender<BusEvent>,
    shutdown_tx: watch::Sender<bool>,
    modules: Vec<(String, watch::Receiver<ModuleStatus>)>,
    tasks: Vec<JoinHandle<()>>,
}

impl Orchestrator {
    /// Starts supervising every spec on its own task.
    pub fn start(specs: Vec<ModuleSpec>, opts: RunOptions) -> Self {
        let bus = new_bus();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut modules = Vec::new();
        let mut tasks = Vec::new();
        for spec in specs {
            let (status_tx, status_rx) = watch::channel(ModuleStatus::Starting);
            modules.push((spec.manifest.id.clone(), status_rx));
            let task = run_module(spec, bus.clone(), status_tx, shutdown_rx.clone(), opts);
            tasks.push(tokio::spawn(task));
        }
        Self {
            bus,
            shutdown_tx,
            modules,
            tasks,
        }
    }

    /// Subscribes to events published by all modules.
    pub fn subscribe(&self) -> broadcast::Receiver<BusEvent> {
        self.bus.subscribe()
    }

    /// Current status of every module.
    pub fn statuses(&self) -> Vec<(String, ModuleStatus)> {
        let current =
            |(id, rx): &(String, watch::Receiver<ModuleStatus>)| (id.clone(), rx.borrow().clone());
        self.modules.iter().map(current).collect()
    }

    /// Asks every module to stop and waits for the supervision tasks.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::time::timeout;

    fn spec_for(policy: &str, max: u32) -> ModuleSpec {
        let text = format!(
            r#"{{"id":"ghost_mod","name":"Ghost","version":"0.1.0","api_version":1,"entry":{{"exe":"ghost"}},"restart":{{"policy":"{policy}","max_restarts":{max}}}}}"#
        );
        ModuleSpec {
            manifest: parse_manifest(&text, HOST_API_VERSION).unwrap(),
            binary: PathBuf::from("definitely-missing-binary-xyz"),
            extra_args: Vec::new(),
            config_override: Map::new(),
        }
    }

    fn fast_opts() -> RunOptions {
        RunOptions {
            timeouts: Timeouts::default(),
            backoff: Backoff {
                base: Duration::from_millis(1),
                max: Duration::from_millis(5),
            },
            ping_interval: Duration::from_secs(1),
        }
    }

    async fn wait_failed(rx: &mut watch::Receiver<ModuleStatus>) -> Option<String> {
        loop {
            if let ModuleStatus::Failed(reason) = rx.borrow_and_update().clone() {
                return Some(reason);
            }
            if rx.changed().await.is_err() {
                return None;
            }
        }
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let backoff = Backoff {
            base: Duration::from_millis(100),
            max: Duration::from_secs(1),
        };
        assert_eq!(backoff.delay(0), Duration::from_millis(100));
        assert_eq!(backoff.delay(1), Duration::from_millis(200));
        assert_eq!(backoff.delay(2), Duration::from_millis(400));
        assert_eq!(backoff.delay(4), Duration::from_secs(1));
        assert_eq!(backoff.delay(1000), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn missing_binary_fails_without_restart_policy() {
        let orch = Orchestrator::start(vec![spec_for("never", 0)], fast_opts());
        let mut rx = orch.modules[0].1.clone();
        let reason = timeout(Duration::from_secs(5), wait_failed(&mut rx))
            .await
            .expect("module did not fail in time")
            .expect("status channel closed");
        assert!(reason.contains("cannot spawn"), "{reason}");
        orch.shutdown().await;
    }

    #[tokio::test]
    async fn restarts_are_bounded_by_max_restarts() {
        let orch = Orchestrator::start(vec![spec_for("on_failure", 2)], fast_opts());
        let mut rx = orch.modules[0].1.clone();
        let reason = timeout(Duration::from_secs(5), wait_failed(&mut rx))
            .await
            .expect("module did not fail in time")
            .expect("status channel closed");
        assert!(reason.contains("cannot spawn"), "{reason}");
        orch.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_stops_a_module_that_is_waiting_to_restart() {
        let mut opts = fast_opts();
        opts.backoff.base = Duration::from_secs(30);
        opts.backoff.max = Duration::from_secs(30);
        let orch = Orchestrator::start(vec![spec_for("on_failure", 5)], opts);
        tokio::time::sleep(Duration::from_millis(100)).await;
        timeout(Duration::from_secs(5), orch.shutdown())
            .await
            .expect("shutdown hung");
    }
}
