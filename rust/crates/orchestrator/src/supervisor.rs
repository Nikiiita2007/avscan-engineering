//! Process supervisor: spawns module executables, runs the handshake and
//! restarts failed modules according to their manifest restart policy.
//! Every module has its own stop signal and bounded command queue, so one
//! module can be started, stopped or commanded independently.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use avscan_manifest::{parse_manifest, Manifest, RestartPolicy, HOST_API_VERSION};
use serde_json::{Map, Value};
use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::bus::{new_bus, BusEvent};
use crate::config::Config;
use crate::session::{CommandOutcome, Connection, HostCommand, Session, SessionEnd, Timeouts};

/// Commands that may wait for one module before the caller gets `QueueFull`.
const COMMAND_QUEUE: usize = 16;

/// Source name of events published by the orchestrator itself.
pub const HOST_SOURCE: &str = "host";

/// Lifecycle state of one supervised module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleStatus {
    Starting,
    Running,
    Restarting { attempt: u32 },
    Stopped,
    Failed(String),
}

/// Why a control request (start, stop, command) was refused.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ControlError {
    #[error("unknown module '{0}'")]
    UnknownModule(String),
    #[error("module is already running or still stopping")]
    AlreadyRunning,
    #[error("module is not running")]
    NotRunning,
    #[error("command queue of the module is full")]
    QueueFull,
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
    commands: &mut mpsc::Receiver<HostCommand>,
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
    match session.run(shutdown, commands, opts.ping_interval).await {
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
/// Commands queued while the module restarts are delivered after the restart.
pub async fn run_module(
    spec: ModuleSpec,
    bus: broadcast::Sender<BusEvent>,
    status: watch::Sender<ModuleStatus>,
    mut shutdown: watch::Receiver<bool>,
    mut commands: mpsc::Receiver<HostCommand>,
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
        let run = run_once(&spec, &bus, &status, &mut shutdown, &mut commands, &opts);
        match run.await {
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

/// Control handles of one supervised module.
struct ModuleEntry {
    spec: ModuleSpec,
    status: watch::Receiver<ModuleStatus>,
    stop: watch::Sender<bool>,
    commands: mpsc::Sender<HostCommand>,
    task: Option<JoinHandle<()>>,
}

impl ModuleEntry {
    fn is_active(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }
}

fn launch(spec: ModuleSpec, bus: &broadcast::Sender<BusEvent>, opts: RunOptions) -> ModuleEntry {
    let (status_tx, status_rx) = watch::channel(ModuleStatus::Starting);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE);
    let task = run_module(
        spec.clone(),
        bus.clone(),
        status_tx,
        stop_rx,
        command_rx,
        opts,
    );
    ModuleEntry {
        spec,
        status: status_rx,
        stop: stop_tx,
        commands: command_tx,
        task: Some(tokio::spawn(task)),
    }
}

/// Owns the supervision tasks of all modules.
pub struct Orchestrator {
    bus: broadcast::Sender<BusEvent>,
    opts: RunOptions,
    modules: Vec<ModuleEntry>,
}

impl Orchestrator {
    /// Starts supervising every spec on its own task.
    pub fn start(specs: Vec<ModuleSpec>, opts: RunOptions) -> Self {
        let bus = new_bus();
        let modules = specs
            .into_iter()
            .map(|spec| launch(spec, &bus, opts))
            .collect();
        Self { bus, opts, modules }
    }

    /// Subscribes to events published by all modules.
    pub fn subscribe(&self) -> broadcast::Receiver<BusEvent> {
        self.bus.subscribe()
    }

    /// Publishes an event from the host. Modules whose manifest `subscribes`
    /// list matches the topic receive it. Returns how many receivers the bus
    /// had (modules and SSE clients alike); it does not mean delivery.
    pub fn publish(&self, topic: &str, data: Value) -> usize {
        let event = BusEvent {
            topic: topic.to_string(),
            data,
            source: HOST_SOURCE.to_string(),
        };
        self.bus.send(event).unwrap_or(0)
    }

    /// Current status of every module.
    pub fn statuses(&self) -> Vec<(String, ModuleStatus)> {
        let current = |m: &ModuleEntry| (m.spec.manifest.id.clone(), m.status.borrow().clone());
        self.modules.iter().map(current).collect()
    }

    fn entry(&self, id: &str) -> Result<&ModuleEntry, ControlError> {
        let found = self.modules.iter().find(|m| m.spec.manifest.id == id);
        found.ok_or_else(|| ControlError::UnknownModule(id.to_string()))
    }

    fn entry_mut(&mut self, id: &str) -> Result<&mut ModuleEntry, ControlError> {
        let found = self.modules.iter_mut().find(|m| m.spec.manifest.id == id);
        found.ok_or_else(|| ControlError::UnknownModule(id.to_string()))
    }

    /// Starts a module whose supervision task has finished (stopped or failed).
    pub fn start_module(&mut self, id: &str) -> Result<(), ControlError> {
        let bus = self.bus.clone();
        let opts = self.opts;
        let entry = self.entry_mut(id)?;
        if entry.is_active() {
            return Err(ControlError::AlreadyRunning);
        }
        let spec = entry.spec.clone();
        *entry = launch(spec, &bus, opts);
        Ok(())
    }

    /// Requests a graceful stop; it does not wait for the module to exit.
    pub fn stop_module(&mut self, id: &str) -> Result<(), ControlError> {
        let entry = self.entry_mut(id)?;
        if !entry.is_active() {
            return Err(ControlError::NotRunning);
        }
        let _ = entry.stop.send(true);
        Ok(())
    }

    /// Queues a command for a module. The receiver yields the module's answer.
    pub fn command(
        &self,
        id: &str,
        name: String,
        args: Map<String, Value>,
    ) -> Result<oneshot::Receiver<CommandOutcome>, ControlError> {
        let entry = self.entry(id)?;
        let (reply, outcome) = oneshot::channel();
        let command = HostCommand { name, args, reply };
        entry.commands.try_send(command).map_err(|e| match e {
            TrySendError::Full(_) => ControlError::QueueFull,
            TrySendError::Closed(_) => ControlError::NotRunning,
        })?;
        Ok(outcome)
    }

    /// Asks every module to stop and waits for the supervision tasks.
    pub async fn shutdown(self) {
        for module in &self.modules {
            let _ = module.stop.send(true);
        }
        for module in self.modules {
            if let Some(task) = module.task {
                let _ = task.await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
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
        let mut rx = orch.modules[0].status.clone();
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
        let mut rx = orch.modules[0].status.clone();
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

    #[tokio::test]
    async fn unknown_module_is_reported() {
        let mut orch = Orchestrator::start(Vec::new(), fast_opts());
        let missing = ControlError::UnknownModule("nope".to_string());
        assert_eq!(orch.start_module("nope"), Err(missing.clone()));
        assert_eq!(orch.stop_module("nope"), Err(missing.clone()));
        let command = orch.command("nope", "scan.run".to_string(), Map::new());
        assert_eq!(command.err(), Some(missing));
    }

    #[tokio::test]
    async fn stop_module_stops_one_waiting_module() {
        let mut opts = fast_opts();
        opts.backoff.base = Duration::from_secs(30);
        opts.backoff.max = Duration::from_secs(30);
        let mut orch = Orchestrator::start(vec![spec_for("on_failure", 5)], opts);
        tokio::time::sleep(Duration::from_millis(100)).await;
        orch.stop_module("ghost_mod").unwrap();
        let mut rx = orch.modules[0].status.clone();
        let stopped = timeout(Duration::from_secs(5), async {
            while *rx.borrow_and_update() != ModuleStatus::Stopped {
                rx.changed().await.unwrap();
            }
        })
        .await;
        assert!(stopped.is_ok(), "module did not reach Stopped");
        orch.shutdown().await;
    }

    #[tokio::test]
    async fn publish_reaches_subscribers_with_the_host_as_source() {
        let orch = Orchestrator::start(Vec::new(), fast_opts());
        let mut events = orch.subscribe();
        let receivers = orch.publish("host.scan", json!({ "path": "/x" }));
        assert_eq!(receivers, 1);
        let event = timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("no event")
            .expect("bus closed");
        assert_eq!(event.topic, "host.scan");
        assert_eq!(event.source, HOST_SOURCE);
        assert_eq!(event.data["path"], "/x");
        orch.shutdown().await;
    }
}
