//! Modules driven by an external host over a named pipe (Windows only).
//!
//! A module listed under `pipes` in the configuration is not supervised by
//! the `Orchestrator`: there is no handshake, no HTTP command, no bus
//! forwarding and no entry in `GET /modules`. The orchestrator creates the
//! pipe, spawns the process, waits for the host to connect and relays bytes
//! between the pipe and the module's stdio. The host speaks the protocol with
//! the module itself. The restart policy of the manifest still applies when
//! the module or the pipe fails; a module that exits successfully after the
//! host has gone stays stopped.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use avscan_manifest::RestartPolicy;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::supervisor::{ModuleSpec, RunOptions};

/// A module together with the pipe its host connects to.
#[derive(Debug, Clone)]
pub struct HostedModule {
    pub spec: ModuleSpec,
    pub pipe: String,
}

/// Splits the specs into hosted modules (listed in `pipes`) and the rest.
/// A pipe set for an unknown or disabled module is an error.
pub fn split_hosted(
    specs: Vec<ModuleSpec>,
    pipes: &BTreeMap<String, String>,
) -> Result<(Vec<HostedModule>, Vec<ModuleSpec>)> {
    let known = |id: &String| specs.iter().any(|spec| spec.manifest.id == *id);
    if let Some(id) = pipes.keys().find(|id| !known(id)) {
        bail!("a pipe is set for module '{id}', which is unknown or disabled");
    }
    let mut hosted = Vec::new();
    let mut plain = Vec::new();
    for spec in specs {
        match pipes.get(&spec.manifest.id) {
            Some(pipe) => hosted.push(HostedModule {
                pipe: pipe.clone(),
                spec,
            }),
            None => plain.push(spec),
        }
    }
    Ok((hosted, plain))
}

#[cfg_attr(not(windows), allow(dead_code))]
enum Outcome {
    Shutdown,
    Failed(String),
}

#[cfg(windows)]
mod platform {
    use std::process::Stdio;

    use tokio::process::{Child, Command};
    use tokio::sync::watch;
    use tracing::info;

    use super::{HostedModule, Outcome};
    use crate::pipe;
    use crate::supervisor::RunOptions;

    fn spawn(module: &HostedModule) -> std::io::Result<Child> {
        let spec = &module.spec;
        Command::new(&spec.binary)
            .args(&spec.manifest.args)
            .args(&spec.extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
    }

    /// One launch: create the pipe, spawn, wait for the host, relay.
    pub(super) async fn run_once(
        module: &HostedModule,
        stop: &mut watch::Receiver<bool>,
        opts: &RunOptions,
    ) -> Outcome {
        let name = module.pipe.as_str();
        let server = match pipe::windows::create(name) {
            Ok(server) => server,
            Err(e) => return Outcome::Failed(format!("cannot create pipe {name}: {e}")),
        };
        let mut child = match spawn(module) {
            Ok(child) => child,
            Err(e) => {
                let binary = module.spec.binary.display();
                return Outcome::Failed(format!("cannot spawn {binary}: {e}"));
            }
        };
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill().await;
            return Outcome::Failed("child stdio is not piped".to_string());
        };
        let connected = tokio::select! {
            result = server.connect() => Some(result),
            _ = stop.changed() => None,
            exit = child.wait() => {
                return Outcome::Failed(format!("module exited before the host connected: {exit:?}"));
            }
        };
        match connected {
            None => {
                let _ = child.kill().await;
                return Outcome::Shutdown;
            }
            Some(Err(e)) => {
                let _ = child.kill().await;
                return Outcome::Failed(format!("pipe {name} failed: {e}"));
            }
            Some(Ok(())) => {}
        }
        info!(module = %module.spec.manifest.id, pipe = name, "host connected");
        let relayed = tokio::select! {
            result = pipe::relay(server, stdout, stdin) => Some(result),
            _ = stop.changed() => None,
        };
        let Some(relayed) = relayed else {
            let _ = child.kill().await;
            return Outcome::Shutdown;
        };
        if let Err(e) = relayed {
            let _ = child.kill().await;
            return Outcome::Failed(format!("pipe relay failed: {e}"));
        }
        match tokio::time::timeout(opts.timeouts.stop, child.wait()).await {
            Ok(Ok(code)) if code.success() => Outcome::Shutdown,
            Ok(Ok(code)) => Outcome::Failed(format!("module exited with {code}")),
            Ok(Err(e)) => Outcome::Failed(format!("waiting for the module failed: {e}")),
            Err(_) => {
                let _ = child.kill().await;
                Outcome::Failed("module did not exit after the host disconnected".to_string())
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use tokio::sync::watch;

    use super::{HostedModule, Outcome};
    use crate::supervisor::RunOptions;

    pub(super) async fn run_once(
        module: &HostedModule,
        _stop: &mut watch::Receiver<bool>,
        _opts: &RunOptions,
    ) -> Outcome {
        let name = &module.pipe;
        Outcome::Failed(format!("named pipe {name} is not supported on this platform"))
    }
}

/// Supervises one hosted module until shutdown or until it fails for good.
async fn run_hosted(module: HostedModule, mut stop: watch::Receiver<bool>, opts: RunOptions) {
    let id = module.spec.manifest.id.clone();
    let mut restarts: u32 = 0;
    loop {
        if *stop.borrow() {
            return;
        }
        match platform::run_once(&module, &mut stop, &opts).await {
            Outcome::Shutdown => {
                info!(module = %id, "hosted module stopped");
                return;
            }
            Outcome::Failed(reason) => {
                let manifest = &module.spec.manifest;
                let allowed = manifest.restart_policy == RestartPolicy::OnFailure;
                if !allowed || restarts >= manifest.max_restarts {
                    error!(module = %id, %reason, "hosted module failed permanently");
                    return;
                }
                restarts += 1;
                warn!(module = %id, %reason, attempt = restarts, "hosted module failed, restarting");
                let delay = opts.backoff.delay(restarts - 1);
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = stop.changed() => {}
                }
            }
        }
    }
}

/// Owns the tasks of all hosted modules.
pub struct HostedRunner {
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl HostedRunner {
    /// Starts one task per hosted module.
    pub fn start(modules: Vec<HostedModule>, opts: RunOptions) -> Self {
        let (stop, stop_rx) = watch::channel(false);
        let tasks = modules
            .into_iter()
            .map(|module| tokio::spawn(run_hosted(module, stop_rx.clone(), opts)))
            .collect();
        Self { stop, tasks }
    }

    /// Stops every hosted module (its process is killed) and waits for the tasks.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use avscan_manifest::{parse_manifest, HOST_API_VERSION};
    use serde_json::Map;

    fn spec(id: &str) -> ModuleSpec {
        let text = format!(
            r#"{{"id":"{id}","name":"Mod","version":"0.1.0","api_version":1,"entry":{{"exe":"x"}}}}"#
        );
        ModuleSpec {
            manifest: parse_manifest(&text, HOST_API_VERSION).unwrap(),
            binary: PathBuf::from("x"),
            extra_args: Vec::new(),
            config_override: Map::new(),
        }
    }

    fn ids(specs: &[ModuleSpec]) -> Vec<String> {
        specs.iter().map(|s| s.manifest.id.clone()).collect()
    }

    #[test]
    fn only_listed_modules_become_hosted() {
        let pipes = BTreeMap::from([("mod_b".to_string(), "pipe-b".to_string())]);
        let (hosted, plain) = split_hosted(vec![spec("mod_a"), spec("mod_b")], &pipes).unwrap();
        assert_eq!(hosted.len(), 1);
        assert_eq!(hosted[0].spec.manifest.id, "mod_b");
        assert_eq!(hosted[0].pipe, "pipe-b");
        assert_eq!(ids(&plain), ["mod_a"]);
    }

    #[test]
    fn no_pipes_leave_every_module_plain() {
        let (hosted, plain) = split_hosted(vec![spec("mod_a")], &BTreeMap::new()).unwrap();
        assert!(hosted.is_empty());
        assert_eq!(ids(&plain), ["mod_a"]);
    }

    #[test]
    fn a_pipe_for_an_unknown_module_is_an_error() {
        let pipes = BTreeMap::from([("ghost".to_string(), "pipe-g".to_string())]);
        let error = split_hosted(vec![spec("mod_a")], &pipes).err().unwrap();
        assert!(error.to_string().contains("ghost"), "{error}");
    }

    #[tokio::test]
    async fn the_runner_starts_and_stops_without_modules() {
        let runner = HostedRunner::start(Vec::new(), RunOptions::default());
        runner.shutdown().await;
    }
}
