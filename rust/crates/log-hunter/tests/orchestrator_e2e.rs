//! End-to-end: the orchestrator supervises the real `log-hunter` binary.
//!
//! It lives in this crate because only the owning package gets
//! `CARGO_BIN_EXE_log-hunter`. The orchestrator is a dev-dependency.

use std::path::PathBuf;
use std::time::Duration;

use avscan_manifest::{parse_manifest, HOST_API_VERSION};
use avscan_orchestrator::bus::BusEvent;
use avscan_orchestrator::supervisor::{ModuleSpec, ModuleStatus, Orchestrator, RunOptions};
use serde_json::{json, Map};
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout, Instant};

const WAIT: Duration = Duration::from_secs(20);
const MODULE_ID: &str = "log_hunter";
const LOG_LINE: &str = "Nov 26 14:02:11 host sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n";

fn spec() -> ModuleSpec {
    let text = include_str!("../../../modules/log_hunter/module.json");
    let manifest = parse_manifest(text, HOST_API_VERSION).unwrap();
    let mut config_override = Map::new();
    config_override.insert("paths".to_string(), json!([]));
    ModuleSpec {
        manifest,
        binary: PathBuf::from(env!("CARGO_BIN_EXE_log-hunter")),
        extra_args: Vec::new(),
        config_override,
    }
}

async fn wait_for(orch: &Orchestrator, want: ModuleStatus) {
    let deadline = Instant::now() + WAIT;
    loop {
        let current = orch
            .statuses()
            .into_iter()
            .find(|(id, _)| id == MODULE_ID)
            .map(|(_, status)| status);
        if current.as_ref() == Some(&want) {
            return;
        }
        let in_time = Instant::now() < deadline;
        assert!(in_time, "waiting for {want:?}, last status {current:?}");
        sleep(Duration::from_millis(50)).await;
    }
}

async fn next_log_event(events: &mut broadcast::Receiver<BusEvent>) -> BusEvent {
    loop {
        let event = events.recv().await.expect("event bus closed");
        if event.topic == "log_hunter.log" {
            return event;
        }
    }
}

#[tokio::test]
async fn orchestrator_drives_the_real_module() {
    let dir = std::env::temp_dir().join(format!("avscan-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("auth.log");
    std::fs::write(&log, LOG_LINE).unwrap();

    let mut orch = Orchestrator::start(vec![spec()], RunOptions::default());
    let mut events = orch.subscribe();
    wait_for(&orch, ModuleStatus::Running).await;

    let mut args = Map::new();
    args.insert("paths".to_string(), json!([log.to_str().unwrap()]));
    let outcome = orch
        .command(MODULE_ID, "log.hunt".to_string(), args)
        .unwrap();
    let result = timeout(WAIT, outcome)
        .await
        .expect("module did not answer")
        .expect("module ended before answering");
    assert!(result.ok, "command failed: {:?}", result.error);

    let event = timeout(WAIT, next_log_event(&mut events))
        .await
        .expect("no log event");
    assert_eq!(event.source, MODULE_ID);
    assert_eq!(event.data["message"], "analysis finished");

    let rejected = orch
        .command(MODULE_ID, "evil".to_string(), Map::new())
        .unwrap();
    let rejected = timeout(WAIT, rejected)
        .await
        .expect("no answer to the rejected command")
        .expect("module ended before answering");
    assert!(!rejected.ok);

    orch.stop_module(MODULE_ID).unwrap();
    wait_for(&orch, ModuleStatus::Stopped).await;
    orch.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
