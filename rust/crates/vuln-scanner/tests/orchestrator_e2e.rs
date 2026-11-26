//! End-to-end: the orchestrator supervises the real `vuln-scanner` binary.

use std::path::{Path, PathBuf};
use std::time::Duration;

use avscan_manifest::{parse_manifest, HOST_API_VERSION};
use avscan_orchestrator::bus::BusEvent;
use avscan_orchestrator::supervisor::{ModuleSpec, ModuleStatus, Orchestrator, RunOptions};
use serde_json::{json, Map};
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout, Instant};

const WAIT: Duration = Duration::from_secs(20);
const MODULE_ID: &str = "vuln_scanner";
const REPORT_TOPIC: &str = "vuln_scanner.report";

fn spec(root: &Path) -> ModuleSpec {
    let text = include_str!("../../../modules/vuln_scanner/module.json");
    let manifest = parse_manifest(text, HOST_API_VERSION).unwrap();
    let mut config_override = Map::new();
    config_override.insert("paths".to_string(), json!([]));
    config_override.insert("command_roots".to_string(), json!([root.to_str().unwrap()]));
    ModuleSpec {
        manifest,
        binary: PathBuf::from(env!("CARGO_BIN_EXE_vuln-scanner")),
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

async fn next_report(events: &mut broadcast::Receiver<BusEvent>) -> BusEvent {
    loop {
        let event = events.recv().await.expect("event bus closed");
        if event.topic == REPORT_TOPIC {
            return event;
        }
    }
}

#[tokio::test]
async fn orchestrator_drives_the_real_scanner() {
    let dir = std::env::temp_dir().join(format!("avscan-e2e-vuln-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Dockerfile"), "FROM ubuntu:16.04\nUSER app\n").unwrap();
    let target = dir.to_str().unwrap();

    let mut orch = Orchestrator::start(vec![spec(&dir)], RunOptions::default());
    let mut events = orch.subscribe();
    wait_for(&orch, ModuleStatus::Running).await;

    let mut args = Map::new();
    args.insert("paths".to_string(), json!([target]));
    let outcome = orch
        .command(MODULE_ID, "vuln.scan_files".to_string(), args)
        .unwrap();
    let result = timeout(WAIT, outcome)
        .await
        .expect("module did not answer")
        .expect("module ended before answering");
    assert!(result.ok, "command failed: {:?}", result.error);
    let report = timeout(WAIT, next_report(&mut events))
        .await
        .expect("no report for the command");
    assert_eq!(report.source, MODULE_ID);
    assert_eq!(report.data["scanned_files"], 1);

    let received = orch.publish("vuln_scanner.scan", json!({ "paths": [target] }));
    assert!(received >= 1);
    let report = timeout(WAIT, next_report(&mut events))
        .await
        .expect("no report for the host event");
    assert_eq!(report.data["scanned_files"], 1);

    let mut outside = Map::new();
    outside.insert("paths".to_string(), json!(["Cargo.toml"]));
    let refused = orch
        .command(MODULE_ID, "vuln.scan_files".to_string(), outside)
        .unwrap();
    let refused = timeout(WAIT, refused)
        .await
        .expect("no answer to the refused command")
        .expect("module ended before answering");
    assert!(!refused.ok);

    orch.stop_module(MODULE_ID).unwrap();
    wait_for(&orch, ModuleStatus::Stopped).await;
    orch.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
