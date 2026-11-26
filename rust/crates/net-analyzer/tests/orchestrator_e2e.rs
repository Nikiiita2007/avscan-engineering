//! End-to-end: the orchestrator supervises the real `net-analyzer` binary.

use std::path::{Path, PathBuf};
use std::time::Duration;

use avscan_manifest::{parse_manifest, HOST_API_VERSION};
use avscan_orchestrator::bus::BusEvent;
use avscan_orchestrator::supervisor::{ModuleSpec, ModuleStatus, Orchestrator, RunOptions};
use serde_json::{json, Map};
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout, Instant};

const WAIT: Duration = Duration::from_secs(20);
const MODULE_ID: &str = "net_analyzer";
const LOG_TOPIC: &str = "net_analyzer.log";

fn spec(root: &Path) -> ModuleSpec {
    let text = include_str!("../../../../modules/net_analyzer/module.json");
    let manifest = parse_manifest(text, HOST_API_VERSION).unwrap();
    let mut config_override = Map::new();
    config_override.insert("pcap_paths".to_string(), json!([]));
    config_override.insert("command_roots".to_string(), json!([root.to_str().unwrap()]));
    ModuleSpec {
        manifest,
        binary: PathBuf::from(env!("CARGO_BIN_EXE_net-analyzer")),
        extra_args: Vec::new(),
        config_override,
    }
}

/// A classic little-endian libpcap file without any packets.
fn empty_pcap() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&65_535u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes
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
        if event.topic == LOG_TOPIC {
            return event;
        }
    }
}

#[tokio::test]
async fn orchestrator_drives_the_real_analyzer() {
    let dir = std::env::temp_dir().join(format!("avscan-e2e-net-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let capture = dir.join("empty.pcap");
    std::fs::write(&capture, empty_pcap()).unwrap();

    let mut orch = Orchestrator::start(vec![spec(&dir)], RunOptions::default());
    let mut events = orch.subscribe();
    wait_for(&orch, ModuleStatus::Running).await;

    let mut args = Map::new();
    args.insert("pcap_paths".to_string(), json!([capture.to_str().unwrap()]));
    let outcome = orch
        .command(MODULE_ID, "net.analyze".to_string(), args)
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
    assert!(event.data["message"].is_string());

    let mut outside = Map::new();
    outside.insert("pcap_paths".to_string(), json!(["Cargo.toml"]));
    let refused = orch
        .command(MODULE_ID, "net.analyze".to_string(), outside)
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
