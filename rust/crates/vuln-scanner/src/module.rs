//! AVScan module runtime: speaks the module protocol over stdin/stdout.
//!
//! Flow (mirrors `libs/host/module_host.hpp`): the host sends `hello`, the
//! module answers `hello_ack`; the host sends `start` with the config, the module
//! answers `started`. Then `ping` is answered with `pong`, an `event` on
//! `vuln_scanner.scan` triggers a scan, and `stop` ends the session.
//! Only protocol frames may be written to the output; diagnostics go to stderr.

use std::io::{Read, Write};
use std::path::PathBuf;

use avscan_protocol::{encode_frame, FrameReader, Message, ProtocolError};
use serde_json::{json, Value};
use thiserror::Error;

use crate::scan::{scan_paths, ScanOptions};

pub const MODULE_ID: &str = "vuln_scanner";
pub const SCAN_TOPIC: &str = "vuln_scanner.scan";
pub const REPORT_TOPIC: &str = "vuln_scanner.report";
pub const CAPABILITIES: [&str; 2] = ["vuln.scan_files", "report.mask_sensitive"];
const HOST_API: i64 = 1;

/// Errors that end a module session.
#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("report serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Handshake(String),
}

/// Module configuration taken from the `start` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleConfig {
    pub paths: Vec<PathBuf>,
    pub options: ScanOptions,
}

fn paths_from(value: Option<&Value>) -> Vec<PathBuf> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    for item in items {
        if let Some(path) = item.as_str() {
            paths.push(PathBuf::from(path));
        }
    }
    paths
}

impl ModuleConfig {
    pub fn from_value(config: &Value) -> Self {
        let mut options = ScanOptions::default();
        if let Some(n) = config.get("max_depth").and_then(Value::as_u64) {
            options.max_depth = n as usize;
        }
        if let Some(kb) = config.get("max_file_kb").and_then(Value::as_u64) {
            options.max_file_bytes = kb.saturating_mul(1024);
        }
        if let Some(n) = config.get("max_findings").and_then(Value::as_u64) {
            options.max_findings = n as usize;
        }
        Self {
            paths: paths_from(config.get("paths")),
            options,
        }
    }
}

fn reply(msg_type: &str, payload: Value) -> Message {
    Message::new(msg_type)
        .with_module(MODULE_ID)
        .with_payload(payload)
}

struct Channel<R, W> {
    input: R,
    output: W,
    frames: FrameReader,
}

impl<R: Read, W: Write> Channel<R, W> {
    fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            frames: FrameReader::new(),
        }
    }

    /// Next message, or `None` when the host closed the input.
    fn recv(&mut self) -> Result<Option<Message>, ModuleError> {
        let mut buf = [0u8; 4096];
        loop {
            if let Some(msg) = self.frames.next_message()? {
                return Ok(Some(msg));
            }
            let n = self.input.read(&mut buf)?;
            if n == 0 {
                return Ok(None);
            }
            self.frames.feed(&buf[..n]);
        }
    }

    fn send(&mut self, msg: &Message) -> Result<(), ModuleError> {
        let frame = encode_frame(msg)?;
        self.output.write_all(&frame)?;
        self.output.flush()?;
        Ok(())
    }
}

fn report_event(report: &crate::report::Report) -> Result<Message, ModuleError> {
    let data = serde_json::to_value(report)?;
    Ok(reply("event", json!({ "topic": REPORT_TOPIC, "data": data })))
}

fn publish_scan<R: Read, W: Write>(
    ch: &mut Channel<R, W>,
    paths: &[PathBuf],
    options: &ScanOptions,
) -> Result<(), ModuleError> {
    let mut report = scan_paths(paths, options);
    let event = report_event(&report)?;
    match ch.send(&event) {
        Err(ModuleError::Protocol(ProtocolError::FrameTooLarge)) => {
            report.findings.clear();
            report.truncated = true;
            let event = report_event(&report)?;
            ch.send(&event)
        }
        other => other,
    }
}

fn handle_event<R: Read, W: Write>(
    ch: &mut Channel<R, W>,
    msg: &Message,
    options: &ScanOptions,
) -> Result<(), ModuleError> {
    let topic = msg.payload.get("topic").and_then(Value::as_str);
    if topic != Some(SCAN_TOPIC) {
        return Ok(());
    }
    let data = msg.payload.get("data");
    let paths = paths_from(data.and_then(|d| d.get("paths")));
    if paths.is_empty() {
        let note = json!({ "message": "scan request without paths ignored" });
        return ch.send(&reply("log", note));
    }
    publish_scan(ch, &paths, options)
}

/// Runs one module session until `stop` or until the host closes the input.
pub fn run<R: Read, W: Write>(input: R, output: W) -> Result<(), ModuleError> {
    let mut ch = Channel::new(input, output);

    let Some(hello) = ch.recv()? else {
        return Ok(());
    };
    let host_api = hello.payload.get("host_api").and_then(Value::as_i64);
    if hello.msg_type != "hello" || host_api != Some(HOST_API) {
        return Err(ModuleError::Handshake("expected hello with host_api 1".to_string()));
    }
    let ack = json!({
        "api_version": HOST_API,
        "module_version": env!("CARGO_PKG_VERSION"),
        "capabilities": CAPABILITIES,
    });
    ch.send(&reply("hello_ack", ack))?;

    let Some(start) = ch.recv()? else {
        return Ok(());
    };
    if start.msg_type != "start" {
        return Err(ModuleError::Handshake("expected start".to_string()));
    }
    let config_value = start.payload.get("config").cloned().unwrap_or(Value::Null);
    let config = ModuleConfig::from_value(&config_value);
    ch.send(&reply("started", json!({})))?;
    if !config.paths.is_empty() {
        publish_scan(&mut ch, &config.paths, &config.options)?;
    }

    while let Some(msg) = ch.recv()? {
        match msg.msg_type.as_str() {
            "ping" => {
                let mut pong = reply("pong", json!({}));
                pong.id = msg.id.clone();
                ch.send(&pong)?;
            }
            "stop" => {
                ch.send(&reply("stopped", json!({})))?;
                return Ok(());
            }
            "event" => handle_event(&mut ch, &msg, &config.options)?,
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    use avscan_manifest::{parse_manifest, HOST_API_VERSION};

    fn host_msg(msg_type: &str, payload: Value) -> Message {
        reply(msg_type, payload)
    }

    fn frames(messages: Vec<Message>) -> Vec<u8> {
        let mut bytes = Vec::new();
        for msg in messages {
            bytes.extend(encode_frame(&msg).unwrap());
        }
        bytes
    }

    fn decode_all(bytes: &[u8]) -> Vec<Message> {
        let mut reader = FrameReader::new();
        reader.feed(bytes);
        let mut out = Vec::new();
        while let Some(msg) = reader.next_message().unwrap() {
            out.push(msg);
        }
        out
    }

    fn run_session(messages: Vec<Message>) -> Result<Vec<Message>, ModuleError> {
        let input = frames(messages);
        let mut output = Vec::new();
        run(input.as_slice(), &mut output)?;
        Ok(decode_all(&output))
    }

    fn handshake(start_config: Value) -> Vec<Message> {
        vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": start_config })),
        ]
    }

    #[test]
    fn handshake_ping_and_stop() {
        let mut messages = handshake(json!({}));
        messages.push(host_msg("ping", json!({})).with_id("ping-1"));
        messages.push(host_msg("stop", json!({})));
        let replies = run_session(messages).unwrap();
        let types: Vec<&str> = replies.iter().map(|m| m.msg_type.as_str()).collect();
        assert_eq!(types, ["hello_ack", "started", "pong", "stopped"]);
        assert_eq!(replies[2].id.as_deref(), Some("ping-1"));
        assert!(replies.iter().all(|m| m.module.as_deref() == Some(MODULE_ID)));
    }

    #[test]
    fn hello_ack_matches_the_manifest() {
        let text = include_str!("../../../modules/vuln_scanner/module.json");
        let manifest = parse_manifest(text, HOST_API_VERSION).unwrap();
        assert_eq!(manifest.id, MODULE_ID);
        assert_eq!(manifest.version, env!("CARGO_PKG_VERSION"));
        for capability in CAPABILITIES {
            assert!(manifest.capabilities.iter().any(|c| c == capability));
        }
        assert!(manifest.publishes.iter().any(|t| t == REPORT_TOPIC));
        assert!(manifest.subscribes.iter().any(|t| t == SCAN_TOPIC));
        let replies = run_session(handshake(json!({}))).unwrap();
        assert_eq!(replies[0].payload["module_version"], manifest.version.as_str());
        assert_eq!(replies[0].payload["api_version"], manifest.api_version);
    }

    #[test]
    fn scans_paths_from_the_start_config() {
        let dir = TempDir::new("module_start");
        dir.write("Dockerfile", "FROM ubuntu:latest\nUSER app\n");
        let config = json!({ "paths": [dir.path().to_str().unwrap()] });
        let replies = run_session(handshake(config)).unwrap();
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[2].msg_type, "event");
        assert_eq!(replies[2].payload["topic"], REPORT_TOPIC);
        assert_eq!(replies[2].payload["data"]["scanned_files"], 1);
    }

    #[test]
    fn scan_event_triggers_a_report() {
        let dir = TempDir::new("module_event");
        dir.write("Dockerfile", "FROM ubuntu:16.04\nUSER app\n");
        let paths = json!([dir.path().to_str().unwrap()]);
        let trigger = json!({ "topic": SCAN_TOPIC, "data": { "paths": paths } });
        let mut messages = handshake(json!({}));
        messages.push(host_msg("event", trigger));
        messages.push(host_msg("stop", json!({})));
        let replies = run_session(messages).unwrap();
        let report = &replies[2].payload["data"];
        assert_eq!(report["findings"][0]["rule"], "docker-eol-image");
        assert_eq!(report["findings"][0]["severity"], "high");
        assert_eq!(replies[3].msg_type, "stopped");
    }

    #[test]
    fn scan_request_without_paths_is_logged_not_fatal() {
        let trigger = json!({ "topic": SCAN_TOPIC, "data": {} });
        let mut messages = handshake(json!({}));
        messages.push(host_msg("event", trigger));
        messages.push(host_msg("stop", json!({})));
        let replies = run_session(messages).unwrap();
        assert_eq!(replies[2].msg_type, "log");
        assert_eq!(replies[3].msg_type, "stopped");
    }

    #[test]
    fn unrelated_events_are_ignored() {
        let other = json!({ "topic": "host.shutdown", "data": {} });
        let mut messages = handshake(json!({}));
        messages.push(host_msg("event", other));
        messages.push(host_msg("stop", json!({})));
        let replies = run_session(messages).unwrap();
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[2].msg_type, "stopped");
    }

    #[test]
    fn rejects_a_bad_hello() {
        let bad = vec![host_msg("hello", json!({ "host_api": 2 }))];
        assert!(matches!(run_session(bad), Err(ModuleError::Handshake(_))));
        let wrong_type = vec![host_msg("start", json!({}))];
        assert!(matches!(run_session(wrong_type), Err(ModuleError::Handshake(_))));
    }

    #[test]
    fn closed_input_ends_the_session_cleanly() {
        assert!(run_session(Vec::new()).unwrap().is_empty());
        let replies = run_session(handshake(json!({}))).unwrap();
        assert_eq!(replies.len(), 2);
    }

    #[test]
    fn config_keys_override_defaults() {
        let value = json!({ "max_depth": 2, "max_file_kb": 4, "max_findings": 7, "paths": ["a", 1] });
        let config = ModuleConfig::from_value(&value);
        assert_eq!(config.options.max_depth, 2);
        assert_eq!(config.options.max_file_bytes, 4096);
        assert_eq!(config.options.max_findings, 7);
        assert_eq!(config.paths, vec![PathBuf::from("a")]);
        assert!(ModuleConfig::from_value(&Value::Null).paths.is_empty());
    }
}
