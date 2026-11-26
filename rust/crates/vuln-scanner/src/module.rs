//! AVScan module runtime: speaks the module protocol over stdin/stdout.
//!
//! Flow (mirrors `libs/host/module_host.hpp`): the host sends `hello`, the
//! module answers `hello_ack`; the host sends `start` with the config, the module
//! answers `started`. Then `ping` is answered with `pong`, an `event` on
//! `vuln_scanner.scan` triggers a scan, and `stop` ends the session.
//! Only protocol frames may be written to the output; diagnostics go to stderr.
//!
//! Command `vuln.scan_files` (args: `paths`) scans the paths, publishes the
//! report as `vuln_scanner.report` and answers `command_result`. Every path is
//! resolved (symlinks included) and must lie inside one of the `command_roots`.
//! Without `command_roots` the configured `paths` are the roots; with neither,
//! the command is refused. Scans run on the protocol thread, so a large tree
//! delays `ping` answers until it is done.

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
const SCAN_COMMAND: &str = "vuln.scan_files";
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
    /// Directories or files the `vuln.scan_files` command may read.
    pub command_roots: Vec<PathBuf>,
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

/// Explicit `command_roots`, or else the configured scan paths.
fn command_roots_from(value: Option<&Value>, paths: &[PathBuf]) -> Vec<PathBuf> {
    let configured = paths_from(value);
    if configured.is_empty() {
        paths.to_vec()
    } else {
        configured
    }
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
        let paths = paths_from(config.get("paths"));
        let command_roots = command_roots_from(config.get("command_roots"), &paths);
        Self {
            paths,
            command_roots,
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
    Ok(reply(
        "event",
        json!({ "topic": REPORT_TOPIC, "data": data }),
    ))
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

fn command_result(request: &Message, ok: bool, error: Option<&str>) -> Message {
    let mut payload = json!({ "ok": ok });
    if let Some(text) = error {
        payload["error"] = json!(text);
    }
    let mut result = reply("command_result", payload);
    result.id = request.id.clone();
    result
}

/// Resolves every path (following symlinks) and requires it to lie inside one
/// of the roots. Returns the resolved paths or a message for the requester.
fn check_paths(paths: &[PathBuf], roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    if roots.is_empty() {
        return Err("no usable command_roots are configured".to_string());
    }
    let mut checked = Vec::new();
    for path in paths {
        let real = std::fs::canonicalize(path)
            .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
        if !roots.iter().any(|root| real.starts_with(root)) {
            return Err(format!("{} is outside command_roots", path.display()));
        }
        checked.push(real);
    }
    Ok(checked)
}

/// Answers one `command`. Unknown commands and bad arguments are reported in
/// the result (`ok: false`); they do not end the session.
fn handle_command<R: Read, W: Write>(
    ch: &mut Channel<R, W>,
    request: &Message,
    config: &ModuleConfig,
) -> Result<(), ModuleError> {
    let name = request
        .payload
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("");
    if name != SCAN_COMMAND {
        let text = format!("unsupported command '{name}'");
        return ch.send(&command_result(request, false, Some(text.as_str())));
    }
    let args = request.payload.get("args");
    let requested = paths_from(args.and_then(|a| a.get("paths")));
    if requested.is_empty() {
        let text = "args.paths must list at least one path";
        return ch.send(&command_result(request, false, Some(text)));
    }
    let paths = match check_paths(&requested, &config.command_roots) {
        Ok(paths) => paths,
        Err(text) => {
            return ch.send(&command_result(request, false, Some(text.as_str())));
        }
    };
    publish_scan(ch, &paths, &config.options)?;
    ch.send(&command_result(request, true, None))
}

/// Runs one module session until `stop` or until the host closes the input.
pub fn run<R: Read, W: Write>(input: R, output: W) -> Result<(), ModuleError> {
    let mut ch = Channel::new(input, output);

    let Some(hello) = ch.recv()? else {
        return Ok(());
    };
    let host_api = hello.payload.get("host_api").and_then(Value::as_i64);
    if hello.msg_type != "hello" || host_api != Some(HOST_API) {
        return Err(ModuleError::Handshake(
            "expected hello with host_api 1".to_string(),
        ));
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
            "command" => handle_command(&mut ch, &msg, &config)?,
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

    fn command_msg(id: &str, name: &str, args: Value) -> Message {
        let msg = host_msg("command", json!({ "name": name, "args": args }));
        msg.with_id(id)
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

    /// Handshake with `config`, one `vuln.scan_files` command and stop.
    fn scan_session(config: Value, paths: Value) -> Vec<Message> {
        let mut messages = handshake(config);
        let args = json!({ "paths": paths });
        messages.push(command_msg("cmd-1", SCAN_COMMAND, args));
        messages.push(host_msg("stop", json!({})));
        run_session(messages).unwrap()
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
        assert!(replies
            .iter()
            .all(|m| m.module.as_deref() == Some(MODULE_ID)));
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
        assert_eq!(
            replies[0].payload["module_version"],
            manifest.version.as_str()
        );
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
    fn scan_command_publishes_a_report_and_answers() {
        let dir = TempDir::new("module_command");
        dir.write("Dockerfile", "FROM ubuntu:16.04\nUSER app\n");
        let root = dir.path().to_str().unwrap().to_string();
        let config = json!({ "command_roots": [root] });
        let replies = scan_session(config, json!([dir.path().to_str().unwrap()]));
        let types: Vec<&str> = replies.iter().map(|m| m.msg_type.as_str()).collect();
        assert_eq!(
            types,
            ["hello_ack", "started", "event", "command_result", "stopped"]
        );
        assert_eq!(replies[2].payload["topic"], REPORT_TOPIC);
        let report = &replies[2].payload["data"];
        assert_eq!(report["findings"][0]["rule"], "docker-eol-image");
        assert_eq!(replies[3].id.as_deref(), Some("cmd-1"));
        assert_eq!(replies[3].payload["ok"], json!(true));
    }

    #[test]
    fn scan_command_refuses_paths_outside_the_roots() {
        let allowed = TempDir::new("module_roots_allowed");
        let other = TempDir::new("module_roots_other");
        other.write("Dockerfile", "FROM ubuntu:16.04\n");
        let root = allowed.path().to_str().unwrap().to_string();
        let config = json!({ "command_roots": [root] });
        let replies = scan_session(config, json!([other.path().to_str().unwrap()]));
        let types: Vec<&str> = replies.iter().map(|m| m.msg_type.as_str()).collect();
        assert_eq!(types, ["hello_ack", "started", "command_result", "stopped"]);
        assert_eq!(replies[2].payload["ok"], json!(false));
        let error = replies[2].payload["error"].as_str().unwrap();
        assert!(error.contains("outside command_roots"));
    }

    #[test]
    fn scan_command_needs_configured_roots() {
        let dir = TempDir::new("module_no_roots");
        dir.write("Dockerfile", "FROM ubuntu:16.04\n");
        let replies = scan_session(json!({}), json!([dir.path().to_str().unwrap()]));
        assert_eq!(replies[2].msg_type, "command_result");
        assert_eq!(replies[2].payload["ok"], json!(false));
        let error = replies[2].payload["error"].as_str().unwrap();
        assert!(error.contains("command_roots"));
    }

    #[test]
    fn bad_commands_get_error_results() {
        let mut messages = handshake(json!({}));
        messages.push(command_msg("cmd-1", "evil", json!({})));
        messages.push(command_msg("cmd-2", SCAN_COMMAND, json!({})));
        messages.push(host_msg("stop", json!({})));
        let replies = run_session(messages).unwrap();
        let types: Vec<&str> = replies.iter().map(|m| m.msg_type.as_str()).collect();
        assert_eq!(
            types,
            [
                "hello_ack",
                "started",
                "command_result",
                "command_result",
                "stopped"
            ]
        );
        assert_eq!(replies[2].id.as_deref(), Some("cmd-1"));
        assert_eq!(replies[2].payload["ok"], json!(false));
        let unsupported = replies[2].payload["error"].as_str().unwrap();
        assert!(unsupported.contains("unsupported"));
        assert_eq!(replies[3].id.as_deref(), Some("cmd-2"));
        assert_eq!(replies[3].payload["ok"], json!(false));
    }

    #[test]
    fn command_roots_default_to_the_configured_paths() {
        let paths = [PathBuf::from("project")];
        let roots = command_roots_from(None, &paths);
        assert_eq!(roots, [PathBuf::from("project")]);
        let explicit = json!(["/srv/code"]);
        let roots = command_roots_from(Some(&explicit), &paths);
        assert_eq!(roots, [PathBuf::from("/srv/code")]);
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
        assert!(matches!(
            run_session(wrong_type),
            Err(ModuleError::Handshake(_))
        ));
    }

    #[test]
    fn closed_input_ends_the_session_cleanly() {
        assert!(run_session(Vec::new()).unwrap().is_empty());
        let replies = run_session(handshake(json!({}))).unwrap();
        assert_eq!(replies.len(), 2);
    }

    #[test]
    fn config_keys_override_defaults() {
        let value =
            json!({ "max_depth": 2, "max_file_kb": 4, "max_findings": 7, "paths": ["a", 1] });
        let config = ModuleConfig::from_value(&value);
        assert_eq!(config.options.max_depth, 2);
        assert_eq!(config.options.max_file_bytes, 4096);
        assert_eq!(config.options.max_findings, 7);
        assert_eq!(config.paths, vec![PathBuf::from("a")]);
        assert_eq!(config.command_roots, vec![PathBuf::from("a")]);
        assert!(ModuleConfig::from_value(&Value::Null).paths.is_empty());
    }
}
