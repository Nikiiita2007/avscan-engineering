//! AVScan module runtime: speaks the module protocol over stdin/stdout.
//!
//! Flow (mirrors `libs/host/module_host.hpp`): `hello` / `hello_ack`, then
//! `start` with the config / `started`. After that the module analyzes the
//! configured log files (once, or continuously with `follow`), answers `ping`
//! and ends on `stop`. Alerts are published as `log_hunter.ioc` events and
//! progress as `log_hunter.log`. Only protocol frames may be written to the
//! output; diagnostics go to stderr.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use avscan_protocol::{encode_frame, FrameReader, Message, ProtocolError};
use serde_json::{json, Value};
use thiserror::Error;

use crate::alert::Alert;
use crate::follow::{emit, AlertSink, Follower, Notify};
use crate::hunter::hunt_reader;
use crate::rules::Rules;

pub const MODULE_ID: &str = "log_hunter";
pub const IOC_TOPIC: &str = "log_hunter.ioc";
pub const LOG_TOPIC: &str = "log_hunter.log";
pub const CAPABILITIES: [&str; 2] = ["log.hunt", "report.mask_sensitive"];
const HOST_API: i64 = 1;

/// Errors that end a module session.
#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("{0}")]
    Handshake(String),
    #[error("invalid module config: {0}")]
    Config(String),
    #[error("output lock poisoned")]
    Poisoned,
}

fn config_error(what: &str, error: &dyn std::fmt::Display) -> ModuleError {
    ModuleError::Config(format!("{what}: {error}"))
}

/// Module configuration taken from the `start` message.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleConfig {
    pub paths: Vec<PathBuf>,
    pub follow: bool,
    pub mask_secrets: bool,
    pub rules: Rules,
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

fn parse_rules(value: Option<&Value>, mask: bool) -> Result<Rules, ModuleError> {
    let mut rules = Rules::default();
    if let Some(v) = value {
        rules = serde_json::from_value(v.clone()).map_err(|e| config_error("rules", &e))?;
    }
    rules.mask_names = mask;
    rules.validate().map_err(ModuleError::Config)?;
    Ok(rules)
}

impl ModuleConfig {
    pub fn from_value(config: &Value) -> Result<Self, ModuleError> {
        let mask_secrets = config
            .get("mask_secrets")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let follow = config
            .get("follow")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(Self {
            paths: paths_from(config.get("paths")),
            follow,
            mask_secrets,
            rules: parse_rules(config.get("rules"), mask_secrets)?,
        })
    }
}

fn reply(msg_type: &str, payload: Value) -> Message {
    Message::new(msg_type)
        .with_module(MODULE_ID)
        .with_payload(payload)
}

/// Shared, thread-safe frame writer (follower threads publish alerts too).
#[derive(Clone)]
struct Out {
    inner: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl Out {
    fn new(output: Box<dyn Write + Send>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(output)),
        }
    }

    fn send(&self, msg: &Message) -> Result<(), ModuleError> {
        let frame = encode_frame(msg)?;
        let mut out = self.inner.lock().map_err(|_| ModuleError::Poisoned)?;
        out.write_all(&frame)?;
        out.flush()?;
        Ok(())
    }

    fn event(&self, topic: &str, data: Value) -> Result<(), ModuleError> {
        self.send(&reply("event", json!({ "topic": topic, "data": data })))
    }
}

fn alert_sink(out: &Out) -> AlertSink {
    let out = out.clone();
    Arc::new(move |alert: &Alert| {
        if let Ok(data) = serde_json::to_value(alert) {
            let _ = out.event(IOC_TOPIC, data);
        }
    })
}

fn notifier(out: &Out) -> Notify {
    let out = out.clone();
    Arc::new(move |text: &str| {
        let _ = out.event(LOG_TOPIC, json!({ "message": text }));
    })
}

fn analyze_file(out: &Out, path: &Path, rules: &Rules, sink: &AlertSink) {
    let file = path.display().to_string();
    let result =
        File::open(path).and_then(|f| hunt_reader(BufReader::new(f), rules, |a| emit(sink, &a)));
    let note = match result {
        Ok(stats) => json!({ "message": "analysis finished", "file": file, "stats": stats }),
        Err(e) => json!({ "message": format!("cannot analyze: {e}"), "file": file }),
    };
    let _ = out.event(LOG_TOPIC, note);
}

fn recv<R: Read>(input: &mut R, frames: &mut FrameReader) -> Result<Option<Message>, ModuleError> {
    let mut buf = [0u8; 4096];
    loop {
        if let Some(msg) = frames.next_message()? {
            return Ok(Some(msg));
        }
        let n = input.read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        frames.feed(&buf[..n]);
    }
}

enum Exit {
    Stop,
    Closed,
}

fn serve<R: Read>(input: &mut R, frames: &mut FrameReader, out: &Out) -> Result<Exit, ModuleError> {
    while let Some(msg) = recv(input, frames)? {
        match msg.msg_type.as_str() {
            "ping" => {
                let mut pong = reply("pong", json!({}));
                pong.id = msg.id.clone();
                out.send(&pong)?;
            }
            "stop" => return Ok(Exit::Stop),
            _ => {}
        }
    }
    Ok(Exit::Closed)
}

/// Runs one module session until `stop` or until the host closes the input.
pub fn run<R: Read>(mut input: R, output: Box<dyn Write + Send>) -> Result<(), ModuleError> {
    let out = Out::new(output);
    let mut frames = FrameReader::new();

    let Some(hello) = recv(&mut input, &mut frames)? else {
        return Ok(());
    };
    let host_api = hello.payload.get("host_api").and_then(Value::as_i64);
    if hello.msg_type != "hello" || host_api != Some(HOST_API) {
        let text = "expected hello with host_api 1";
        return Err(ModuleError::Handshake(text.to_string()));
    }
    let ack = json!({
        "api_version": HOST_API,
        "module_version": env!("CARGO_PKG_VERSION"),
        "capabilities": CAPABILITIES,
    });
    out.send(&reply("hello_ack", ack))?;

    let Some(start) = recv(&mut input, &mut frames)? else {
        return Ok(());
    };
    if start.msg_type != "start" {
        return Err(ModuleError::Handshake("expected start".to_string()));
    }
    let config_value = start.payload.get("config").cloned().unwrap_or(Value::Null);
    let config = match ModuleConfig::from_value(&config_value) {
        Ok(config) => config,
        Err(e) => {
            let _ = out.send(&reply("error", json!({ "message": e.to_string() })));
            return Err(e);
        }
    };
    out.send(&reply("started", json!({})))?;

    let sink = alert_sink(&out);
    let mut followers = Vec::new();
    for path in &config.paths {
        if config.follow {
            let rules = config.rules.clone();
            let follower = Follower::start(path.clone(), rules, Arc::clone(&sink), notifier(&out));
            followers.push(follower);
        } else {
            analyze_file(&out, path, &config.rules, &sink);
        }
    }

    let exit = serve(&mut input, &mut frames, &out);
    drop(followers);
    if matches!(exit?, Exit::Stop) {
        out.send(&reply("stopped", json!({})))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{failed, TempDir};
    use std::collections::VecDeque;
    use std::io;
    use std::thread;
    use std::time::Duration;

    use avscan_manifest::{parse_manifest, HOST_API_VERSION};

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Input that delivers chunks after a delay, so background threads get time to work.
    struct Script {
        chunks: VecDeque<(Duration, Vec<u8>)>,
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some((delay, chunk)) = self.chunks.pop_front() else {
                return Ok(0);
            };
            thread::sleep(delay);
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            if n < chunk.len() {
                self.chunks
                    .push_front((Duration::ZERO, chunk[n..].to_vec()));
            }
            Ok(n)
        }
    }

    fn host_msg(msg_type: &str, payload: Value) -> Message {
        reply(msg_type, payload)
    }

    fn frames_of(messages: Vec<Message>) -> Vec<u8> {
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

    fn run_raw(messages: Vec<Message>) -> (Result<(), ModuleError>, Vec<Message>) {
        let input = frames_of(messages);
        let buf = SharedBuf::default();
        let result = run(input.as_slice(), Box::new(buf.clone()));
        let bytes = buf.0.lock().unwrap().clone();
        (result, decode_all(&bytes))
    }

    fn session(config: Value) -> Vec<Message> {
        let messages = vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": config })),
            host_msg("stop", json!({})),
        ];
        let (result, replies) = run_raw(messages);
        result.unwrap();
        replies
    }

    fn types(replies: &[Message]) -> Vec<&str> {
        replies.iter().map(|m| m.msg_type.as_str()).collect()
    }

    fn log_text(msg: &Message) -> String {
        msg.payload["data"]["message"].as_str().unwrap().to_string()
    }

    fn burst_log(dir: &TempDir) -> PathBuf {
        let text: String = (0..5)
            .map(|s| failed(0, s, "203.0.113.5", "root"))
            .collect();
        dir.write("auth.log", &text);
        dir.path().join("auth.log")
    }

    #[test]
    fn handshake_ping_and_stop() {
        let messages = vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": {} })),
            host_msg("ping", json!({})).with_id("ping-1"),
            host_msg("stop", json!({})),
        ];
        let (result, replies) = run_raw(messages);
        result.unwrap();
        assert_eq!(types(&replies), ["hello_ack", "started", "pong", "stopped"]);
        assert_eq!(replies[2].id.as_deref(), Some("ping-1"));
        assert!(replies
            .iter()
            .all(|m| m.module.as_deref() == Some(MODULE_ID)));
    }

    #[test]
    fn matches_the_manifest() {
        let text = include_str!("../../../modules/log_hunter/module.json");
        let manifest = parse_manifest(text, HOST_API_VERSION).unwrap();
        assert_eq!(manifest.id, MODULE_ID);
        assert_eq!(manifest.version, env!("CARGO_PKG_VERSION"));
        for capability in CAPABILITIES {
            assert!(manifest.capabilities.iter().any(|c| c == capability));
        }
        assert!(manifest.publishes.iter().any(|t| t == IOC_TOPIC));
        assert!(manifest.publishes.iter().any(|t| t == LOG_TOPIC));
        let mut config = manifest.config.clone();
        config.insert("paths".to_string(), json!([]));
        let replies = session(Value::Object(config));
        assert_eq!(types(&replies), ["hello_ack", "started", "stopped"]);
        assert_eq!(replies[0].payload["api_version"], manifest.api_version);
    }

    #[test]
    fn analyzes_log_files_once() {
        let dir = TempDir::new("module_once");
        let path = burst_log(&dir);
        let replies = session(json!({ "paths": [path.to_str().unwrap()] }));
        assert_eq!(
            types(&replies),
            ["hello_ack", "started", "event", "event", "stopped"]
        );
        assert_eq!(replies[2].payload["topic"], IOC_TOPIC);
        assert_eq!(replies[2].payload["data"]["rule"], "ssh-bruteforce");
        assert_eq!(replies[3].payload["topic"], LOG_TOPIC);
        assert_eq!(replies[3].payload["data"]["stats"]["lines"], 5);
    }

    #[test]
    fn missing_files_are_reported_not_fatal() {
        let replies = session(json!({ "paths": ["definitely/missing.log"] }));
        assert_eq!(
            types(&replies),
            ["hello_ack", "started", "event", "stopped"]
        );
        assert!(log_text(&replies[2]).contains("cannot analyze"));
    }

    #[test]
    fn follow_mode_publishes_alerts_from_a_background_thread() {
        let dir = TempDir::new("module_follow");
        let path = burst_log(&dir);
        let config = json!({ "paths": [path.to_str().unwrap()], "follow": true });
        let first = frames_of(vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": config })),
        ]);
        let last = frames_of(vec![host_msg("stop", json!({}))]);
        let mut chunks = VecDeque::new();
        chunks.push_back((Duration::ZERO, first));
        chunks.push_back((Duration::from_millis(900), last));
        let buf = SharedBuf::default();
        run(Script { chunks }, Box::new(buf.clone())).unwrap();
        let replies = decode_all(&buf.0.lock().unwrap().clone());
        let kinds = types(&replies);
        assert_eq!(kinds.first(), Some(&"hello_ack"));
        assert_eq!(kinds.last(), Some(&"stopped"));
        let rules: Vec<&Value> = replies
            .iter()
            .filter(|m| m.payload["topic"] == IOC_TOPIC)
            .map(|m| &m.payload["data"]["rule"])
            .collect();
        assert_eq!(rules, ["ssh-bruteforce"]);
        assert!(replies.iter().any(|m| m.payload["data"]["message"]
            .as_str()
            .is_some_and(|t| t.starts_with("following"))));
    }

    #[test]
    fn invalid_config_sends_an_error_and_fails() {
        let bad_configs = [
            json!({ "rules": { "bogus": 1 } }),
            json!({ "rules": { "bad_ips": ["nope"] } }),
            json!({ "rules": { "bruteforce_threshold": 0 } }),
        ];
        for config in bad_configs {
            let messages = vec![
                host_msg("hello", json!({ "host_api": 1 })),
                host_msg("start", json!({ "config": config })),
            ];
            let (result, replies) = run_raw(messages);
            assert!(matches!(result, Err(ModuleError::Config(_))));
            assert_eq!(types(&replies), ["hello_ack", "error"]);
        }
    }

    #[test]
    fn rejects_a_bad_hello_and_closed_input() {
        let bad = vec![host_msg("hello", json!({ "host_api": 2 }))];
        assert!(matches!(run_raw(bad).0, Err(ModuleError::Handshake(_))));
        let (result, replies) = run_raw(Vec::new());
        assert!(result.is_ok());
        assert!(replies.is_empty());
    }

    #[test]
    fn config_defaults_and_masking_flag() {
        let config = ModuleConfig::from_value(&Value::Null).unwrap();
        assert!(config.mask_secrets && config.rules.mask_names);
        assert!(config.paths.is_empty() && !config.follow);
        let open = ModuleConfig::from_value(&json!({ "mask_secrets": false })).unwrap();
        assert!(!open.rules.mask_names);
    }
}
