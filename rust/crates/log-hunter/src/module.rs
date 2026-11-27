//! AVScan module runtime: speaks the module protocol over stdin/stdout.
//!
//! Flow (mirrors `libs/host/module_host.hpp`): `hello` / `hello_ack`, then
//! `start` with the config / `started`. After that the module analyzes the
//! configured log files (once, or continuously with `follow`), answers `ping`
//! and `command`, and ends on `stop`. Alerts are published as `log_hunter.ioc`
//! events and progress as `log_hunter.log`. Only protocol frames may be written
//! to the output; diagnostics go to stderr.
//!
//! Command `log.hunt` (args: `paths`, a list of files) analyzes the files with
//! the rules from the start config and answers `command_result`. Every path is
//! resolved (symlinks included) and must lie inside one of the `command_roots`
//! directories. Without `command_roots` the directories of the configured
//! `paths` are used; with neither, the command is refused. The analysis runs
//! on a worker thread (at most `MAX_WORKERS` at a time), so `ping` is answered
//! while it runs. `stop` waits for the analyses that are still running. The
//! files named in the start config are analyzed before the module serves
//! requests, so a large one delays the first `ping` answer.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use avscan_module_kit::{check_paths, paths_from, Workers};
use avscan_protocol::{FrameReader, Message, ProtocolError};
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
const HUNT_COMMAND: &str = "log.hunt";
/// How many `log.hunt` analyses may run at the same time.
const MAX_WORKERS: usize = 4;

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

impl From<avscan_module_kit::KitError> for ModuleError {
    fn from(error: avscan_module_kit::KitError) -> Self {
        use avscan_module_kit::KitError;
        match error {
            KitError::Io(e) => Self::Io(e),
            KitError::Protocol(e) => Self::Protocol(e),
            KitError::Poisoned => Self::Poisoned,
        }
    }
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
    /// Directories the `log.hunt` command may read from.
    pub command_roots: Vec<PathBuf>,
    pub rules: Rules,
}

/// Explicit `command_roots`, or else the directories of the configured paths.
fn command_roots_from(value: Option<&Value>, paths: &[PathBuf]) -> Vec<PathBuf> {
    let configured = paths_from(value);
    if !configured.is_empty() {
        return configured;
    }
    let parents = paths
        .iter()
        .filter_map(|p| p.parent())
        .filter(|p| !p.as_os_str().is_empty());
    parents.map(Path::to_path_buf).collect()
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
        let paths = paths_from(config.get("paths"));
        let command_roots = command_roots_from(config.get("command_roots"), &paths);
        Ok(Self {
            paths,
            follow,
            mask_secrets,
            command_roots,
            rules: parse_rules(config.get("rules"), mask_secrets)?,
        })
    }
}

fn reply(msg_type: &str, payload: Value) -> Message {
    Message::new(msg_type)
        .with_module(MODULE_ID)
        .with_payload(payload)
}

/// Shared, thread-safe frame writer (follower and worker threads write too).
#[derive(Clone)]
struct Out(avscan_module_kit::Out);

impl Out {
    fn new(output: Box<dyn Write + Send>) -> Self {
        Self(avscan_module_kit::Out::new(output))
    }

    fn send(&self, msg: &Message) -> Result<(), ModuleError> {
        Ok(self.0.send(msg)?)
    }

    fn event(&self, topic: &str, data: Value) -> Result<(), ModuleError> {
        Ok(self.0.event(MODULE_ID, topic, data)?)
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
    Ok(avscan_module_kit::recv(input, frames)?)
}

fn result_message(id: Option<&str>, ok: bool, error: Option<&str>) -> Message {
    avscan_module_kit::result_message(MODULE_ID, id, ok, error)
}

fn command_result(request: &Message, ok: bool, error: Option<&str>) -> Message {
    result_message(request.id.as_deref(), ok, error)
}

/// Answers one `command`. Unknown commands and bad arguments are answered at
/// once with `ok: false`; a valid `log.hunt` is answered by its worker thread
/// when the analysis is done. Neither ends the session.
fn handle_command(
    request: &Message,
    out: &Out,
    config: &ModuleConfig,
    sink: &AlertSink,
    workers: &mut Workers,
) -> Result<(), ModuleError> {
    let name = request
        .payload
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("");
    if name != HUNT_COMMAND {
        let text = format!("unsupported command '{name}'");
        return out.send(&command_result(request, false, Some(text.as_str())));
    }
    let args = request.payload.get("args");
    let requested = paths_from(args.and_then(|a| a.get("paths")));
    if requested.is_empty() {
        let text = "args.paths must list at least one file";
        return out.send(&command_result(request, false, Some(text)));
    }
    let paths = match check_paths(&requested, &config.command_roots) {
        Ok(paths) => paths,
        Err(text) => {
            return out.send(&command_result(request, false, Some(text.as_str())));
        }
    };
    if !workers.try_acquire() {
        let text = "too many analyses are running";
        return out.send(&command_result(request, false, Some(text)));
    }
    let out = out.clone();
    let rules = config.rules.clone();
    let sink = Arc::clone(sink);
    let id = request.id.clone();
    workers.spawn(move || {
        for path in &paths {
            analyze_file(&out, path, &rules, &sink);
        }
        let _ = out.send(&result_message(id.as_deref(), true, None));
    });
    Ok(())
}

enum Exit {
    Stop,
    Closed,
}

fn serve<R: Read>(
    input: &mut R,
    frames: &mut FrameReader,
    out: &Out,
    config: &ModuleConfig,
    sink: &AlertSink,
    workers: &mut Workers,
) -> Result<Exit, ModuleError> {
    while let Some(msg) = recv(input, frames)? {
        match msg.msg_type.as_str() {
            "ping" => {
                let mut pong = reply("pong", json!({}));
                pong.id = msg.id.clone();
                out.send(&pong)?;
            }
            "command" => handle_command(&msg, out, config, sink, workers)?,
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

    let mut workers = Workers::new(MAX_WORKERS);
    let exit = serve(&mut input, &mut frames, &out, &config, &sink, &mut workers);
    workers.join_all();
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
    use avscan_protocol::encode_frame;
    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex;
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

    fn command_msg(id: &str, name: &str, args: Value) -> Message {
        let msg = host_msg("command", json!({ "name": name, "args": args }));
        msg.with_id(id)
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

    /// Runs hello, start with `config`, one `log.hunt` command and stop.
    fn hunt_session(config: Value, paths: Value) -> Vec<Message> {
        let messages = vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": config })),
            command_msg("cmd-1", "log.hunt", json!({ "paths": paths })),
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
    fn log_hunt_command_analyzes_the_requested_files() {
        let dir = TempDir::new("module_command");
        let path = burst_log(&dir);
        let root = dir.path().to_str().unwrap().to_string();
        let config = json!({ "command_roots": [root] });
        let replies = hunt_session(config, json!([path.to_str().unwrap()]));
        assert_eq!(
            types(&replies),
            [
                "hello_ack",
                "started",
                "event",
                "event",
                "command_result",
                "stopped"
            ]
        );
        assert_eq!(replies[2].payload["data"]["rule"], "ssh-bruteforce");
        assert_eq!(replies[4].id.as_deref(), Some("cmd-1"));
        assert_eq!(replies[4].payload["ok"], json!(true));
    }

    #[test]
    fn ping_is_answered_while_a_command_is_handled() {
        let dir = TempDir::new("module_ping_command");
        let path = burst_log(&dir);
        let root = dir.path().to_str().unwrap().to_string();
        let args = json!({ "paths": [path.to_str().unwrap()] });
        let messages = vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": { "command_roots": [root] } })),
            command_msg("cmd-1", "log.hunt", args),
            host_msg("ping", json!({})).with_id("ping-1"),
            host_msg("stop", json!({})),
        ];
        let (result, replies) = run_raw(messages);
        result.unwrap();
        let kinds = types(&replies);
        assert!(kinds.contains(&"pong"));
        assert_eq!(kinds.last(), Some(&"stopped"));
        let at = kinds.iter().position(|k| *k == "command_result").unwrap();
        let events_before = kinds[..at].iter().filter(|k| **k == "event").count();
        assert_eq!(events_before, 2);
        assert_eq!(replies[at].id.as_deref(), Some("cmd-1"));
        assert_eq!(replies[at].payload["ok"], json!(true));
    }

    #[test]
    fn log_hunt_command_refuses_paths_outside_the_roots() {
        let allowed = TempDir::new("module_roots_allowed");
        let other = TempDir::new("module_roots_other");
        let outside = burst_log(&other);
        let root = allowed.path().to_str().unwrap().to_string();
        let config = json!({ "command_roots": [root] });
        let replies = hunt_session(config, json!([outside.to_str().unwrap()]));
        assert_eq!(
            types(&replies),
            ["hello_ack", "started", "command_result", "stopped"]
        );
        assert_eq!(replies[2].payload["ok"], json!(false));
        let error = replies[2].payload["error"].as_str().unwrap();
        assert!(error.contains("outside command_roots"));
    }

    #[test]
    fn log_hunt_command_needs_configured_roots() {
        let dir = TempDir::new("module_no_roots");
        let path = burst_log(&dir);
        let replies = hunt_session(json!({}), json!([path.to_str().unwrap()]));
        assert_eq!(replies[2].msg_type, "command_result");
        assert_eq!(replies[2].payload["ok"], json!(false));
        let error = replies[2].payload["error"].as_str().unwrap();
        assert!(error.contains("command_roots"));
    }

    #[test]
    fn command_roots_default_to_the_directories_of_the_paths() {
        let paths = [
            PathBuf::from("/var/log/auth.log"),
            PathBuf::from("local.log"),
        ];
        let roots = command_roots_from(None, &paths);
        assert_eq!(roots, [PathBuf::from("/var/log")]);
        let explicit = json!(["/srv/logs"]);
        let roots = command_roots_from(Some(&explicit), &paths);
        assert_eq!(roots, [PathBuf::from("/srv/logs")]);
    }

    #[test]
    fn bad_commands_get_error_results() {
        let messages = vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": {} })),
            command_msg("cmd-1", "evil", json!({})),
            command_msg("cmd-2", "log.hunt", json!({})),
            host_msg("stop", json!({})),
        ];
        let (result, replies) = run_raw(messages);
        result.unwrap();
        assert_eq!(
            types(&replies),
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
            .filter(|m| m.payload.get("topic") == Some(&json!(IOC_TOPIC)))
            .map(|m| &m.payload["data"]["rule"])
            .collect();
        assert_eq!(rules, ["ssh-bruteforce"]);
        let following = replies.iter().any(|m| {
            let text = m.payload.get("data").and_then(|d| d["message"].as_str());
            text.is_some_and(|t| t.starts_with("following"))
        });
        assert!(following);
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
        assert!(config.command_roots.is_empty());
        let open = ModuleConfig::from_value(&json!({ "mask_secrets": false })).unwrap();
        assert!(!open.rules.mask_names);
    }
}
