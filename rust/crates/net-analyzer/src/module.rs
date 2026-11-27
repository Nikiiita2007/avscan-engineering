//! AVScan module runtime: speaks the module protocol over stdin/stdout.
//!
//! Flow (mirrors `libs/host/module_host.hpp`): `hello` / `hello_ack`, then
//! `start` with the config / `started`. After that the module analyzes the
//! configured pcap files, optionally listens on a loopback port, answers `ping`
//! and `command`, and ends on `stop`. Alerts are published as
//! `net_analyzer.alert` events and progress as `net_analyzer.log`. Only
//! protocol frames may be written to the output; diagnostics go to stderr.
//!
//! Command `net.analyze` (args: `pcap_paths`, a list of pcap files) analyzes
//! the files with the rules from the start config and answers
//! `command_result`. Every path is resolved (symlinks included) and must lie
//! inside one of the `command_roots` directories. Without `command_roots` the
//! directories of the configured `pcap_paths` are used; with neither, the
//! command is refused. The analysis runs on a worker thread (at most
//! `MAX_WORKERS` at a time), so `ping` is answered while it runs. `stop` waits
//! for the analyses that are still running. The files named in the start
//! config are analyzed before the module serves requests, so a large one
//! delays the first `ping` answer.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use avscan_module_kit::{check_paths, paths_from};
use avscan_protocol::{encode_frame, FrameReader, Message, ProtocolError};
use serde_json::{json, Value};
use thiserror::Error;

use crate::alert::Alert;
use crate::analyzer::analyze_reader;
use crate::listen::{emit, AlertSink, Listener};
use crate::pcap::PcapError;
use crate::rules::Rules;

pub const MODULE_ID: &str = "net_analyzer";
pub const ALERT_TOPIC: &str = "net_analyzer.alert";
pub const LOG_TOPIC: &str = "net_analyzer.log";
pub const CAPABILITIES: [&str; 2] = ["net.analyze", "report.mask_sensitive"];
const ANALYZE_COMMAND: &str = "net.analyze";
const HOST_API: i64 = 1;
/// How many `net.analyze` analyses may run at the same time.
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

fn config_error(what: &str, error: &dyn std::fmt::Display) -> ModuleError {
    ModuleError::Config(format!("{what}: {error}"))
}

/// Module configuration taken from the `start` message.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleConfig {
    pub mask_secrets: bool,
    pub pcap_paths: Vec<PathBuf>,
    /// Directories the `net.analyze` command may read from.
    pub command_roots: Vec<PathBuf>,
    pub listen: Option<SocketAddr>,
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
    Ok(rules)
}

fn parse_listen(value: Option<&Value>) -> Result<Option<SocketAddr>, ModuleError> {
    let Some(text) = value.and_then(Value::as_str) else {
        return Ok(None);
    };
    let addr = text
        .parse::<SocketAddr>()
        .map_err(|e| config_error("listen", &e))?;
    Ok(Some(addr))
}

impl ModuleConfig {
    pub fn from_value(config: &Value) -> Result<Self, ModuleError> {
        let mode = config
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("passive");
        if mode != "passive" {
            let text = format!("unsupported mode '{mode}', only 'passive' is implemented");
            return Err(ModuleError::Config(text));
        }
        let mask_secrets = config
            .get("mask_secrets")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let pcap_paths = paths_from(config.get("pcap_paths"));
        let command_roots = command_roots_from(config.get("command_roots"), &pcap_paths);
        Ok(Self {
            mask_secrets,
            pcap_paths,
            command_roots,
            listen: parse_listen(config.get("listen"))?,
            rules: parse_rules(config.get("rules"), mask_secrets)?,
        })
    }
}

fn reply(msg_type: &str, payload: Value) -> Message {
    Message::new(msg_type)
        .with_module(MODULE_ID)
        .with_payload(payload)
}

/// Shared, thread-safe frame writer (listener and worker threads write too).
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
            let _ = out.event(ALERT_TOPIC, data);
        }
    })
}

fn analyze_file(out: &Out, path: &Path, rules: &Rules, sink: &AlertSink) {
    let file = path.display().to_string();
    let opened = File::open(path).map_err(PcapError::from);
    let result = opened.and_then(|f| analyze_reader(BufReader::new(f), rules, |a| emit(sink, &a)));
    let note = match result {
        Ok(stats) => json!({ "message": "analysis finished", "file": file, "stats": stats }),
        Err(e) => json!({ "message": format!("cannot analyze: {e}"), "file": file }),
    };
    let _ = out.event(LOG_TOPIC, note);
}

fn start_listener(out: &Out, config: &ModuleConfig, sink: &AlertSink) -> Option<Listener> {
    let addr = config.listen?;
    match Listener::start(addr, config.rules.clone(), Arc::clone(sink)) {
        Ok(listener) => {
            let note = json!({ "message": "listening", "addr": listener.addr.to_string() });
            let _ = out.event(LOG_TOPIC, note);
            Some(listener)
        }
        Err(e) => {
            let note = json!({ "message": format!("cannot listen on {addr}: {e}") });
            let _ = out.event(LOG_TOPIC, note);
            None
        }
    }
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

fn result_message(id: Option<&str>, ok: bool, error: Option<&str>) -> Message {
    avscan_module_kit::result_message(MODULE_ID, id, ok, error)
}

fn command_result(request: &Message, ok: bool, error: Option<&str>) -> Message {
    result_message(request.id.as_deref(), ok, error)
}

/// Worker threads of the running `net.analyze` analyses. Only the protocol
/// thread starts workers, so the counter needs no compare-and-swap.
#[derive(Default)]
struct Workers {
    handles: Vec<JoinHandle<()>>,
    active: Arc<AtomicUsize>,
}

impl Workers {
    /// Reserves a slot; false when `MAX_WORKERS` analyses are already running.
    fn try_acquire(&self) -> bool {
        if self.active.load(Ordering::SeqCst) >= MAX_WORKERS {
            return false;
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        true
    }

    /// Runs `job` on a new thread and frees the reserved slot afterwards.
    fn spawn(&mut self, job: impl FnOnce() + Send + 'static) {
        self.handles.retain(|handle| !handle.is_finished());
        let active = Arc::clone(&self.active);
        self.handles.push(std::thread::spawn(move || {
            job();
            active.fetch_sub(1, Ordering::SeqCst);
        }));
    }

    /// Waits for every running analysis.
    fn join_all(&mut self) {
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Answers one `command`. Unknown commands and bad arguments are answered at
/// once with `ok: false`; a valid `net.analyze` is answered by its worker
/// thread when the analysis is done. Neither ends the session.
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
    if name != ANALYZE_COMMAND {
        let text = format!("unsupported command '{name}'");
        return out.send(&command_result(request, false, Some(text.as_str())));
    }
    let args = request.payload.get("args");
    let requested = paths_from(args.and_then(|a| a.get("pcap_paths")));
    if requested.is_empty() {
        let text = "args.pcap_paths must list at least one file";
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
    for path in &config.pcap_paths {
        analyze_file(&out, path, &config.rules, &sink);
    }
    let listener = start_listener(&out, &config, &sink);

    let mut workers = Workers::default();
    let exit = serve(&mut input, &mut frames, &out, &config, &sink, &mut workers);
    workers.join_all();
    drop(listener);
    if matches!(exit?, Exit::Stop) {
        out.send(&reply("stopped", json!({})))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::TCP_SYN;
    use crate::pcap::LINKTYPE_ETHERNET;
    use crate::test_util::{pcap_file, tcp_frame, TempDir};

    use avscan_manifest::{parse_manifest, HOST_API_VERSION};

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
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

    /// Runs hello, start with `config`, one `net.analyze` command and stop.
    fn analyze_session(config: Value, pcap_paths: Value) -> Vec<Message> {
        let args = json!({ "pcap_paths": pcap_paths });
        let messages = vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": config })),
            command_msg("cmd-1", ANALYZE_COMMAND, args),
            host_msg("stop", json!({})),
        ];
        let (result, replies) = run_raw(messages);
        result.unwrap();
        replies
    }

    fn syn_pcap(dir: &TempDir, name: &str) -> PathBuf {
        let frame = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], (5000, 4444), TCP_SYN);
        dir.write_bytes(name, &pcap_file(LINKTYPE_ETHERNET, &[(1.0, frame)]));
        dir.path().join(name)
    }

    fn types(replies: &[Message]) -> Vec<&str> {
        replies.iter().map(|m| m.msg_type.as_str()).collect()
    }

    fn log_text(msg: &Message) -> String {
        msg.payload["data"]["message"].as_str().unwrap().to_string()
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
    fn matches_the_existing_cpp_manifest() {
        let text = include_str!("../../../../modules/net_analyzer/module.json");
        let manifest = parse_manifest(text, HOST_API_VERSION).unwrap();
        assert_eq!(manifest.id, MODULE_ID);
        assert_eq!(manifest.version, env!("CARGO_PKG_VERSION"));
        for capability in CAPABILITIES {
            assert!(manifest.capabilities.iter().any(|c| c == capability));
        }
        assert!(manifest.publishes.iter().any(|t| t == ALERT_TOPIC));
        assert!(manifest.publishes.iter().any(|t| t == LOG_TOPIC));
        let replies = session(Value::Object(manifest.config.clone()));
        assert_eq!(types(&replies), ["hello_ack", "started", "stopped"]);
        assert_eq!(replies[0].payload["api_version"], manifest.api_version);
    }

    #[test]
    fn analyzes_pcap_files_from_the_config() {
        let dir = TempDir::new("module_pcap");
        let path = syn_pcap(&dir, "c2.pcap");
        let replies = session(json!({ "pcap_paths": [path.to_str().unwrap()] }));
        assert_eq!(
            types(&replies),
            ["hello_ack", "started", "event", "event", "stopped"]
        );
        assert_eq!(replies[2].payload["topic"], ALERT_TOPIC);
        assert_eq!(replies[2].payload["data"]["rule"], "suspicious-port");
        assert_eq!(replies[3].payload["topic"], LOG_TOPIC);
        assert_eq!(replies[3].payload["data"]["stats"]["packets"], 1);
    }

    #[test]
    fn analyze_command_reports_alerts_and_answers() {
        let dir = TempDir::new("module_command");
        let path = syn_pcap(&dir, "c2.pcap");
        let root = dir.path().to_str().unwrap().to_string();
        let config = json!({ "command_roots": [root] });
        let replies = analyze_session(config, json!([path.to_str().unwrap()]));
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
        assert_eq!(replies[2].payload["topic"], ALERT_TOPIC);
        assert_eq!(replies[2].payload["data"]["rule"], "suspicious-port");
        assert_eq!(replies[4].id.as_deref(), Some("cmd-1"));
        assert_eq!(replies[4].payload["ok"], json!(true));
    }

    #[test]
    fn ping_is_answered_while_a_command_is_handled() {
        let dir = TempDir::new("module_ping_command");
        let path = syn_pcap(&dir, "c2.pcap");
        let root = dir.path().to_str().unwrap().to_string();
        let args = json!({ "pcap_paths": [path.to_str().unwrap()] });
        let config = json!({ "command_roots": [root] });
        let messages = vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": config })),
            command_msg("cmd-1", ANALYZE_COMMAND, args),
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
    fn the_number_of_running_analyses_is_bounded() {
        let workers = Workers::default();
        for _ in 0..MAX_WORKERS {
            assert!(workers.try_acquire());
        }
        assert!(!workers.try_acquire());
        workers.active.fetch_sub(1, Ordering::SeqCst);
        assert!(workers.try_acquire());
    }

    #[test]
    fn workers_free_their_slot_and_are_joined() {
        let mut workers = Workers::default();
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(workers.try_acquire());
        workers.spawn(move || {
            tx.send(7).unwrap();
        });
        workers.join_all();
        assert_eq!(rx.recv().unwrap(), 7);
        assert_eq!(workers.active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn analyze_command_refuses_paths_outside_the_roots() {
        let allowed = TempDir::new("module_roots_allowed");
        let other = TempDir::new("module_roots_other");
        let outside = syn_pcap(&other, "x.pcap");
        let root = allowed.path().to_str().unwrap().to_string();
        let config = json!({ "command_roots": [root] });
        let replies = analyze_session(config, json!([outside.to_str().unwrap()]));
        assert_eq!(
            types(&replies),
            ["hello_ack", "started", "command_result", "stopped"]
        );
        assert_eq!(replies[2].payload["ok"], json!(false));
        let error = replies[2].payload["error"].as_str().unwrap();
        assert!(error.contains("outside command_roots"));
    }

    #[test]
    fn analyze_command_needs_configured_roots() {
        let dir = TempDir::new("module_no_roots");
        let path = syn_pcap(&dir, "x.pcap");
        let replies = analyze_session(json!({}), json!([path.to_str().unwrap()]));
        assert_eq!(replies[2].msg_type, "command_result");
        assert_eq!(replies[2].payload["ok"], json!(false));
        let error = replies[2].payload["error"].as_str().unwrap();
        assert!(error.contains("command_roots"));
    }

    #[test]
    fn bad_commands_get_error_results() {
        let messages = vec![
            host_msg("hello", json!({ "host_api": 1 })),
            host_msg("start", json!({ "config": {} })),
            command_msg("cmd-1", "evil", json!({})),
            command_msg("cmd-2", ANALYZE_COMMAND, json!({})),
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
    fn command_roots_default_to_the_directories_of_the_paths() {
        let paths = [PathBuf::from("/srv/pcap/a.pcap"), PathBuf::from("b.pcap")];
        let roots = command_roots_from(None, &paths);
        assert_eq!(roots, [PathBuf::from("/srv/pcap")]);
        let explicit = json!(["/srv/other"]);
        let roots = command_roots_from(Some(&explicit), &paths);
        assert_eq!(roots, [PathBuf::from("/srv/other")]);
    }

    #[test]
    fn missing_pcap_files_are_reported_not_fatal() {
        let replies = session(json!({ "pcap_paths": ["definitely/missing.pcap"] }));
        assert_eq!(
            types(&replies),
            ["hello_ack", "started", "event", "stopped"]
        );
        assert!(log_text(&replies[2]).contains("cannot analyze"));
    }

    #[test]
    fn rules_can_be_overridden_from_the_config() {
        let dir = TempDir::new("module_rules");
        let frame = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], (5000, 9999), TCP_SYN);
        dir.write_bytes("x.pcap", &pcap_file(LINKTYPE_ETHERNET, &[(1.0, frame)]));
        let path = dir.path().join("x.pcap");
        let config = json!({
            "pcap_paths": [path.to_str().unwrap()],
            "rules": { "suspicious_ports": [9999] }
        });
        let replies = session(config);
        assert_eq!(replies[2].payload["data"]["rule"], "suspicious-port");
    }

    #[test]
    fn invalid_config_sends_an_error_and_fails() {
        let bad_configs = [
            json!({ "mode": "active" }),
            json!({ "rules": { "bogus": 1 } }),
            json!({ "listen": "not-an-address" }),
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
    fn listens_on_loopback_and_reports_the_address() {
        let replies = session(json!({ "listen": "127.0.0.1:0" }));
        assert_eq!(
            types(&replies),
            ["hello_ack", "started", "event", "stopped"]
        );
        assert_eq!(log_text(&replies[2]), "listening");
    }

    #[test]
    fn refuses_to_listen_on_non_loopback_addresses() {
        let replies = session(json!({ "listen": "0.0.0.0:0" }));
        assert_eq!(
            types(&replies),
            ["hello_ack", "started", "event", "stopped"]
        );
        assert!(log_text(&replies[2]).contains("cannot listen"));
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
        assert!(config.pcap_paths.is_empty() && config.listen.is_none());
        assert!(config.command_roots.is_empty());
        let open = ModuleConfig::from_value(&json!({ "mask_secrets": false })).unwrap();
        assert!(!open.rules.mask_names);
    }
}
