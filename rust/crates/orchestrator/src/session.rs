//! Host side of the module protocol over any async byte stream.
//!
//! Mirrors `libs/host/module_host.hpp`: the host sends `hello` and the module
//! answers `hello_ack`; the host sends `start` and the module answers
//! `started`. Afterwards the module streams `event`/`log` messages and
//! answers `ping` with `pong`.

use std::time::Duration;

use avscan_manifest::{Manifest, HOST_API_VERSION};
use avscan_protocol::{encode_frame, FrameReader, Message, ProtocolError};
use serde_json::{json, Map, Value};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, watch};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::bus::{topic_allowed, BusEvent};

/// Errors of one module connection.
#[derive(Debug, Error)]
pub enum HostError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out")]
    Timeout,
    #[error("connection closed")]
    Closed,
    #[error("{0}")]
    Violation(String),
}

fn violation(msg: impl Into<String>) -> HostError {
    HostError::Violation(msg.into())
}

/// Timeouts of the handshake, stop and liveness checks.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub hello: Duration,
    pub start: Duration,
    pub stop: Duration,
    pub ping: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            hello: Duration::from_millis(5000),
            start: Duration::from_millis(10000),
            stop: Duration::from_millis(5000),
            ping: Duration::from_millis(2000),
        }
    }
}

/// Framed message transport over an async reader/writer pair.
pub struct Connection<R, W> {
    reader: R,
    writer: W,
    frames: FrameReader,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Connection<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            frames: FrameReader::new(),
        }
    }

    pub async fn send(&mut self, msg: &Message) -> Result<(), HostError> {
        let frame = encode_frame(msg)?;
        self.writer.write_all(&frame).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Receives one message. Cancel-safe: bytes already read stay buffered.
    pub async fn recv(&mut self, timeout: Duration) -> Result<Message, HostError> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 4096];
        loop {
            if let Some(msg) = self.frames.next_message()? {
                return Ok(msg);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            let read = tokio::time::timeout(left, self.reader.read(&mut buf)).await;
            let n = read.map_err(|_| HostError::Timeout)??;
            if n == 0 {
                return Err(HostError::Closed);
            }
            self.frames.feed(&buf[..n]);
        }
    }
}

/// How a running session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// Shutdown was requested; `graceful` is true if the module answered `stopped`.
    Shutdown { graceful: bool },
    /// The module broke the protocol, stopped answering or disconnected.
    Failed(String),
}

enum Wake {
    Shutdown,
    Received(Result<Message, HostError>),
}

/// One host-to-module session (handshake, event routing, liveness, stop).
pub struct Session<R, W> {
    conn: Connection<R, W>,
    manifest: Manifest,
    bus: broadcast::Sender<BusEvent>,
    timeouts: Timeouts,
    running: bool,
    ping_seq: u32,
    dropped_events: u32,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Session<R, W> {
    pub fn new(
        conn: Connection<R, W>,
        manifest: Manifest,
        bus: broadcast::Sender<BusEvent>,
        timeouts: Timeouts,
    ) -> Self {
        Self {
            conn,
            manifest,
            bus,
            timeouts,
            running: false,
            ping_seq: 0,
            dropped_events: 0,
        }
    }

    /// Number of events dropped because their topic was not declared.
    pub fn dropped_events(&self) -> u32 {
        self.dropped_events
    }

    fn base(&self, msg_type: &str) -> Message {
        Message::new(msg_type).with_module(self.manifest.id.clone())
    }

    /// Handshake and start. `config_override` keys replace manifest config keys.
    pub async fn start(&mut self, config_override: &Map<String, Value>) -> Result<(), HostError> {
        let t = self.timeouts;
        let hello = self.base("hello");
        let hello = hello.with_payload(json!({ "host_api": HOST_API_VERSION }));
        self.conn.send(&hello).await?;
        let ack = self.expect("hello_ack", t.hello, true).await?;
        self.check_ack(&ack)?;

        let mut config = self.manifest.config.clone();
        for (key, value) in config_override {
            config.insert(key.clone(), value.clone());
        }
        let start = self.base("start").with_payload(json!({ "config": config }));
        self.conn.send(&start).await?;
        self.expect("started", t.start, true).await?;
        self.running = true;
        info!(module = %self.manifest.id, "module started");
        Ok(())
    }

    /// Liveness check: `ping` with a correlation id, expects a matching `pong`.
    pub async fn ping(&mut self) -> Result<(), HostError> {
        self.ping_seq += 1;
        let id = format!("ping-{}", self.ping_seq);
        let msg = self.base("ping").with_id(id.clone());
        self.conn.send(&msg).await?;
        let t = self.timeouts.ping;
        let pong = self.expect("pong", t, true).await?;
        if pong.id.as_deref() != Some(id.as_str()) {
            return Err(violation("pong carries the wrong id"));
        }
        Ok(())
    }

    /// Graceful stop. Returns true if the module confirmed with `stopped`.
    pub async fn stop(&mut self) -> bool {
        let msg = self.base("stop");
        if self.conn.send(&msg).await.is_err() {
            self.running = false;
            return false;
        }
        let t = self.timeouts.stop;
        let graceful = self.expect("stopped", t, false).await.is_ok();
        self.running = false;
        graceful
    }

    /// Serves the session until shutdown is requested or the module fails.
    /// `idle` is how long to wait for traffic before sending a `ping`.
    pub async fn run(
        &mut self,
        shutdown: &mut watch::Receiver<bool>,
        idle: Duration,
    ) -> SessionEnd {
        loop {
            if *shutdown.borrow() {
                return SessionEnd::Shutdown {
                    graceful: self.stop().await,
                };
            }
            let wake = tokio::select! {
                _ = shutdown.changed() => Wake::Shutdown,
                received = self.conn.recv(idle) => Wake::Received(received),
            };
            match wake {
                Wake::Shutdown => {
                    return SessionEnd::Shutdown {
                        graceful: self.stop().await,
                    };
                }
                Wake::Received(Ok(msg)) => {
                    if let Err(e) = self.dispatch(&msg) {
                        return SessionEnd::Failed(e.to_string());
                    }
                }
                Wake::Received(Err(HostError::Timeout)) => {
                    if let Err(e) = self.ping().await {
                        return SessionEnd::Failed(e.to_string());
                    }
                }
                Wake::Received(Err(e)) => return SessionEnd::Failed(e.to_string()),
            }
        }
    }

    fn dispatch(&mut self, msg: &Message) -> Result<(), HostError> {
        self.check_envelope(msg)?;
        match msg.msg_type.as_str() {
            "event" => self.handle_event(msg),
            "log" => self.handle_log(msg),
            "pong" => {}
            "error" => {
                let text = payload_text(msg, "message");
                warn!(module = %self.manifest.id, error = text, "module reported an error");
            }
            "stopped" => return Err(violation("module stopped on its own")),
            other => {
                return Err(violation(format!(
                    "unexpected message '{other}' from module"
                )))
            }
        }
        Ok(())
    }

    /// Waits for a message of type `ty`. Logs and events that arrive meanwhile
    /// are processed. In `strict` mode any other message type is an error.
    async fn expect(
        &mut self,
        ty: &str,
        timeout: Duration,
        strict: bool,
    ) -> Result<Message, HostError> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let msg = self.conn.recv(left).await?;
            self.check_envelope(&msg)?;
            if msg.msg_type == ty {
                return Ok(msg);
            }
            match msg.msg_type.as_str() {
                "log" => self.handle_log(&msg),
                "event" => self.handle_event(&msg),
                other if strict => {
                    let text = format!("unexpected '{other}' while waiting for '{ty}'");
                    return Err(violation(text));
                }
                _ => {}
            }
        }
    }

    fn check_envelope(&self, msg: &Message) -> Result<(), HostError> {
        if msg.module.as_deref() != Some(self.manifest.id.as_str()) {
            let text = format!("message from unexpected module {:?}", msg.module);
            return Err(violation(text));
        }
        Ok(())
    }

    fn check_ack(&self, ack: &Message) -> Result<(), HostError> {
        let p = &ack.payload;
        if p.get("api_version").and_then(Value::as_i64) != Some(self.manifest.api_version) {
            return Err(violation("module api_version differs from its manifest"));
        }
        if p.get("module_version").and_then(Value::as_str) != Some(self.manifest.version.as_str()) {
            return Err(violation(
                "module version differs from the manifest version",
            ));
        }
        let Some(caps) = p.get("capabilities").and_then(Value::as_array) else {
            return Err(violation("hello_ack must list capabilities"));
        };
        for cap in caps {
            let Some(name) = cap.as_str() else {
                return Err(violation("capabilities must be strings"));
            };
            if !self.manifest.capabilities.iter().any(|c| c == name) {
                let text = format!("module claims undeclared capability '{name}'");
                return Err(violation(text));
            }
        }
        Ok(())
    }

    fn handle_log(&self, msg: &Message) {
        let text = payload_text(msg, "message");
        info!(module = %self.manifest.id, message = text, "module log");
    }

    fn handle_event(&mut self, msg: &Message) {
        if !self.running {
            return;
        }
        let topic = payload_text(msg, "topic");
        if topic.is_empty() || !topic_allowed(&self.manifest.publishes, topic) {
            self.dropped_events += 1;
            warn!(module = %self.manifest.id, topic, "dropped event with undeclared topic");
            return;
        }
        let data = msg
            .payload
            .get("data")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let event = BusEvent {
            topic: topic.to_string(),
            data,
            source: self.manifest.id.clone(),
        };
        // Having no subscribers is fine: nobody observes the event.
        let _ = self.bus.send(event);
    }
}

fn payload_text<'a>(msg: &'a Message, key: &str) -> &'a str {
    msg.payload.get(key).and_then(Value::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    use avscan_manifest::parse_manifest;
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
    use tokio::time::timeout;

    use crate::bus::new_bus;

    type Pipe = Connection<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>;
    const WAIT: Duration = Duration::from_secs(2);

    fn pipe() -> (Pipe, Pipe) {
        let (a, b) = tokio::io::duplex(16 * 1024);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        (Connection::new(ar, aw), Connection::new(br, bw))
    }

    fn manifest() -> Manifest {
        let text = r#"{"id":"log_hunter","name":"Log hunter","version":"0.1.0","api_version":1,"entry":{"exe":"log-hunter"},"capabilities":["log.hunt"],"events":{"publishes":["log_hunter.ioc"]},"config":{"path":"/var/log/auth.log"}}"#;
        parse_manifest(text, HOST_API_VERSION).unwrap()
    }

    fn fast() -> Timeouts {
        let t = Duration::from_millis(200);
        Timeouts {
            hello: t,
            start: t,
            stop: t,
            ping: t,
        }
    }

    fn good_ack() -> Value {
        json!({"api_version": 1, "module_version": "0.1.0", "capabilities": ["log.hunt"]})
    }

    fn reply(msg_type: &str, payload: Value) -> Message {
        Message::new(msg_type)
            .with_module("log_hunter")
            .with_payload(payload)
    }

    async fn answer_hello(module: &mut Pipe, ack: Message) {
        let hello = module.recv(WAIT).await.unwrap();
        assert_eq!(hello.msg_type, "hello");
        assert_eq!(hello.payload["host_api"], 1);
        module.send(&ack).await.unwrap();
    }

    async fn answer_start(module: &mut Pipe) -> Message {
        let start = module.recv(WAIT).await.unwrap();
        assert_eq!(start.msg_type, "start");
        module.send(&reply("started", json!({}))).await.unwrap();
        start
    }

    async fn start_with_ack(ack: Message) -> Result<(), HostError> {
        let (host, mut module) = pipe();
        tokio::spawn(async move {
            answer_hello(&mut module, ack).await;
        });
        let mut session = Session::new(host, manifest(), new_bus(), fast());
        session.start(&Map::new()).await
    }

    #[tokio::test]
    async fn handshake_merges_config_override() {
        let (host, mut module) = pipe();
        let module_task = tokio::spawn(async move {
            answer_hello(&mut module, reply("hello_ack", good_ack())).await;
            answer_start(&mut module).await
        });
        let mut session = Session::new(host, manifest(), new_bus(), fast());
        let mut over = Map::new();
        over.insert("path".to_string(), json!("/tmp/x"));
        session.start(&over).await.unwrap();
        let start = module_task.await.unwrap();
        assert_eq!(start.payload["config"]["path"], "/tmp/x");
    }

    #[tokio::test]
    async fn rejects_undeclared_capability() {
        let ack = json!({"api_version": 1, "module_version": "0.1.0", "capabilities": ["evil"]});
        let res = start_with_ack(reply("hello_ack", ack)).await;
        assert!(matches!(res, Err(HostError::Violation(_))));
    }

    #[tokio::test]
    async fn rejects_version_mismatch() {
        let ack = json!({"api_version": 1, "module_version": "9.9.9", "capabilities": []});
        let res = start_with_ack(reply("hello_ack", ack)).await;
        assert!(matches!(res, Err(HostError::Violation(_))));
    }

    #[tokio::test]
    async fn rejects_foreign_module_id() {
        let ack = Message::new("hello_ack")
            .with_module("intruder")
            .with_payload(good_ack());
        let res = start_with_ack(ack).await;
        assert!(matches!(res, Err(HostError::Violation(_))));
    }

    #[tokio::test]
    async fn times_out_without_ack() {
        let (host, mut module) = pipe();
        tokio::spawn(async move {
            let _ = module.recv(WAIT).await;
            tokio::time::sleep(Duration::from_millis(600)).await;
        });
        let mut session = Session::new(host, manifest(), new_bus(), fast());
        let res = session.start(&Map::new()).await;
        assert!(matches!(res, Err(HostError::Timeout)));
    }

    #[tokio::test]
    async fn routes_declared_events_and_drops_undeclared() {
        let (host, mut module) = pipe();
        tokio::spawn(async move {
            answer_hello(&mut module, reply("hello_ack", good_ack())).await;
            answer_start(&mut module).await;
            let allowed = json!({"topic": "log_hunter.ioc", "data": {"ip": "1.2.3.4"}});
            module.send(&reply("event", allowed)).await.unwrap();
            let denied = json!({"topic": "other.topic", "data": {}});
            module.send(&reply("event", denied)).await.unwrap();
            let stop = module.recv(WAIT).await.unwrap();
            assert_eq!(stop.msg_type, "stop");
            module.send(&reply("stopped", json!({}))).await.unwrap();
        });

        let bus = new_bus();
        let mut events = bus.subscribe();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let mut session = Session::new(host, manifest(), bus, fast());
        session.start(&Map::new()).await.unwrap();
        let runner = tokio::spawn(async move {
            let end = session.run(&mut shutdown_rx, Duration::from_secs(1)).await;
            (end, session.dropped_events())
        });

        let event = timeout(WAIT, events.recv()).await.unwrap().unwrap();
        assert_eq!(event.topic, "log_hunter.ioc");
        assert_eq!(event.source, "log_hunter");
        assert_eq!(event.data["ip"], "1.2.3.4");

        shutdown_tx.send(true).unwrap();
        let (end, dropped) = timeout(WAIT, runner).await.unwrap().unwrap();
        assert_eq!(end, SessionEnd::Shutdown { graceful: true });
        assert_eq!(dropped, 1);
    }

    #[tokio::test]
    async fn ping_requires_matching_pong_id() {
        let (host, mut module) = pipe();
        tokio::spawn(async move {
            answer_hello(&mut module, reply("hello_ack", good_ack())).await;
            answer_start(&mut module).await;
            for answer_id in ["ping-1", "wrong"] {
                let ping = module.recv(WAIT).await.unwrap();
                assert_eq!(ping.msg_type, "ping");
                let pong = reply("pong", json!({})).with_id(answer_id);
                module.send(&pong).await.unwrap();
            }
        });
        let mut session = Session::new(host, manifest(), new_bus(), fast());
        session.start(&Map::new()).await.unwrap();
        session.ping().await.unwrap();
        let second = session.ping().await;
        assert!(matches!(second, Err(HostError::Violation(_))));
    }
}
