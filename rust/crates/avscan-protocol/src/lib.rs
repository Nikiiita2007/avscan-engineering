//! Wire protocol between the AVScan module host and module processes.
//!
//! Mirrors `libs/host/protocol.hpp`. A frame is a 4-byte **little-endian**
//! payload length followed by that many bytes of UTF-8 JSON (one [`Message`]).

use serde_json::{Map, Value};
use thiserror::Error;

/// Protocol version carried in the `v` field of every message.
pub const PROTOCOL_VERSION: i64 = 1;
/// Maximum payload size of a single frame (1 MiB).
pub const MAX_FRAME_BYTES: usize = 1 << 20;
const HEADER_LEN: usize = 4;
const MAX_ID_LEN: usize = 64;
const MAX_TYPE_LEN: usize = 32;
const KNOWN_KEYS: [&str; 5] = ["v", "type", "id", "module", "payload"];

/// Errors produced while encoding or decoding frames.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("invalid frame length {0}")]
    InvalidLength(usize),
    #[error("frame exceeds the 1 MiB limit")]
    FrameTooLarge,
    #[error("invalid JSON in frame: {0}")]
    InvalidJson(String),
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("frame reader is in an error state; drop the connection")]
    Poisoned,
}

fn invalid(msg: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidMessage(msg.into())
}

/// One protocol message (the JSON envelope inside a frame).
///
/// Types used by the host: hello, hello_ack, start, started, stop, stopped,
/// ping, pong, event, log, error.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub msg_type: String,
    pub id: Option<String>,
    pub module: Option<String>,
    pub payload: Map<String, Value>,
}

impl Message {
    /// Creates a message with an empty payload.
    pub fn new(msg_type: impl Into<String>) -> Self {
        Self {
            msg_type: msg_type.into(),
            id: None,
            module: None,
            payload: Map::new(),
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }

    /// Sets the payload; anything that is not a JSON object is ignored.
    pub fn with_payload(mut self, payload: Value) -> Self {
        if let Value::Object(map) = payload {
            self.payload = map;
        }
        self
    }

    /// Converts the message into its JSON envelope.
    pub fn to_value(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("v".to_string(), Value::from(PROTOCOL_VERSION));
        obj.insert("type".to_string(), Value::from(self.msg_type.as_str()));
        if let Some(id) = &self.id {
            obj.insert("id".to_string(), Value::from(id.as_str()));
        }
        if let Some(module) = &self.module {
            obj.insert("module".to_string(), Value::from(module.as_str()));
        }
        obj.insert("payload".to_string(), Value::Object(self.payload.clone()));
        Value::Object(obj)
    }

    /// Strict envelope validation: unknown keys, wrong types and a wrong
    /// protocol version are all errors (same rules as the C++ host).
    pub fn from_value(value: &Value) -> Result<Self, ProtocolError> {
        let Some(obj) = value.as_object() else {
            return Err(invalid("message must be a JSON object"));
        };
        for key in obj.keys() {
            if !KNOWN_KEYS.contains(&key.as_str()) {
                return Err(invalid(format!("unknown message field '{key}'")));
            }
        }
        if obj.get("v").and_then(Value::as_i64) != Some(PROTOCOL_VERSION) {
            return Err(invalid("unsupported or missing protocol version 'v'"));
        }
        let msg_type = match obj.get("type").and_then(Value::as_str) {
            Some(t) if valid_message_type(t) => t.to_string(),
            _ => return Err(invalid("invalid or missing 'type'")),
        };
        let payload = match obj.get("payload") {
            None => Map::new(),
            Some(Value::Object(map)) => map.clone(),
            Some(_) => return Err(invalid("'payload' must be an object")),
        };
        Ok(Self {
            msg_type,
            id: optional_string(obj, "id")?,
            module: optional_string(obj, "module")?,
            payload,
        })
    }
}

fn valid_message_type(t: &str) -> bool {
    let chars_ok = t.chars().all(|c| c.is_ascii_lowercase() || c == '_');
    !t.is_empty() && t.len() <= MAX_TYPE_LEN && chars_ok
}

fn optional_string(obj: &Map<String, Value>, key: &str) -> Result<Option<String>, ProtocolError> {
    match obj.get(key) {
        None => Ok(None),
        Some(Value::String(s)) if s.len() <= MAX_ID_LEN => Ok(Some(s.clone())),
        Some(_) => Err(invalid(format!("invalid '{key}'"))),
    }
}

/// Serializes a message into one frame (little-endian length + JSON).
pub fn encode_frame(msg: &Message) -> Result<Vec<u8>, ProtocolError> {
    let body = serde_json::to_vec(&msg.to_value())
        .map_err(|e| ProtocolError::InvalidJson(e.to_string()))?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let len = u32::try_from(body.len()).map_err(|_| ProtocolError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Incremental decoder: feed bytes as they arrive, then call
/// [`FrameReader::next_message`] until it returns `Ok(None)`.
/// After the first error the reader stays poisoned.
#[derive(Debug)]
pub struct FrameReader {
    buf: Vec<u8>,
    max_frame: usize,
    failed: bool,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    pub fn new() -> Self {
        Self::with_limit(MAX_FRAME_BYTES)
    }

    pub fn with_limit(max_frame: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_frame,
            failed: false,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        if !self.failed {
            self.buf.extend_from_slice(data);
        }
    }

    /// Returns the next complete message, `Ok(None)` if more bytes are needed.
    pub fn next_message(&mut self) -> Result<Option<Message>, ProtocolError> {
        if self.failed {
            return Err(ProtocolError::Poisoned);
        }
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let header = [self.buf[0], self.buf[1], self.buf[2], self.buf[3]];
        let len = u32::from_le_bytes(header) as usize;
        if len == 0 || len > self.max_frame {
            return self.fail(ProtocolError::InvalidLength(len));
        }
        let end = HEADER_LEN + len;
        if self.buf.len() < end {
            return Ok(None);
        }
        let parsed = serde_json::from_slice::<Value>(&self.buf[HEADER_LEN..end])
            .map_err(|e| ProtocolError::InvalidJson(e.to_string()))
            .and_then(|v| Message::from_value(&v));
        match parsed {
            Ok(msg) => {
                self.buf.drain(..end);
                Ok(Some(msg))
            }
            Err(e) => self.fail(e),
        }
    }

    fn fail<T>(&mut self, err: ProtocolError) -> Result<T, ProtocolError> {
        self.failed = true;
        self.buf.clear();
        Err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raw_frame(body: &str) -> Vec<u8> {
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(body.as_bytes());
        out
    }

    fn sample() -> Message {
        Message::new("event")
            .with_module("log_hunter")
            .with_id("e1")
            .with_payload(json!({"topic": "log_hunter.ioc", "count": 3}))
    }

    #[test]
    fn roundtrip() {
        let msg = sample();
        let frame = encode_frame(&msg).unwrap();
        let mut reader = FrameReader::new();
        reader.feed(&frame);
        assert_eq!(reader.next_message().unwrap(), Some(msg));
        assert_eq!(reader.next_message().unwrap(), None);
    }

    #[test]
    fn header_is_little_endian() {
        let frame = encode_frame(&sample()).unwrap();
        let header: [u8; 4] = frame[..4].try_into().unwrap();
        assert_eq!(u32::from_le_bytes(header) as usize, frame.len() - 4);
    }

    #[test]
    fn byte_by_byte_feed() {
        let msg = sample();
        let frame = encode_frame(&msg).unwrap();
        let mut reader = FrameReader::new();
        let mut got = None;
        for byte in &frame {
            reader.feed(std::slice::from_ref(byte));
            if let Some(m) = reader.next_message().unwrap() {
                got = Some(m);
            }
        }
        assert_eq!(got, Some(msg));
    }

    #[test]
    fn defaults_for_optional_fields() {
        let mut reader = FrameReader::new();
        reader.feed(&raw_frame(r#"{"v":1,"type":"hello"}"#));
        let msg = reader.next_message().unwrap().unwrap();
        assert_eq!(msg.msg_type, "hello");
        assert!(msg.module.is_none() && msg.id.is_none());
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn rejects_zero_length_and_poisons() {
        let mut reader = FrameReader::new();
        reader.feed(&[0, 0, 0, 0]);
        assert_eq!(reader.next_message(), Err(ProtocolError::InvalidLength(0)));
        assert_eq!(reader.next_message(), Err(ProtocolError::Poisoned));
    }

    #[test]
    fn big_endian_header_is_rejected() {
        let mut reader = FrameReader::new();
        reader.feed(&[0, 0, 0, 5]);
        assert!(matches!(
            reader.next_message(),
            Err(ProtocolError::InvalidLength(_))
        ));
    }

    #[test]
    fn rejects_oversized_length() {
        let mut reader = FrameReader::new();
        let len = (MAX_FRAME_BYTES as u32 + 1).to_le_bytes();
        reader.feed(&len);
        assert!(matches!(
            reader.next_message(),
            Err(ProtocolError::InvalidLength(_))
        ));
    }

    #[test]
    fn rejects_invalid_json() {
        let mut reader = FrameReader::new();
        reader.feed(&raw_frame("{not json"));
        assert!(matches!(
            reader.next_message(),
            Err(ProtocolError::InvalidJson(_))
        ));
    }

    #[test]
    fn rejects_bad_envelopes() {
        let bad = [
            r#"{"v":1,"type":"ping","extra":1}"#,
            r#"{"v":2,"type":"ping"}"#,
            r#"{"type":"ping"}"#,
            r#"{"v":1,"type":"Ping"}"#,
            r#"{"v":1,"type":"ping","payload":[]}"#,
            r#"{"v":1,"type":"ping","id":5}"#,
            "[]",
        ];
        for body in bad {
            let mut reader = FrameReader::new();
            reader.feed(&raw_frame(body));
            assert!(
                matches!(reader.next_message(), Err(ProtocolError::InvalidMessage(_))),
                "accepted {body}"
            );
        }
    }

    #[test]
    fn encode_rejects_oversized_message() {
        let blob = "x".repeat(MAX_FRAME_BYTES);
        let msg = Message::new("event").with_payload(json!({ "blob": blob }));
        assert_eq!(encode_frame(&msg), Err(ProtocolError::FrameTooLarge));
    }
}
