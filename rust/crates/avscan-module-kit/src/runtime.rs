//! Frame input, a shared frame writer and a bounded worker pool.

use std::fmt;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use avscan_protocol::{encode_frame, FrameReader, Message, ProtocolError};
use serde_json::{json, Value};

/// Errors of the shared runtime pieces. A module maps them into its own error type.
#[derive(Debug)]
pub enum KitError {
    Io(std::io::Error),
    Protocol(ProtocolError),
    Poisoned,
}

impl fmt::Display for KitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::Poisoned => write!(f, "output lock poisoned"),
        }
    }
}

impl std::error::Error for KitError {}

impl From<std::io::Error> for KitError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for KitError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Next message, or `None` when the input is closed.
pub fn recv<R: Read>(input: &mut R, frames: &mut FrameReader) -> Result<Option<Message>, KitError> {
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

/// Shared, thread-safe frame writer. Clones write to the same output.
#[derive(Clone)]
pub struct Out {
    inner: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl Out {
    pub fn new(output: Box<dyn Write + Send>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(output)),
        }
    }

    /// Writes one frame and flushes. Frames of different threads never interleave.
    pub fn send(&self, msg: &Message) -> Result<(), KitError> {
        let frame = encode_frame(msg)?;
        let mut out = self.inner.lock().map_err(|_| KitError::Poisoned)?;
        out.write_all(&frame)?;
        out.flush()?;
        Ok(())
    }

    /// Writes an `event` frame for `topic` with the identity of `module`.
    pub fn event(&self, module: &str, topic: &str, data: Value) -> Result<(), KitError> {
        let message = Message::new("event")
            .with_module(module)
            .with_payload(json!({ "topic": topic, "data": data }));
        self.send(&message)
    }
}

/// Worker threads with a limit on how many run at the same time. Only one
/// thread (the protocol thread) may call `try_acquire` and `spawn`, so the
/// counter needs no compare-and-swap.
pub struct Workers {
    limit: usize,
    handles: Vec<JoinHandle<()>>,
    active: Arc<AtomicUsize>,
}

impl Workers {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            handles: Vec::new(),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Reserves a slot; false when `limit` jobs are already running. A
    /// successful call must be followed by `spawn`.
    pub fn try_acquire(&self) -> bool {
        if self.active.load(Ordering::SeqCst) >= self.limit {
            return false;
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        true
    }

    /// Runs `job` on a new thread and frees the reserved slot afterwards.
    pub fn spawn(&mut self, job: impl FnOnce() + Send + 'static) {
        self.handles.retain(|handle| !handle.is_finished());
        let active = Arc::clone(&self.active);
        self.handles.push(std::thread::spawn(move || {
            job();
            active.fetch_sub(1, Ordering::SeqCst);
        }));
    }

    /// Number of reserved or running jobs.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Waits for every running job.
    pub fn join_all(&mut self) {
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

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

    /// Input that returns at most `step` bytes per read.
    struct Chunked {
        data: Vec<u8>,
        step: usize,
    }

    impl Read for Chunked {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.data.len().min(self.step).min(buf.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data.drain(..n);
            Ok(n)
        }
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

    #[test]
    fn recv_reads_frames_split_across_reads() {
        let first = Message::new("ping").with_module("m").with_id("p1");
        let second = Message::new("stop").with_module("m");
        let mut bytes = Vec::new();
        bytes.extend(encode_frame(&first).unwrap());
        bytes.extend(encode_frame(&second).unwrap());
        let mut input = Chunked {
            data: bytes,
            step: 3,
        };
        let mut frames = FrameReader::new();
        let a = recv(&mut input, &mut frames).unwrap().unwrap();
        assert_eq!(a.msg_type, "ping");
        assert_eq!(a.id.as_deref(), Some("p1"));
        let b = recv(&mut input, &mut frames).unwrap().unwrap();
        assert_eq!(b.msg_type, "stop");
        assert!(recv(&mut input, &mut frames).unwrap().is_none());
    }

    #[test]
    fn out_writes_frames_and_events() {
        let buf = SharedBuf::default();
        let out = Out::new(Box::new(buf.clone()));
        out.event("log_hunter", "log_hunter.log", json!({ "message": "x" }))
            .unwrap();
        out.send(&Message::new("pong").with_module("log_hunter"))
            .unwrap();
        let messages = decode_all(&buf.0.lock().unwrap().clone());
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].msg_type, "event");
        assert_eq!(messages[0].module.as_deref(), Some("log_hunter"));
        assert_eq!(messages[0].payload["topic"], "log_hunter.log");
        assert_eq!(messages[0].payload["data"]["message"], "x");
        assert_eq!(messages[1].msg_type, "pong");
    }

    #[test]
    fn out_is_shared_between_threads() {
        let buf = SharedBuf::default();
        let out = Out::new(Box::new(buf.clone()));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let out = out.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        out.send(&Message::new("pong").with_module("m")).unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let messages = decode_all(&buf.0.lock().unwrap().clone());
        assert_eq!(messages.len(), 100);
        assert!(messages.iter().all(|m| m.msg_type == "pong"));
    }

    #[test]
    fn the_number_of_running_jobs_is_bounded() {
        let workers = Workers::new(4);
        for _ in 0..4 {
            assert!(workers.try_acquire());
        }
        assert!(!workers.try_acquire());
        workers.active.fetch_sub(1, Ordering::SeqCst);
        assert!(workers.try_acquire());
    }

    #[test]
    fn workers_free_their_slot_and_are_joined() {
        let mut workers = Workers::new(2);
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(workers.try_acquire());
        workers.spawn(move || {
            tx.send(7).unwrap();
        });
        workers.join_all();
        assert_eq!(rx.recv().unwrap(), 7);
        assert_eq!(workers.active(), 0);
    }
}
