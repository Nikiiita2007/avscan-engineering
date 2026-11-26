//! Localhost listener: accepts TCP connections that stream a pcap capture
//! (for example `tcpdump -U -w - | nc 127.0.0.1 9099`) and analyzes them live.

use std::io::{self, Read};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::alert::Alert;
use crate::analyzer::analyze_reader;
use crate::rules::Rules;

const MAX_CONNECTIONS: usize = 8;

/// Receiver of alerts; called from worker threads.
pub type AlertSink = Arc<dyn Fn(&Alert) + Send + Sync>;

/// Calls the sink with an alert.
pub fn emit(sink: &AlertSink, alert: &Alert) {
    let callback = sink.as_ref();
    callback(alert);
}

fn is_timeout(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut
}

/// Reader that turns read timeouts into an end of stream once `stop` is set.
struct StopReader {
    inner: TcpStream,
    stop: Arc<AtomicBool>,
}

impl Read for StopReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.inner.read(buf) {
                Err(e) if is_timeout(&e) => {
                    if self.stop.load(Ordering::Relaxed) {
                        return Ok(0);
                    }
                }
                other => return other,
            }
        }
    }
}

fn serve(stream: TcpStream, rules: &Rules, sink: &AlertSink, stop: &Arc<AtomicBool>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let reader = StopReader {
        inner: stream,
        stop: Arc::clone(stop),
    };
    let _ = analyze_reader(reader, rules, |alert| emit(sink, &alert));
}

fn accept_loop(listener: &TcpListener, rules: &Rules, sink: &AlertSink, stop: &Arc<AtomicBool>) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                workers.retain(|w| !w.is_finished());
                if workers.len() >= MAX_CONNECTIONS {
                    continue;
                }
                let rules = rules.clone();
                let sink = Arc::clone(sink);
                let stop = Arc::clone(stop);
                workers.push(thread::spawn(move || serve(stream, &rules, &sink, &stop)));
            }
            Err(e) if is_timeout(&e) => thread::sleep(Duration::from_millis(25)),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}

/// A running listener. Dropping it stops the accept loop and all connections.
pub struct Listener {
    /// The bound address (useful when port 0 was requested).
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Listener {
    /// Binds `addr`, which must be a loopback address, and starts accepting.
    pub fn start(addr: SocketAddr, rules: Rules, sink: AlertSink) -> io::Result<Self> {
        if !addr.ip().is_loopback() {
            let kind = io::ErrorKind::InvalidInput;
            return Err(io::Error::new(
                kind,
                "listen address must be a loopback address",
            ));
        }
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let local = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || accept_loop(&listener, &rules, &sink, &thread_stop));
        Ok(Self {
            addr: local,
            stop,
            handle: Some(handle),
        })
    }

    /// Stops accepting and waits for the worker threads.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::LINKTYPE_ETHERNET;
    use crate::test_util::{pcap_file, tcp_frame};
    use std::io::Write;
    use std::sync::{mpsc, Mutex};

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn channel_sink() -> (AlertSink, mpsc::Receiver<Alert>) {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let sink: AlertSink = Arc::new(move |alert: &Alert| {
            let _ = tx.lock().unwrap().send(alert.clone());
        });
        (sink, rx)
    }

    #[test]
    fn analyzes_a_pcap_stream_from_localhost() {
        let (sink, rx) = channel_sink();
        let mut listener = Listener::start(loopback(), Rules::default(), sink).unwrap();
        let frame = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], (5000, 4444), 0x02);
        let capture = pcap_file(LINKTYPE_ETHERNET, &[(1.0, frame)]);
        let mut stream = TcpStream::connect(listener.addr).unwrap();
        stream.write_all(&capture).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let alert = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(alert.rule, "suspicious-port");
        listener.shutdown();
    }

    #[test]
    fn refuses_non_loopback_addresses() {
        let (sink, _rx) = channel_sink();
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let error = Listener::start(addr, Rules::default(), sink).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn shutdown_does_not_hang_on_idle_connections() {
        let (sink, _rx) = channel_sink();
        let mut listener = Listener::start(loopback(), Rules::default(), sink).unwrap();
        let _idle = TcpStream::connect(listener.addr).unwrap();
        thread::sleep(Duration::from_millis(100));
        listener.shutdown();
    }

    #[test]
    fn garbage_streams_are_ignored() {
        let (sink, rx) = channel_sink();
        let mut listener = Listener::start(loopback(), Rules::default(), sink).unwrap();
        let mut stream = TcpStream::connect(listener.addr).unwrap();
        stream
            .write_all(&[
                0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                18, 19, 20, 21, 22, 23, 24,
            ])
            .unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
        listener.shutdown();
    }
}
