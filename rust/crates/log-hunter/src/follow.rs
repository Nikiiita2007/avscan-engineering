//! Follows a growing log file (like `tail -f`), including truncation and
//! rotation, and feeds new lines to a [`Hunter`].

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::alert::Alert;
use crate::hunter::Hunter;
use crate::rules::Rules;

const MAX_READ: u64 = 1 << 20;
const MAX_PENDING: usize = 64 * 1024;

/// Receiver of alerts; called from the follower thread.
pub type AlertSink = Arc<dyn Fn(&Alert) + Send + Sync>;
/// Receiver of progress and error messages.
pub type Notify = Arc<dyn Fn(&str) + Send + Sync>;

/// Calls the sink with an alert.
pub fn emit(sink: &AlertSink, alert: &Alert) {
    let callback = sink.as_ref();
    callback(alert);
}

fn say(notify: &Notify, text: &str) {
    let callback = notify.as_ref();
    callback(text);
}

/// Reads what was appended since `offset` and returns the complete lines.
/// A shrinking file (rotation or truncation) restarts at the beginning.
pub fn read_new(path: &Path, offset: &mut u64, pending: &mut Vec<u8>) -> io::Result<Vec<String>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len < *offset {
        *offset = 0;
        pending.clear();
    }
    file.seek(SeekFrom::Start(*offset))?;
    let mut chunk = Vec::new();
    let read = file.take(MAX_READ).read_to_end(&mut chunk)?;
    *offset += read as u64;
    pending.extend_from_slice(&chunk);
    let mut lines = Vec::new();
    while let Some(pos) = pending.iter().position(|b| *b == b'\n') {
        let raw: Vec<u8> = pending.drain(..=pos).collect();
        lines.push(String::from_utf8_lossy(&raw).trim_end().to_string());
    }
    if pending.len() > MAX_PENDING {
        pending.clear();
    }
    Ok(lines)
}

struct Job {
    path: PathBuf,
    rules: Rules,
    sink: AlertSink,
    notify: Notify,
}

fn sleep_unless_stopped(stop: &AtomicBool) {
    for _ in 0..5 {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        thread::sleep(Duration::from_millis(40));
    }
}

fn follow_loop(job: &Job, stop: &AtomicBool) {
    let mut hunter = Hunter::new(job.rules.clone());
    let mut offset = 0u64;
    let mut pending = Vec::new();
    let mut failing = false;
    let mut announced = false;
    while !stop.load(Ordering::Relaxed) {
        match read_new(&job.path, &mut offset, &mut pending) {
            Ok(lines) => {
                failing = false;
                for line in lines {
                    if let Some(alerts) = hunter.feed_line(&line) {
                        for alert in alerts {
                            emit(&job.sink, &alert);
                        }
                    }
                }
                if !announced {
                    announced = true;
                    say(&job.notify, &format!("following {}", job.path.display()));
                }
            }
            Err(e) => {
                if !failing {
                    failing = true;
                    say(&job.notify, &format!("cannot read {}: {e}", job.path.display()));
                }
            }
        }
        sleep_unless_stopped(stop);
    }
}

/// A running follower. Dropping it stops the thread.
pub struct Follower {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Follower {
    /// Starts following `path`; the file is read from the beginning first.
    pub fn start(path: PathBuf, rules: Rules, sink: AlertSink, notify: Notify) -> Self {
        let job = Job {
            path,
            rules,
            sink,
            notify,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || follow_loop(&job, &thread_stop));
        Self {
            stop,
            handle: Some(handle),
        }
    }

    /// Stops the thread and waits for it.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Follower {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{append, failed, TempDir};
    use std::sync::{mpsc, Mutex};

    fn channel_sink() -> (AlertSink, mpsc::Receiver<Alert>) {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let sink: AlertSink = Arc::new(move |alert: &Alert| {
            let _ = tx.lock().unwrap().send(alert.clone());
        });
        (sink, rx)
    }

    fn silent() -> Notify {
        Arc::new(|_text: &str| {})
    }

    #[test]
    fn read_new_returns_only_complete_lines() {
        let dir = TempDir::new("follow_read");
        dir.write("a.log", "one\ntw");
        let path = dir.path().join("a.log");
        let mut offset = 0;
        let mut pending = Vec::new();
        assert_eq!(read_new(&path, &mut offset, &mut pending).unwrap(), ["one"]);
        append(&path, "o\nthree\n");
        let lines = read_new(&path, &mut offset, &mut pending).unwrap();
        assert_eq!(lines, ["two", "three"]);
        assert!(read_new(&path, &mut offset, &mut pending).unwrap().is_empty());
    }

    #[test]
    fn read_new_restarts_after_truncation() {
        let dir = TempDir::new("follow_rotate");
        dir.write("a.log", "aaaaaaaa\n");
        let path = dir.path().join("a.log");
        let mut offset = 0;
        let mut pending = Vec::new();
        assert_eq!(read_new(&path, &mut offset, &mut pending).unwrap().len(), 1);
        dir.write("a.log", "b\n");
        let lines = read_new(&path, &mut offset, &mut pending).unwrap();
        assert_eq!(lines, ["b"]);
    }

    #[test]
    fn read_new_reports_missing_files() {
        let mut offset = 0;
        let mut pending = Vec::new();
        let result = read_new(Path::new("definitely/missing.log"), &mut offset, &mut pending);
        assert!(result.is_err());
    }

    #[test]
    fn follower_alerts_on_lines_appended_later() {
        let dir = TempDir::new("follow_live");
        dir.write("auth.log", &(failed(0, 0, "203.0.113.5", "root") + &failed(0, 1, "203.0.113.5", "root")));
        let path = dir.path().join("auth.log");
        let (sink, rx) = channel_sink();
        let mut follower = Follower::start(path.clone(), Rules::default(), sink, silent());
        thread::sleep(Duration::from_millis(300));
        let more: String = (2..5).map(|s| failed(0, s, "203.0.113.5", "root")).collect();
        append(&path, &more);
        let alert = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(alert.rule, "ssh-bruteforce");
        follower.shutdown();
    }

    #[test]
    fn follower_reports_unreadable_files_once() {
        let (sink, _rx) = channel_sink();
        let (tx, notes) = mpsc::channel();
        let tx = Mutex::new(tx);
        let notify: Notify = Arc::new(move |text: &str| {
            let _ = tx.lock().unwrap().send(text.to_string());
        });
        let missing = PathBuf::from("definitely/missing.log");
        let mut follower = Follower::start(missing, Rules::default(), sink, notify);
        let first = notes.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(first.contains("cannot read"));
        thread::sleep(Duration::from_millis(500));
        assert!(notes.try_recv().is_err());
        follower.shutdown();
    }
}
