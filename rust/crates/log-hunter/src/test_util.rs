//! Helpers shared by unit tests.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// A temporary directory that is removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let name = format!("log_hunter_{tag}_{}", std::process::id());
        let path = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn write(&self, rel: &str, content: &str) {
        fs::write(self.0.join(rel), content).expect("write file");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn append(path: &Path, text: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open for append");
    file.write_all(text.as_bytes()).expect("append");
}

/// A failed sshd password line at 14:`min`:`sec` on Nov 26.
pub fn failed(min: u32, sec: u32, ip: &str, user: &str) -> String {
    format!(
        "Nov 26 14:{min:02}:{sec:02} srv sshd[7]: Failed password for {user} from {ip} port 22\n"
    )
}
