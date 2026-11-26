//! Helpers shared by unit tests.

use std::fs;
use std::path::{Path, PathBuf};

/// A temporary directory that is removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let name = format!("vuln_scanner_{tag}_{}", std::process::id());
        let path = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn write(&self, rel: &str, content: &str) {
        let target = self.0.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(target, content).expect("write file");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
