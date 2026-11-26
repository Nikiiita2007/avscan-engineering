//! File discovery and dispatch: walks paths and runs the right checks per file.

use std::fs;
use std::path::{Path, PathBuf};

use crate::report::Report;
use crate::{dockerfile, manifests, secrets};

/// Limits of one scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    pub max_depth: usize,
    pub max_file_bytes: u64,
    pub max_findings: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_file_bytes: 1024 * 1024,
            max_findings: 500,
        }
    }
}

enum FileKind {
    Dockerfile,
    PackageJson,
    Requirements,
    Config,
}

fn classify(name: &str) -> Option<FileKind> {
    let lower = name.to_ascii_lowercase();
    if lower == "dockerfile" || lower.starts_with("dockerfile.") || lower.ends_with(".dockerfile") {
        return Some(FileKind::Dockerfile);
    }
    if lower == "package.json" {
        return Some(FileKind::PackageJson);
    }
    if lower.starts_with("requirements") && lower.ends_with(".txt") {
        return Some(FileKind::Requirements);
    }
    if lower == ".env" || lower.starts_with(".env.") {
        return Some(FileKind::Config);
    }
    let config = Some(FileKind::Config);
    match Path::new(&lower).extension().and_then(|e| e.to_str()) {
        Some("yml" | "yaml" | "ini" | "cfg" | "conf" | "toml") => config,
        _ => None,
    }
}

fn is_skipped_dir_name(name: &str) -> bool {
    if name == ".git" || name == "node_modules" || name == "target" {
        return true;
    }
    name == ".venv" || name == "venv" || name == "__pycache__"
}

fn scan_file(path: &Path, size: u64, options: &ScanOptions, report: &mut Report) {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let Some(kind) = classify(name) else {
        return;
    };
    if size > options.max_file_bytes {
        report.skipped_files += 1;
        return;
    }
    let Ok(bytes) = fs::read(path) else {
        report.skipped_files += 1;
        return;
    };
    let text = String::from_utf8_lossy(&bytes);
    let shown = path.display().to_string();
    report.scanned_files += 1;
    let mut findings = match kind {
        FileKind::Dockerfile => dockerfile::analyze(&text, &shown),
        FileKind::PackageJson => manifests::analyze_package_json(&text, &shown),
        FileKind::Requirements => manifests::analyze_requirements(&text, &shown),
        FileKind::Config => Vec::new(),
    };
    findings.extend(secrets::scan_text(&text, &shown));
    report.findings.extend(findings);
}

fn visit(path: &Path, depth: usize, options: &ScanOptions, report: &mut Report) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        report.skipped_files += 1;
        return;
    };
    if meta.file_type().is_symlink() {
        report.skipped_files += 1;
        return;
    }
    if !meta.is_dir() {
        scan_file(path, meta.len(), options, report);
        return;
    }
    if depth >= options.max_depth {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        report.skipped_files += 1;
        return;
    };
    let mut children: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    children.sort();
    for child in children {
        let name = child.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if child.is_dir() && is_skipped_dir_name(name) {
            continue;
        }
        visit(&child, depth + 1, options, report);
    }
}

/// Scans files and directories and returns the finished report.
pub fn scan_paths(paths: &[PathBuf], options: &ScanOptions) -> Report {
    let mut report = Report::default();
    for path in paths {
        visit(path, 0, options, &mut report);
    }
    report.finish(options.max_findings);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    const DOCKERFILE: &str = "FROM ubuntu:16.04\nRUN curl -sSL https://x.example/i.sh | sh\n";
    const PACKAGE_JSON: &str = "{\"dependencies\": {\"lodash\": \"^4.17.20\"}}";
    const REQUIREMENTS: &str = "requests==2.25.0\n";

    fn rules(report: &Report) -> Vec<&str> {
        report.findings.iter().map(|f| f.rule.as_str()).collect()
    }

    #[test]
    fn scans_known_files_and_skips_vendored_dirs() {
        let dir = TempDir::new("scan_known");
        dir.write("Dockerfile", DOCKERFILE);
        dir.write("app/package.json", PACKAGE_JSON);
        dir.write("app/requirements.txt", REQUIREMENTS);
        dir.write("app/node_modules/x/package.json", PACKAGE_JSON);
        dir.write("notes.txt", "nothing to see");
        let report = scan_paths(&[dir.path().to_path_buf()], &ScanOptions::default());
        assert_eq!(report.scanned_files, 3);
        let found = rules(&report);
        assert!(found.contains(&"docker-eol-image"));
        assert!(found.contains(&"docker-pipe-to-shell"));
        assert!(found.contains(&"CVE-2021-23337"));
        assert!(found.contains(&"CVE-2023-32681"));
        assert_eq!(found.iter().filter(|r| **r == "CVE-2021-23337").count(), 1);
        assert!(report.has_serious());
    }

    #[test]
    fn finds_secrets_in_config_files() {
        let dir = TempDir::new("scan_secrets");
        dir.write(".env", "DB_PASSWORD=Zx9fQ2mLp7Vb\n");
        dir.write("config/app.yml", "api_key: Qw3rT7yU1oPz\n");
        let report = scan_paths(&[dir.path().to_path_buf()], &ScanOptions::default());
        assert_eq!(report.scanned_files, 2);
        assert_eq!(report.findings.len(), 2);
        assert!(report
            .findings
            .iter()
            .all(|f| f.rule == "generic-credential"));
    }

    #[test]
    fn respects_size_and_depth_limits() {
        let dir = TempDir::new("scan_limits");
        dir.write("Dockerfile", DOCKERFILE);
        dir.write("a/b/Dockerfile", DOCKERFILE);
        let mut options = ScanOptions {
            max_file_bytes: 10,
            ..ScanOptions::default()
        };
        let report = scan_paths(&[dir.path().to_path_buf()], &options);
        assert_eq!(report.scanned_files, 0);
        assert_eq!(report.skipped_files, 2);
        options.max_file_bytes = 1024;
        options.max_depth = 1;
        let report = scan_paths(&[dir.path().to_path_buf()], &options);
        assert_eq!(report.scanned_files, 1);
    }

    #[test]
    fn missing_paths_are_counted_as_skipped() {
        let missing = PathBuf::from("definitely/missing/path");
        let report = scan_paths(&[missing], &ScanOptions::default());
        assert_eq!(report.skipped_files, 1);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn findings_are_capped() {
        let dir = TempDir::new("scan_cap");
        dir.write("Dockerfile", DOCKERFILE);
        let options = ScanOptions {
            max_findings: 1,
            ..ScanOptions::default()
        };
        let report = scan_paths(&[dir.path().to_path_buf()], &options);
        assert_eq!(report.findings.len(), 1);
        assert!(report.truncated);
        assert!(report.summary.high >= 1);
    }

    #[test]
    fn classifies_file_names() {
        assert!(matches!(classify("Dockerfile"), Some(FileKind::Dockerfile)));
        assert!(matches!(
            classify("app.dockerfile"),
            Some(FileKind::Dockerfile)
        ));
        assert!(matches!(
            classify("requirements-dev.txt"),
            Some(FileKind::Requirements)
        ));
        assert!(matches!(classify(".env.local"), Some(FileKind::Config)));
        assert!(classify("main.rs").is_none());
    }
}
