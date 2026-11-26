//! Dockerfile checks: unpinned or end-of-life base images, root user and risky
//! `RUN`/`ADD` patterns.

use crate::report::{Finding, Kind, Severity};

/// Base image reference split into name and tag.
struct ImageRef<'a> {
    name: &'a str,
    tag: Option<&'a str>,
    pinned: bool,
}

fn parse_image(reference: &str) -> ImageRef<'_> {
    if let Some((name, _digest)) = reference.split_once('@') {
        return ImageRef {
            name,
            tag: None,
            pinned: true,
        };
    }
    match reference.rsplit_once(':') {
        Some((name, tag)) if !tag.contains('/') => ImageRef {
            name,
            tag: Some(tag),
            pinned: false,
        },
        _ => ImageRef {
            name: reference,
            tag: None,
            pinned: false,
        },
    }
}

/// Explains why a base image tag is end-of-life. Built-in snapshot, not exhaustive.
fn eol_reason(name: &str, tag: &str) -> Option<&'static str> {
    let short = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
    let first = tag.split(['.', '-']).next().unwrap_or("");
    let major: Option<u32> = first.parse().ok();
    if short == "ubuntu" {
        let release: String = tag.chars().take(5).collect();
        let old = release == "14.04" || release == "16.04" || release == "18.04";
        return old.then_some("Ubuntu release is out of standard support");
    }
    if short == "debian" {
        let old_name = first == "jessie" || first == "stretch" || first == "buster";
        let old_major = major.is_some_and(|m| m <= 10);
        return (old_name || old_major).then_some("Debian release is end-of-life");
    }
    if short == "centos" {
        return major.is_some_and(|m| m <= 8).then_some("CentOS release is end-of-life");
    }
    if short == "python" {
        return major.is_some_and(|m| m == 2).then_some("Python 2 is end-of-life");
    }
    if short == "node" {
        return major.is_some_and(|m| m <= 16).then_some("Node.js release is end-of-life");
    }
    None
}

fn split_instruction(line: &str) -> Option<(String, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (word, rest) = trimmed.split_once(char::is_whitespace).unwrap_or((trimmed, ""));
    Some((word.to_ascii_uppercase(), rest.trim()))
}

fn is_root(args: &str) -> bool {
    let first = args.split(':').next().unwrap_or("");
    let user = first.trim().to_ascii_lowercase();
    user == "root" || user == "0"
}

struct Analyzer<'a> {
    file: &'a str,
    stages: Vec<String>,
    findings: Vec<Finding>,
    last_from: Option<usize>,
    user_ok: bool,
}

impl Analyzer<'_> {
    fn add(&mut self, line: usize, rule: &str, sev: Severity, text: &str) {
        let finding = Finding::new(Kind::Dockerfile, rule, sev, self.file, line, text);
        self.findings.push(finding);
    }

    fn check_from(&mut self, args: &str, line: usize) {
        let mut tokens = args.split_whitespace().filter(|t| !t.starts_with("--"));
        let Some(reference) = tokens.next() else {
            return;
        };
        let keyword = tokens.next();
        let alias = tokens.next();
        let lowered = reference.to_ascii_lowercase();
        let internal = self.stages.contains(&lowered) || lowered == "scratch";
        if !internal && !reference.starts_with('$') {
            self.check_image(reference, line);
        }
        if keyword.is_some_and(|k| k.eq_ignore_ascii_case("as")) {
            if let Some(name) = alias {
                self.stages.push(name.to_ascii_lowercase());
            }
        }
    }

    fn check_image(&mut self, reference: &str, line: usize) {
        let image = parse_image(reference);
        if image.pinned {
            return;
        }
        match image.tag {
            None => {
                let text = "base image has no tag (implicitly :latest)";
                self.add(line, "docker-unpinned-image", Severity::Medium, text);
            }
            Some("latest") => {
                let text = "base image uses the :latest tag";
                self.add(line, "docker-unpinned-image", Severity::Medium, text);
            }
            Some(tag) => {
                if let Some(reason) = eol_reason(image.name, tag) {
                    self.add(line, "docker-eol-image", Severity::High, reason);
                }
            }
        }
    }

    fn check_run(&mut self, args: &str, line: usize) {
        let compact: String = args.split_whitespace().collect();
        let fetches = compact.contains("curl") || compact.contains("wget");
        let piped = compact.contains("|sh") || compact.contains("|bash");
        if fetches && piped {
            let text = "downloads a script and pipes it into a shell";
            self.add(line, "docker-pipe-to-shell", Severity::Medium, text);
        }
        if compact.contains("chmod") && compact.contains("777") {
            let text = "chmod 777 makes files world-writable";
            self.add(line, "docker-chmod-777", Severity::Medium, text);
        }
    }

    fn check_add(&mut self, args: &str, line: usize) {
        let source = args.split_whitespace().find(|a| !a.starts_with("--"));
        let remote = source.is_some_and(|s| s.starts_with("http://") || s.starts_with("https://"));
        if remote {
            let text = "ADD with a remote URL; prefer COPY or a verified download";
            self.add(line, "docker-add-remote-url", Severity::Low, text);
        }
    }
}

/// Analyzes the text of a Dockerfile. `file` only labels the findings.
pub fn analyze(text: &str, file: &str) -> Vec<Finding> {
    let mut analyzer = Analyzer {
        file,
        stages: Vec::new(),
        findings: Vec::new(),
        last_from: None,
        user_ok: false,
    };
    for (idx, raw) in text.lines().enumerate() {
        let Some((instruction, args)) = split_instruction(raw) else {
            continue;
        };
        let line = idx + 1;
        match instruction.as_str() {
            "FROM" => {
                analyzer.check_from(args, line);
                analyzer.last_from = Some(line);
                analyzer.user_ok = false;
            }
            "USER" => analyzer.user_ok = !is_root(args),
            "RUN" => analyzer.check_run(args, line),
            "ADD" => analyzer.check_add(args, line),
            _ => {}
        }
    }
    if let Some(line) = analyzer.last_from {
        if !analyzer.user_ok {
            let text = "final image runs as root (no non-root USER)";
            analyzer.add(line, "docker-runs-as-root", Severity::Low, text);
        }
    }
    analyzer.findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_of(text: &str) -> Vec<String> {
        analyze(text, "Dockerfile").into_iter().map(|f| f.rule).collect()
    }

    fn has(text: &str, rule: &str) -> bool {
        rules_of(text).iter().any(|r| r == rule)
    }

    #[test]
    fn flags_latest_and_untagged_images() {
        assert!(has("FROM ubuntu:latest\nUSER app\n", "docker-unpinned-image"));
        assert!(has("FROM python\nUSER app\n", "docker-unpinned-image"));
        assert!(!has("FROM python:3.12\nUSER app\n", "docker-unpinned-image"));
    }

    #[test]
    fn flags_end_of_life_images() {
        assert!(has("FROM ubuntu:16.04\nUSER app\n", "docker-eol-image"));
        assert!(has("FROM node:16-alpine\nUSER node\n", "docker-eol-image"));
        assert!(has("FROM python:2.7\nUSER app\n", "docker-eol-image"));
        assert!(has("FROM debian:buster-slim\nUSER app\n", "docker-eol-image"));
        assert!(!has("FROM node:22-alpine\nUSER node\n", "docker-eol-image"));
    }

    #[test]
    fn digest_pinned_and_internal_stages_are_fine() {
        assert!(rules_of("FROM ubuntu@sha256:abc\nUSER app\n").is_empty());
        let multi = "FROM golang:1.22 AS build\nRUN go build\nFROM build\nUSER 1000\n";
        assert!(rules_of(multi).is_empty());
        assert!(rules_of("FROM scratch\nUSER 1000\n").is_empty());
        assert!(rules_of("FROM ${BASE}\nUSER 1000\n").is_empty());
    }

    #[test]
    fn root_user_checks_only_the_final_stage() {
        assert!(has("FROM alpine:3.20\n", "docker-runs-as-root"));
        assert!(has("FROM alpine:3.20\nUSER root\n", "docker-runs-as-root"));
        assert!(!has("FROM alpine:3.20\nUSER app:app\n", "docker-runs-as-root"));
        let multi = "FROM alpine:3.20 AS a\nUSER app\nFROM alpine:3.20\n";
        assert!(has(multi, "docker-runs-as-root"));
    }

    #[test]
    fn flags_risky_run_and_add() {
        let text = "FROM alpine:3.20\nUSER app\nRUN curl -sSL https://x.example/i.sh | sh\n";
        assert!(has(text, "docker-pipe-to-shell"));
        assert!(has("FROM alpine:3.20\nUSER a\nRUN chmod -R 777 /app\n", "docker-chmod-777"));
        let add = "FROM alpine:3.20\nUSER a\nADD https://x.example/f.tgz /f\n";
        assert!(has(add, "docker-add-remote-url"));
        assert!(!has("FROM alpine:3.20\nUSER a\nADD app.tgz /app\n", "docker-add-remote-url"));
    }

    #[test]
    fn reports_line_numbers() {
        let findings = analyze("# comment\n\nFROM ubuntu:latest\nUSER app\n", "Dockerfile");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
        assert_eq!(findings[0].file, "Dockerfile");
    }
}
