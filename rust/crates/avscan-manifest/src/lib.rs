//! Parsing and strict validation of `module.json`.
//!
//! Mirrors `libs/host/manifest.hpp`: unknown fields are errors and every
//! problem found is reported, not just the first one.

use std::collections::HashSet;

use serde_json::{Map, Value};
use thiserror::Error;

/// Module API version implemented by the host.
pub const HOST_API_VERSION: i64 = 1;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const TOP_LEVEL_KEYS: [&str; 11] = [
    "id",
    "name",
    "version",
    "api_version",
    "description",
    "entry",
    "capabilities",
    "permissions",
    "events",
    "restart",
    "config",
];
const ALLOWED_PERMISSIONS: [&str; 8] = [
    "fs.read",
    "fs.write",
    "net.local",
    "net.outbound",
    "net.capture",
    "process.spawn",
    "admin",
    "etw",
];
const ID_MSG: &str = "id: lowercase letters, digits, '_' and '.', 3..64 characters";
const EXE_MSG: &str = "entry.exe: must be a relative path inside the module directory";
const ARGS_MSG: &str = "entry.args: printable, at most 260 characters each";
const POLICY_MSG: &str = "restart.policy: must be 'never' or 'on_failure'";
const RESTARTS_MSG: &str = "restart.max_restarts: integer 0..10 required";

/// All validation problems found in one manifest.
#[derive(Debug, Error)]
#[error("invalid manifest: {}", .0.join("; "))]
pub struct ManifestError(pub Vec<String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    Never,
    OnFailure,
}

/// A validated module manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub api_version: i64,
    pub exe: String,
    pub args: Vec<String>,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
    pub publishes: Vec<String>,
    pub subscribes: Vec<String>,
    pub restart_policy: RestartPolicy,
    pub max_restarts: u32,
    pub config: Map<String, Value>,
}

fn has_control(s: &str) -> bool {
    s.chars().any(|c| c < ' ' || c == '\u{7f}')
}

fn valid_segment(seg: &str) -> bool {
    let mut chars = seg.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    seg.len() <= 32 && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Module id: 1..8 segments separated by '.', total length 3..64.
pub fn valid_id(s: &str) -> bool {
    (3..=64).contains(&s.len()) && s.split('.').count() <= 8 && s.split('.').all(valid_segment)
}

/// Capability or topic name: `[a-z][a-z0-9_]*(.[a-z0-9_]+)*`, up to 64 chars.
pub fn valid_name(s: &str) -> bool {
    let first_ok = s.chars().next().is_some_and(|c| c.is_ascii_lowercase());
    let chars_ok = s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.');
    first_ok && chars_ok && s.len() <= 64 && !s.contains("..") && !s.ends_with('.')
}

/// Topic pattern: a name, optionally followed by `.*`.
pub fn valid_pattern(s: &str) -> bool {
    match s.strip_suffix(".*") {
        Some(base) => valid_name(base),
        None => valid_name(s),
    }
}

/// MAJOR.MINOR.PATCH, numeric, no leading zeros.
pub fn valid_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            let digits = p.chars().all(|c| c.is_ascii_digit());
            digits && (1..=9).contains(&p.len()) && (p.len() == 1 || !p.starts_with('0'))
        })
}

/// Relative executable path without `..`, drive letters or reserved chars.
pub fn valid_exe(s: &str) -> bool {
    if s.is_empty() || s.len() > 200 || has_control(s) || s.contains(':') {
        return false;
    }
    if s.starts_with('/') || s.starts_with('\\') {
        return false;
    }
    s.split(['/', '\\']).all(|seg| {
        let special = seg.is_empty() || seg == "." || seg == "..";
        let bad_end = seg.ends_with('.') || seg.ends_with(' ');
        let reserved = seg.contains(['<', '>', '"', '|', '?', '*']);
        !special && !bad_end && !reserved
    })
}

fn has_duplicates(list: &[String]) -> bool {
    let mut seen = HashSet::new();
    list.iter().any(|s| !seen.insert(s))
}

fn read_string(
    obj: &Map<String, Value>,
    key: &str,
    required: bool,
    errs: &mut Vec<String>,
) -> Option<String> {
    match obj.get(key) {
        None => {
            if required {
                errs.push(format!("{key}: required"));
            }
            None
        }
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            errs.push(format!("{key}: must be a string"));
            None
        }
    }
}

fn string_list(
    value: Option<&Value>,
    what: &str,
    max: usize,
    errs: &mut Vec<String>,
) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        errs.push(format!("{what}: must be an array of strings"));
        return Vec::new();
    };
    if items.len() > max {
        errs.push(format!("{what}: too many entries"));
        return Vec::new();
    }
    let mut out = Vec::new();
    for item in items {
        match item.as_str() {
            Some(s) => out.push(s.to_string()),
            None => {
                errs.push(format!("{what}: entries must be strings"));
                return Vec::new();
            }
        }
    }
    out
}

fn reject_unknown(obj: &Map<String, Value>, allowed: &[&str], what: &str, errs: &mut Vec<String>) {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            errs.push(format!("{what}: unknown field '{key}'"));
        }
    }
}

/// Parses and validates a manifest. `host_api` is the module API version the
/// host implements.
pub fn parse_manifest(text: &str, host_api: i64) -> Result<Manifest, ManifestError> {
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError(vec!["manifest is too large".to_string()]));
    }
    let value: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => return Err(ManifestError(vec![format!("invalid JSON: {e}")])),
    };
    let Some(obj) = value.as_object() else {
        return Err(ManifestError(vec![
            "manifest must be a JSON object".to_string()
        ]));
    };
    let mut errs: Vec<String> = Vec::new();
    reject_unknown(obj, &TOP_LEVEL_KEYS, "manifest", &mut errs);

    let id = read_string(obj, "id", true, &mut errs);
    if let Some(id) = &id {
        if !valid_id(id) {
            errs.push(ID_MSG.to_string());
        }
    }
    let name = read_string(obj, "name", true, &mut errs);
    if let Some(name) = &name {
        if name.is_empty() || name.len() > 100 || has_control(name) {
            errs.push("name: 1..100 printable characters required".to_string());
        }
    }
    let version = read_string(obj, "version", true, &mut errs);
    if let Some(version) = &version {
        if !valid_version(version) {
            errs.push("version: must be MAJOR.MINOR.PATCH".to_string());
        }
    }
    let description = read_string(obj, "description", false, &mut errs);
    if let Some(d) = &description {
        if d.len() > 500 || has_control(d) {
            errs.push("description: at most 500 printable characters".to_string());
        }
    }

    let mut api_version = 0;
    match obj.get("api_version") {
        None => errs.push("api_version: required".to_string()),
        Some(v) => match v.as_i64() {
            Some(n) if n == host_api => api_version = n,
            Some(n) => errs.push(format!("api_version: unsupported {n}")),
            None => errs.push("api_version: must be an integer".to_string()),
        },
    }

    let mut exe = String::new();
    let mut args = Vec::new();
    match obj.get("entry") {
        None => errs.push("entry: required".to_string()),
        Some(Value::Object(entry)) => {
            reject_unknown(entry, &["exe", "args"], "entry", &mut errs);
            match entry.get("exe").and_then(Value::as_str) {
                Some(path) if valid_exe(path) => exe = path.to_string(),
                Some(_) => errs.push(EXE_MSG.to_string()),
                None => errs.push("entry.exe: required string".to_string()),
            }
            args = string_list(entry.get("args"), "entry.args", 32, &mut errs);
            if args.iter().any(|a| a.len() > 260 || has_control(a)) {
                errs.push(ARGS_MSG.to_string());
            }
        }
        Some(_) => errs.push("entry: must be an object".to_string()),
    }

    let capabilities = string_list(obj.get("capabilities"), "capabilities", 64, &mut errs);
    for c in capabilities.iter().filter(|c| !valid_name(c)) {
        errs.push(format!("capabilities: invalid name '{c}'"));
    }
    let permissions = string_list(obj.get("permissions"), "permissions", 16, &mut errs);
    for p in permissions
        .iter()
        .filter(|p| !ALLOWED_PERMISSIONS.contains(&p.as_str()))
    {
        errs.push(format!("permissions: unknown permission '{p}'"));
    }

    let mut publishes = Vec::new();
    let mut subscribes = Vec::new();
    match obj.get("events") {
        None => {}
        Some(Value::Object(ev)) => {
            reject_unknown(ev, &["publishes", "subscribes"], "events", &mut errs);
            publishes = string_list(ev.get("publishes"), "events.publishes", 64, &mut errs);
            subscribes = string_list(ev.get("subscribes"), "events.subscribes", 64, &mut errs);
        }
        Some(_) => errs.push("events: must be an object".to_string()),
    }
    let own_id = id.as_deref().unwrap_or("");
    for topic in &publishes {
        if !valid_pattern(topic) {
            errs.push(format!("events.publishes: invalid topic '{topic}'"));
            continue;
        }
        let base = topic.strip_suffix(".*").unwrap_or(topic.as_str());
        let own = base == own_id || base.starts_with(&format!("{own_id}."));
        if !own_id.is_empty() && !own {
            errs.push(format!(
                "events.publishes: '{topic}' must start with the module id"
            ));
        }
    }
    for topic in subscribes.iter().filter(|t| !valid_pattern(t)) {
        errs.push(format!("events.subscribes: invalid topic '{topic}'"));
    }
    let lists = [
        ("capabilities", &capabilities),
        ("permissions", &permissions),
        ("events.publishes", &publishes),
        ("events.subscribes", &subscribes),
    ];
    for (what, list) in lists {
        if has_duplicates(list) {
            errs.push(format!("{what}: duplicate entries"));
        }
    }

    let mut restart_policy = RestartPolicy::Never;
    let mut max_restarts: u32 = 0;
    match obj.get("restart") {
        None => {}
        Some(Value::Object(rs)) => {
            reject_unknown(rs, &["policy", "max_restarts"], "restart", &mut errs);
            match rs.get("policy").map(Value::as_str) {
                None | Some(Some("never")) => {}
                Some(Some("on_failure")) => restart_policy = RestartPolicy::OnFailure,
                Some(_) => errs.push(POLICY_MSG.to_string()),
            }
            match rs.get("max_restarts").map(Value::as_u64) {
                None => {}
                Some(Some(n)) if n <= 10 => max_restarts = n as u32,
                Some(_) => errs.push(RESTARTS_MSG.to_string()),
            }
        }
        Some(_) => errs.push("restart: must be an object".to_string()),
    }

    let config = match obj.get("config") {
        None => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => {
            errs.push("config: must be an object".to_string());
            Map::new()
        }
    };

    if !errs.is_empty() {
        return Err(ManifestError(errs));
    }
    Ok(Manifest {
        id: id.unwrap_or_default(),
        name: name.unwrap_or_default(),
        version: version.unwrap_or_default(),
        description: description.unwrap_or_default(),
        api_version,
        exe,
        args,
        capabilities,
        permissions,
        publishes,
        subscribes,
        restart_policy,
        max_restarts,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET_ANALYZER: &str = r#"{
  "id": "net_analyzer",
  "name": "Network analyzer",
  "version": "0.1.0",
  "api_version": 1,
  "entry": { "exe": "net-analyzer.exe", "args": [] },
  "capabilities": ["net.analyze", "report.mask_sensitive"],
  "permissions": ["net.capture", "fs.write", "admin"],
  "events": {
    "publishes": ["net_analyzer.alert", "net_analyzer.log"],
    "subscribes": ["host.shutdown"]
  },
  "restart": { "policy": "never", "max_restarts": 0 },
  "config": { "mode": "passive", "mask_secrets": true }
}"#;

    fn errors_of(text: &str) -> Vec<String> {
        parse_manifest(text, HOST_API_VERSION).unwrap_err().0
    }

    fn assert_error(text: &str, needle: &str) {
        let errs = errors_of(text);
        assert!(errs.iter().any(|e| e.contains(needle)), "{errs:?}");
    }

    #[test]
    fn parses_existing_net_analyzer_manifest() {
        let m = parse_manifest(NET_ANALYZER, HOST_API_VERSION).unwrap();
        assert_eq!(m.id, "net_analyzer");
        assert_eq!(m.exe, "net-analyzer.exe");
        assert_eq!(m.publishes, ["net_analyzer.alert", "net_analyzer.log"]);
        assert_eq!(m.restart_policy, RestartPolicy::Never);
        assert_eq!(
            m.config.get("mode").and_then(Value::as_str),
            Some("passive")
        );
    }

    #[test]
    fn parses_on_failure_policy() {
        let text = NET_ANALYZER.replace(
            r#""policy": "never", "max_restarts": 0"#,
            r#""policy": "on_failure", "max_restarts": 3"#,
        );
        let m = parse_manifest(&text, HOST_API_VERSION).unwrap();
        assert_eq!(m.restart_policy, RestartPolicy::OnFailure);
        assert_eq!(m.max_restarts, 3);
    }

    #[test]
    fn rejects_unknown_field() {
        let text = NET_ANALYZER.replace(r#""api_version": 1,"#, r#""api_version": 1, "x": 1,"#);
        assert_error(&text, "unknown field 'x'");
    }

    #[test]
    fn rejects_wrong_api_version() {
        let text = NET_ANALYZER.replace(r#""api_version": 1"#, r#""api_version": 2"#);
        assert_error(&text, "api_version");
    }

    #[test]
    fn rejects_path_traversal_in_exe() {
        let text = NET_ANALYZER.replace("net-analyzer.exe", "../evil.exe");
        assert_error(&text, "entry.exe");
    }

    #[test]
    fn rejects_foreign_topic() {
        let text = NET_ANALYZER.replace("net_analyzer.alert", "antivirus.alert");
        assert_error(&text, "must start with the module id");
    }

    #[test]
    fn rejects_bad_version_permission_and_restarts() {
        let text = NET_ANALYZER
            .replace("0.1.0", "1.0")
            .replace("admin", "root")
            .replace(r#""max_restarts": 0"#, r#""max_restarts": 11"#);
        let errs = errors_of(&text);
        assert!(errs.iter().any(|e| e.starts_with("version")));
        assert!(errs.iter().any(|e| e.contains("unknown permission")));
        assert!(errs.iter().any(|e| e.starts_with("restart.max_restarts")));
    }

    #[test]
    fn rejects_duplicates() {
        let text = NET_ANALYZER.replace(
            r#"["host.shutdown"]"#,
            r#"["host.shutdown", "host.shutdown"]"#,
        );
        assert_error(&text, "duplicate entries");
    }

    #[test]
    fn rejects_non_objects_and_bad_json() {
        assert_error("[]", "JSON object");
        assert_error("{oops", "invalid JSON");
    }

    #[test]
    fn id_rules() {
        assert!(valid_id("net.analyzer"));
        assert!(valid_id("antivirus"));
        assert!(!valid_id("ab"));
        assert!(!valid_id("Net"));
        assert!(!valid_id("a..b"));
    }
}
