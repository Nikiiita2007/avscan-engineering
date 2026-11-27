//! Shared module helpers. Transport and worker management remain module-local.
//! Path checks preserve current module behavior, not a filesystem sandbox:
//! canonicalization followed by a later open has a race with filesystem changes.

use std::path::PathBuf;

use avscan_protocol::Message;
use serde_json::{json, Value};

/// Collect string entries from a JSON array, ignoring other entries.
pub fn paths_from(value: Option<&Value>) -> Vec<PathBuf> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    items.iter().filter_map(Value::as_str).map(PathBuf::from).collect()
}

/// Resolve paths and require component-wise containment in a usable root.
/// This performs filesystem I/O and does not protect against TOCTOU races.
pub fn check_paths(paths: &[PathBuf], roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    if roots.is_empty() {
        return Err("no usable command_roots are configured".to_string());
    }
    let mut checked = Vec::new();
    for path in paths {
        let real = std::fs::canonicalize(path)
            .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
        if !roots.iter().any(|root| real.starts_with(root)) {
            return Err(format!("{} is outside command_roots", path.display()));
        }
        checked.push(real);
    }
    Ok(checked)
}

/// Build a result using the responding module's identity and request id.
pub fn result_message(module: &str, id: Option<&str>, ok: bool, error: Option<&str>) -> Message {
    let mut payload = json!({ "ok": ok });
    if let Some(text) = error {
        payload["error"] = json!(text);
    }
    let mut message = Message::new("command_result")
        .with_module(module)
        .with_payload(payload);
    message.id = id.map(str::to_string);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_ignore_non_strings() {
        let input = json!(["a", 1, null, "b"]);
        assert_eq!(paths_from(Some(&input)), vec![PathBuf::from("a"), PathBuf::from("b")]);
        assert!(paths_from(None).is_empty());
        assert!(paths_from(Some(&json!({}))).is_empty());
    }

    #[test]
    fn results_keep_identity_and_error() {
        let result = result_message("log_hunter", Some("cmd-1"), false, Some("denied"));
        assert_eq!(result.msg_type, "command_result");
        assert_eq!(result.module.as_deref(), Some("log_hunter"));
        assert_eq!(result.id.as_deref(), Some("cmd-1"));
        assert_eq!(result.payload["ok"], false);
        assert_eq!(result.payload["error"], "denied");
        let result = result_message("log_hunter", None, true, None);
        assert!(result.id.is_none());
        assert!(!result.payload.contains_key("error"));
    }

    #[test]
    fn containment_uses_path_components() {
        let current = std::env::current_dir().unwrap();
        let roots = vec![current.clone()];
        let checked = check_paths(&[current.clone()], &roots).unwrap();
        assert_eq!(checked, vec![std::fs::canonicalize(&current).unwrap()]);
        assert!(check_paths(&[current.clone()], &[]).is_err());
        if let Some(parent) = current.parent() {
            assert!(check_paths(&[parent.to_path_buf()], &roots).is_err());
        }
    }
}
