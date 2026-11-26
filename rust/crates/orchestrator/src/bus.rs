//! In-process event bus shared by all module sessions.

use serde_json::Value;
use tokio::sync::broadcast;

/// Number of events buffered per subscriber before the slowest one lags.
pub const BUS_CAPACITY: usize = 1024;

/// One event published by a module.
#[derive(Debug, Clone, PartialEq)]
pub struct BusEvent {
    pub topic: String,
    pub data: Value,
    /// Id of the module that published the event.
    pub source: String,
}

/// Creates a new bus. Subscribers are created with `Sender::subscribe`.
pub fn new_bus() -> broadcast::Sender<BusEvent> {
    broadcast::channel(BUS_CAPACITY).0
}

/// Does `pattern` (`a.b` or `a.b.*`) match `topic`? `a.*` matches `a` and
/// everything below `a.` (same rule as the C++ host).
pub fn topic_matches(pattern: &str, topic: &str) -> bool {
    match pattern.strip_suffix(".*") {
        Some(base) => {
            let below = topic.strip_prefix(base).is_some_and(|r| r.starts_with('.'));
            topic == base || below
        }
        None => pattern == topic,
    }
}

/// Is `topic` matched by at least one of `patterns`?
pub fn topic_allowed(patterns: &[String], topic: &str) -> bool {
    patterns.iter().any(|p| topic_matches(p, topic))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_topics_match_only_themselves() {
        assert!(topic_matches("a.b", "a.b"));
        assert!(!topic_matches("a.b", "a.b.c"));
        assert!(!topic_matches("a.b", "a"));
    }

    #[test]
    fn wildcard_matches_base_and_children() {
        assert!(topic_matches("a.*", "a"));
        assert!(topic_matches("a.*", "a.b"));
        assert!(topic_matches("a.*", "a.b.c"));
    }

    #[test]
    fn wildcard_does_not_match_partial_segments() {
        assert!(!topic_matches("a.*", "ab"));
        assert!(!topic_matches("a.*", "b.a"));
    }

    #[test]
    fn allowed_checks_every_pattern() {
        let patterns = vec!["x.one".to_string(), "y.*".to_string()];
        assert!(topic_allowed(&patterns, "x.one"));
        assert!(topic_allowed(&patterns, "y.deep.topic"));
        assert!(!topic_allowed(&patterns, "x.two"));
    }
}
