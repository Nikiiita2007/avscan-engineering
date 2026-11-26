//! Alerts produced by the analyzer.

use std::net::IpAddr;

use serde::Serialize;

/// Alert severity, ordered from least to most serious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// One detected anomaly.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    pub rule: String,
    pub severity: Severity,
    /// Capture time in seconds since the epoch.
    pub timestamp: f64,
    pub src: String,
    pub dst: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Alert {
    pub fn new(
        rule: &str,
        severity: Severity,
        timestamp: f64,
        src: IpAddr,
        dst: IpAddr,
        message: &str,
    ) -> Self {
        Self {
            rule: rule.to_string(),
            severity,
            timestamp,
            src: src.to_string(),
            dst: dst.to_string(),
            message: message.to_string(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: String) -> Self {
        self.detail = Some(detail);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_without_empty_detail() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let alert = Alert::new("r", Severity::High, 1.5, ip, ip, "m");
        let value = serde_json::to_value(&alert).unwrap();
        assert_eq!(value["severity"], "high");
        assert_eq!(value["src"], "10.0.0.1");
        assert!(value.get("detail").is_none());
        let with = alert.with_detail("d".to_string());
        assert_eq!(serde_json::to_value(&with).unwrap()["detail"], "d");
    }

    #[test]
    fn severities_are_ordered() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
    }
}
