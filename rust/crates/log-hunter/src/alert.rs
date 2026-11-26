//! Alerts produced by the hunter.

use std::net::IpAddr;

use serde::Serialize;

/// Alert severity, ordered from least to most serious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// One indicator of compromise.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    pub rule: String,
    pub severity: Severity,
    /// Seconds since the epoch (lines without a year use a reference year).
    pub timestamp: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub message: String,
}

impl Alert {
    pub fn new(rule: &str, severity: Severity, timestamp: f64, message: &str) -> Self {
        Self {
            rule: rule.to_string(),
            severity,
            timestamp,
            ip: None,
            user: None,
            message: message.to_string(),
        }
    }

    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip.to_string());
        self
    }

    pub fn with_user(mut self, user: &str) -> Self {
        self.user = Some(user.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_fields_are_skipped_when_empty() {
        let alert = Alert::new("r", Severity::Critical, 2.0, "m");
        let value = serde_json::to_value(&alert).unwrap();
        assert_eq!(value["severity"], "critical");
        assert!(value.get("ip").is_none() && value.get("user").is_none());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let full = alert.with_ip(ip).with_user("bob");
        let value = serde_json::to_value(&full).unwrap();
        assert_eq!(value["ip"], "10.0.0.1");
        assert_eq!(value["user"], "bob");
    }

    #[test]
    fn severities_are_ordered() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::High < Severity::Critical);
    }
}
