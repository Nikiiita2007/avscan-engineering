//! Detection thresholds. Every field can be overridden from the module config.

use serde::Deserialize;

use crate::net::IpNet;

/// Tunable detection rules; unknown keys are rejected.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    /// Length of the sliding window in seconds.
    pub window_secs: f64,
    /// Failed logins from one address within the window that count as brute force.
    pub bruteforce_threshold: usize,
    /// Different invalid usernames from one address that count as enumeration.
    pub enumeration_threshold: usize,
    /// Failures before a successful login that make the login suspicious.
    pub success_after_failures: usize,
    /// Failures of one local user (sudo or su) within the window that are reported.
    pub repeated_failure_threshold: usize,
    /// Addresses or CIDR ranges that are indicators of compromise.
    pub bad_ips: Vec<String>,
    pub alert_root_password_login: bool,
    pub alert_on_account_created: bool,
    /// Mask untrusted usernames in alert text.
    pub mask_names: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            window_secs: 60.0,
            bruteforce_threshold: 5,
            enumeration_threshold: 3,
            success_after_failures: 3,
            repeated_failure_threshold: 3,
            bad_ips: Vec::new(),
            alert_root_password_login: true,
            alert_on_account_created: true,
            mask_names: true,
        }
    }
}

impl Rules {
    /// Checks that the values make sense; the error text names the problem.
    pub fn validate(&self) -> Result<(), String> {
        if !(self.window_secs.is_finite() && self.window_secs > 0.0) {
            return Err("window_secs must be a positive number".to_string());
        }
        let thresholds = [
            self.bruteforce_threshold,
            self.enumeration_threshold,
            self.success_after_failures,
            self.repeated_failure_threshold,
        ];
        if thresholds.contains(&0) {
            return Err("thresholds must be at least 1".to_string());
        }
        for entry in &self.bad_ips {
            if IpNet::parse(entry).is_none() {
                return Err(format!("invalid IP or CIDR in bad_ips: '{entry}'"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_are_valid() {
        assert!(Rules::default().validate().is_ok());
    }

    #[test]
    fn partial_override_keeps_other_defaults() {
        let rules: Rules = serde_json::from_value(json!({ "bruteforce_threshold": 9 })).unwrap();
        assert_eq!(rules.bruteforce_threshold, 9);
        assert_eq!(rules.enumeration_threshold, 3);
        assert!(rules.mask_names);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(serde_json::from_value::<Rules>(json!({ "bogus": 1 })).is_err());
    }

    #[test]
    fn validation_catches_bad_values() {
        let zero = Rules {
            bruteforce_threshold: 0,
            ..Rules::default()
        };
        assert!(zero.validate().is_err());
        let window = Rules {
            window_secs: 0.0,
            ..Rules::default()
        };
        assert!(window.validate().is_err());
        let bad_ip = Rules {
            bad_ips: vec!["nope".to_string()],
            ..Rules::default()
        };
        assert!(bad_ip.validate().unwrap_err().contains("nope"));
        let good_ip = Rules {
            bad_ips: vec!["10.0.0.0/8".to_string()],
            ..Rules::default()
        };
        assert!(good_ip.validate().is_ok());
    }
}
