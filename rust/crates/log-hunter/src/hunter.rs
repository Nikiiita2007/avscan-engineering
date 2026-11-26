//! Detection logic: turns parsed log events into IOC alerts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, BufRead};
use std::net::IpAddr;

use serde::Serialize;

use crate::alert::{Alert, Severity};
use crate::net::IpNet;
use crate::parse::{parse_line, EventKind, LogEvent};
use crate::rules::Rules;

const YEAR_SECS: f64 = 31_536_000.0;
const WRAP_GAP: f64 = 15_000_000.0;

/// Counters of one analysis run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub lines: usize,
    pub parsed: usize,
    pub alerts: usize,
}

/// Sliding window of event times. Alerts once per burst.
#[derive(Default)]
struct Burst {
    times: VecDeque<f64>,
    alerted: bool,
}

impl Burst {
    fn prune(&mut self, ts: f64, window: f64) {
        while let Some(first) = self.times.front().copied() {
            if ts - first <= window {
                break;
            }
            self.times.pop_front();
        }
    }

    /// Records an event; true exactly when the threshold is newly reached.
    fn hit(&mut self, ts: f64, window: f64, threshold: usize) -> bool {
        self.prune(ts, window);
        self.times.push_back(ts);
        if self.times.len() < threshold {
            self.alerted = false;
            return false;
        }
        if self.alerted {
            return false;
        }
        self.alerted = true;
        true
    }

    fn count_at(&mut self, ts: f64, window: f64) -> usize {
        self.prune(ts, window);
        self.times.len()
    }
}

/// Sliding window of distinct invalid usernames.
#[derive(Default)]
struct EnumState {
    seen: VecDeque<(f64, String)>,
    alerted: bool,
}

impl EnumState {
    fn hit(&mut self, ts: f64, window: f64, user: &str, threshold: usize) -> bool {
        while let Some(first) = self.seen.front().map(|e| e.0) {
            if ts - first <= window {
                break;
            }
            self.seen.pop_front();
        }
        self.seen.push_back((ts, user.to_string()));
        let distinct: HashSet<&str> = self.seen.iter().map(|e| e.1.as_str()).collect();
        if distinct.len() < threshold {
            self.alerted = false;
            return false;
        }
        if self.alerted {
            return false;
        }
        self.alerted = true;
        true
    }
}

fn event_ip(kind: &EventKind) -> Option<IpAddr> {
    match kind {
        EventKind::FailedLogin { ip, .. }
        | EventKind::AcceptedLogin { ip, .. }
        | EventKind::InvalidUser { ip, .. } => Some(*ip),
        _ => None,
    }
}

/// Stateful hunter; feed events in log order.
pub struct Hunter {
    rules: Rules,
    nets: Vec<IpNet>,
    last_ts: f64,
    year_offset: f64,
    failures: HashMap<IpAddr, Burst>,
    enumeration: HashMap<IpAddr, EnumState>,
    repeated: HashMap<String, Burst>,
    seen_bad: HashSet<IpAddr>,
    seen_accounts: HashSet<String>,
    seen_sudoers: HashSet<String>,
}

impl Hunter {
    pub fn new(rules: Rules) -> Self {
        let mut nets = Vec::new();
        for entry in &rules.bad_ips {
            if let Some(net) = IpNet::parse(entry) {
                nets.push(net);
            }
        }
        Self {
            rules,
            nets,
            last_ts: 0.0,
            year_offset: 0.0,
            failures: HashMap::new(),
            enumeration: HashMap::new(),
            repeated: HashMap::new(),
            seen_bad: HashSet::new(),
            seen_accounts: HashSet::new(),
            seen_sudoers: HashSet::new(),
        }
    }

    /// Parses and analyzes one log line. `None` if the line is not relevant.
    pub fn feed_line(&mut self, line: &str) -> Option<Vec<Alert>> {
        let event = parse_line(line)?;
        Some(self.feed(&event))
    }

    /// Lines without a year wrap around in January: keep time monotonic.
    fn adjust(&mut self, event: &LogEvent) -> f64 {
        if event.has_year {
            return event.timestamp;
        }
        if event.timestamp + WRAP_GAP < self.last_ts {
            self.year_offset += YEAR_SECS;
        }
        self.last_ts = event.timestamp;
        event.timestamp + self.year_offset
    }

    /// Analyzes one event and returns the alerts it triggered.
    pub fn feed(&mut self, event: &LogEvent) -> Vec<Alert> {
        let ts = self.adjust(event);
        let mut alerts = Vec::new();
        if let Some(ip) = event_ip(&event.kind) {
            alerts.extend(self.check_bad_ip(ts, ip));
        }
        match &event.kind {
            EventKind::FailedLogin {
                user,
                ip,
                invalid_user,
            } => alerts.extend(self.on_failed(ts, user, *ip, *invalid_user)),
            EventKind::AcceptedLogin { user, ip, method } => {
                alerts.extend(self.on_accepted(ts, user, *ip, method));
            }
            EventKind::InvalidUser { user, ip } => {
                alerts.extend(self.on_invalid_user(ts, user, *ip));
            }
            EventKind::SudoFailure { user } => {
                alerts.extend(self.on_repeated(ts, "sudo-failures", user));
            }
            EventKind::SuFailure { user } => {
                alerts.extend(self.on_repeated(ts, "su-failures", user));
            }
            EventKind::NotInSudoers { user } => alerts.extend(self.on_not_in_sudoers(ts, user)),
            EventKind::AccountCreated { name } => alerts.extend(self.on_account(ts, name)),
        }
        alerts
    }

    fn display_user(&self, user: &str, untrusted: bool) -> String {
        if self.rules.mask_names && untrusted && user.chars().count() > 3 {
            let head: String = user.chars().take(2).collect();
            return format!("{head}***");
        }
        user.to_string()
    }

    fn check_bad_ip(&mut self, ts: f64, ip: IpAddr) -> Option<Alert> {
        if !self.nets.iter().any(|net| net.contains(ip)) {
            return None;
        }
        if !self.seen_bad.insert(ip) {
            return None;
        }
        let text = "activity from an address on the IOC list";
        let alert = Alert::new("ioc-ip", Severity::High, ts, text);
        Some(alert.with_ip(ip))
    }

    fn on_failed(&mut self, ts: f64, user: &str, ip: IpAddr, invalid_user: bool) -> Vec<Alert> {
        let window = self.rules.window_secs;
        let threshold = self.rules.bruteforce_threshold;
        let mut alerts = Vec::new();
        let burst = self.failures.entry(ip).or_default();
        if burst.hit(ts, window, threshold) {
            let count = burst.times.len();
            let text = format!("{count} failed logins from one address within {window} s");
            let alert = Alert::new("ssh-bruteforce", Severity::High, ts, &text);
            alerts.push(alert.with_ip(ip));
        }
        if invalid_user {
            alerts.extend(self.on_invalid_user(ts, user, ip));
        }
        alerts
    }

    fn on_invalid_user(&mut self, ts: f64, user: &str, ip: IpAddr) -> Option<Alert> {
        let window = self.rules.window_secs;
        let threshold = self.rules.enumeration_threshold;
        let state = self.enumeration.entry(ip).or_default();
        if !state.hit(ts, window, user, threshold) {
            return None;
        }
        let sample = self.display_user(user, true);
        let text = format!("many invalid usernames tried from one address, e.g. {sample}");
        let alert = Alert::new("ssh-user-enumeration", Severity::Medium, ts, &text);
        Some(alert.with_ip(ip))
    }

    fn on_accepted(&mut self, ts: f64, user: &str, ip: IpAddr, method: &str) -> Vec<Alert> {
        let window = self.rules.window_secs;
        let needed = self.rules.success_after_failures;
        let mut prior = 0;
        if let Some(burst) = self.failures.get_mut(&ip) {
            prior = burst.count_at(ts, window);
        }
        let mut alerts = Vec::new();
        if prior >= needed {
            let text = format!("successful login for {user} after {prior} failed attempts");
            let alert = Alert::new("ssh-login-after-failures", Severity::Critical, ts, &text);
            alerts.push(alert.with_ip(ip).with_user(user));
        }
        let root_password = user == "root" && method == "password";
        if root_password && self.rules.alert_root_password_login {
            let text = "direct root login with a password";
            let alert = Alert::new("root-password-login", Severity::Medium, ts, text);
            alerts.push(alert.with_ip(ip).with_user(user));
        }
        alerts
    }

    fn on_repeated(&mut self, ts: f64, rule: &str, user: &str) -> Option<Alert> {
        let window = self.rules.window_secs;
        let threshold = self.rules.repeated_failure_threshold;
        let key = format!("{rule}:{user}");
        let burst = self.repeated.entry(key).or_default();
        if !burst.hit(ts, window, threshold) {
            return None;
        }
        let text = format!("repeated authentication failures for local user {user}");
        let alert = Alert::new(rule, Severity::Medium, ts, &text);
        Some(alert.with_user(user))
    }

    fn on_not_in_sudoers(&mut self, ts: f64, user: &str) -> Option<Alert> {
        if !self.seen_sudoers.insert(user.to_string()) {
            return None;
        }
        let text = "user tried sudo without being in sudoers";
        let alert = Alert::new("sudo-not-in-sudoers", Severity::Medium, ts, text);
        Some(alert.with_user(user))
    }

    fn on_account(&mut self, ts: f64, name: &str) -> Option<Alert> {
        if !self.rules.alert_on_account_created {
            return None;
        }
        if !self.seen_accounts.insert(name.to_string()) {
            return None;
        }
        let text = "new local account created";
        let alert = Alert::new("account-created", Severity::Medium, ts, text);
        Some(alert.with_user(name))
    }
}

/// Reads a whole log and reports every alert through `on_alert`.
pub fn hunt_reader<R: BufRead, F: FnMut(Alert)>(
    mut reader: R,
    rules: &Rules,
    mut on_alert: F,
) -> io::Result<Stats> {
    let mut hunter = Hunter::new(rules.clone());
    let mut stats = Stats::default();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        stats.lines += 1;
        let line = String::from_utf8_lossy(&buf);
        if let Some(alerts) = hunter.feed_line(line.trim_end()) {
            stats.parsed += 1;
            for alert in alerts {
                stats.alerts += 1;
                on_alert(alert);
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::failed;

    const IP: &str = "203.0.113.5";

    fn hunt(rules: &Rules, text: &str) -> Vec<Alert> {
        let mut alerts = Vec::new();
        hunt_reader(text.as_bytes(), rules, |a| alerts.push(a)).unwrap();
        alerts
    }

    fn named<'a>(alerts: &'a [Alert], rule: &str) -> Vec<&'a Alert> {
        alerts.iter().filter(|a| a.rule == rule).collect()
    }

    #[test]
    fn detects_bruteforce_once_per_burst() {
        let burst: String = (0..5).map(|s| failed(0, s, IP, "root")).collect();
        let alerts = hunt(&Rules::default(), &burst);
        let found = named(&alerts, "ssh-bruteforce");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::High);
        assert_eq!(found[0].ip.as_deref(), Some(IP));
        let four: String = (0..4).map(|s| failed(0, s, IP, "root")).collect();
        assert!(hunt(&Rules::default(), &four).is_empty());
    }

    #[test]
    fn slow_failures_do_not_trigger_and_new_bursts_alert_again() {
        let slow: String = (0..6).map(|m| failed(m * 2, 0, IP, "root")).collect();
        assert!(hunt(&Rules::default(), &slow).is_empty());
        let mut twice: String = (0..5).map(|s| failed(0, s, IP, "root")).collect();
        twice.extend((0..5).map(|s| failed(30, s, IP, "root")));
        let alerts = hunt(&Rules::default(), &twice);
        assert_eq!(named(&alerts, "ssh-bruteforce").len(), 2);
    }

    #[test]
    fn detects_user_enumeration_and_masks_the_sample() {
        let text = "Nov 26 14:00:00 srv sshd[1]: Invalid user admin from 203.0.113.5 port 1\n\
                    Nov 26 14:00:01 srv sshd[1]: Invalid user test from 203.0.113.5 port 1\n\
                    Nov 26 14:00:02 srv sshd[1]: Invalid user oracle from 203.0.113.5 port 1\n";
        let alerts = hunt(&Rules::default(), text);
        let found = named(&alerts, "ssh-user-enumeration");
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("or***"));
        assert!(!found[0].message.contains("oracle"));
        let open = Rules {
            mask_names: false,
            ..Rules::default()
        };
        let alerts = hunt(&open, text);
        assert!(named(&alerts, "ssh-user-enumeration")[0].message.contains("oracle"));
    }

    #[test]
    fn flags_a_successful_login_after_failures() {
        let mut text: String = (0..3).map(|s| failed(0, s, IP, "bob")).collect();
        text.push_str("Nov 26 14:00:10 srv sshd[1]: Accepted password for bob from 203.0.113.5 port 9\n");
        text.push_str("Nov 26 14:00:11 srv sshd[1]: Accepted password for bob from 198.51.100.1 port 9\n");
        let alerts = hunt(&Rules::default(), &text);
        let found = named(&alerts, "ssh-login-after-failures");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Critical);
        assert_eq!(found[0].user.as_deref(), Some("bob"));
        assert_eq!(found[0].ip.as_deref(), Some(IP));
    }

    #[test]
    fn flags_root_password_logins_only() {
        let password = "Nov 26 14:00:00 srv sshd[1]: Accepted password for root from 198.51.100.1 port 9\n";
        let key = "Nov 26 14:00:00 srv sshd[1]: Accepted publickey for root from 198.51.100.1 port 9\n";
        assert_eq!(named(&hunt(&Rules::default(), password), "root-password-login").len(), 1);
        assert!(hunt(&Rules::default(), key).is_empty());
        let quiet = Rules {
            alert_root_password_login: false,
            ..Rules::default()
        };
        assert!(hunt(&quiet, password).is_empty());
    }

    #[test]
    fn reports_repeated_sudo_and_su_failures() {
        let sudo = "Nov 26 14:00:00 srv sudo: pam_unix(sudo:auth): authentication failure; user=bob\n";
        let su = "Nov 26 14:00:00 srv su[5]: FAILED SU (to root) eve on pts/0\n";
        let alerts = hunt(&Rules::default(), &sudo.repeat(3));
        let found = named(&alerts, "sudo-failures");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].user.as_deref(), Some("bob"));
        assert!(hunt(&Rules::default(), &sudo.repeat(2)).is_empty());
        let alerts = hunt(&Rules::default(), &su.repeat(3));
        assert_eq!(named(&alerts, "su-failures").len(), 1);
    }

    #[test]
    fn reports_sudoers_violations_and_new_accounts_once() {
        let denied = "Nov 26 14:00:00 srv sudo: eve : user NOT in sudoers ; TTY=pts/1 ; USER=root\n";
        let add = "Nov 26 14:00:00 srv useradd[7]: new user: name=evil, UID=1001, GID=1001\n";
        let alerts = hunt(&Rules::default(), &denied.repeat(2));
        assert_eq!(named(&alerts, "sudo-not-in-sudoers").len(), 1);
        let alerts = hunt(&Rules::default(), &add.repeat(2));
        assert_eq!(named(&alerts, "account-created").len(), 1);
        let quiet = Rules {
            alert_on_account_created: false,
            ..Rules::default()
        };
        assert!(hunt(&quiet, add).is_empty());
    }

    #[test]
    fn matches_addresses_on_the_ioc_list_once() {
        let rules = Rules {
            bad_ips: vec!["203.0.113.0/24".to_string()],
            ..Rules::default()
        };
        let text = failed(0, 0, "203.0.113.77", "root") + &failed(0, 1, "203.0.113.77", "root");
        let alerts = hunt(&rules, &text);
        let found = named(&alerts, "ioc-ip");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::High);
        assert!(hunt(&rules, &failed(0, 0, "198.51.100.1", "root")).is_empty());
    }

    #[test]
    fn the_year_change_does_not_keep_old_failures_alive() {
        let december = "Dec 31 23:59:00 srv sshd[1]: Failed password for root from 203.0.113.5 port 1\n";
        let january = "Jan  1 00:10:00 srv sshd[1]: Failed password for root from 203.0.113.5 port 1\n";
        let text = format!("{}{january}", december.repeat(4));
        assert!(hunt(&Rules::default(), &text).is_empty());
        let burst = format!("{}{}", december.repeat(3), january.replace("00:10:00", "00:00:30"));
        assert_eq!(named(&hunt(&Rules::default(), &format!("{burst}{december}")), "ssh-bruteforce").len(), 0);
    }

    #[test]
    fn works_with_iso_timestamps_and_counts_lines() {
        let line = "2026-11-26T14:00:00+00:00 srv sshd[1]: Failed password for root from 203.0.113.5 port 1\n";
        let text = format!("{}not a log line\n", line.repeat(5));
        let mut alerts = Vec::new();
        let stats = hunt_reader(text.as_bytes(), &Rules::default(), |a| alerts.push(a)).unwrap();
        assert_eq!(named(&alerts, "ssh-bruteforce").len(), 1);
        assert_eq!(stats.lines, 6);
        assert_eq!(stats.parsed, 5);
        assert_eq!(stats.alerts, 1);
    }

    #[test]
    fn survives_invalid_utf8() {
        let mut bytes = failed(0, 0, IP, "root").into_bytes();
        bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
        let stats = hunt_reader(bytes.as_slice(), &Rules::default(), |_| {}).unwrap();
        assert_eq!(stats.lines, 2);
        assert_eq!(stats.parsed, 1);
    }
}
