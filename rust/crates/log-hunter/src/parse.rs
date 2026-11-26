//! Parsing of syslog-style authentication log lines (`/var/log/auth.log`,
//! `/var/log/secure`). The classic `Nov 26 14:02:11` timestamp and ISO 8601
//! timestamps are both understood.

use std::net::IpAddr;

/// What a recognized log line reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    FailedLogin {
        user: String,
        ip: IpAddr,
        invalid_user: bool,
    },
    AcceptedLogin {
        user: String,
        ip: IpAddr,
        method: String,
    },
    InvalidUser { user: String, ip: IpAddr },
    SudoFailure { user: String },
    NotInSudoers { user: String },
    SuFailure { user: String },
    AccountCreated { name: String },
}

/// One recognized log event with its timestamp.
#[derive(Debug, Clone, PartialEq)]
pub struct LogEvent {
    /// Seconds since the epoch; lines without a year use a fixed reference year.
    pub timestamp: f64,
    /// False for the classic syslog format that carries no year.
    pub has_year: bool,
    pub kind: EventKind,
}

fn take_token(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    if text.is_empty() {
        return None;
    }
    let end = text.find(char::is_whitespace).unwrap_or(text.len());
    Some((&text[..end], &text[end..]))
}

fn month_number(name: &str) -> Option<i64> {
    match name {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian calendar).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `HH:MM:SS` with an optional fraction, as seconds since midnight.
fn parse_clock(text: &str) -> Option<i64> {
    let mut parts = text.split(':');
    let hours: i64 = parts.next()?.parse().ok()?;
    let minutes: i64 = parts.next()?.parse().ok()?;
    let seconds: i64 = parts.next()?.split('.').next()?.parse().ok()?;
    if parts.next().is_some() || hours > 23 || minutes > 59 || seconds > 60 {
        return None;
    }
    Some(hours * 3600 + minutes * 60 + seconds)
}

/// `Nov 26 14:02:11` (the day may be padded with two spaces).
fn parse_classic(line: &str) -> Option<(f64, &str)> {
    let (month, rest) = take_token(line)?;
    let (day, rest) = take_token(rest)?;
    let (clock, rest) = take_token(rest)?;
    let month = month_number(month)?;
    let day: i64 = day.parse().ok()?;
    let seconds = parse_clock(clock)?;
    let days = days_from_civil(2001, month, day);
    Some(((days * 86_400 + seconds) as f64, rest))
}

/// Splits `14:02:11.5+03:00` into the clock and the UTC offset in seconds.
fn split_offset(text: &str) -> Option<(&str, i64)> {
    if let Some(clock) = text.strip_suffix('Z') {
        return Some((clock, 0));
    }
    let Some(pos) = text.rfind(['+', '-']) else {
        return Some((text, 0));
    };
    let (clock, zone) = text.split_at(pos);
    let sign = if zone.starts_with('-') { -1 } else { 1 };
    let (hours, minutes) = zone[1..].split_once(':')?;
    let hours: i64 = hours.parse().ok()?;
    let minutes: i64 = minutes.parse().ok()?;
    Some((clock, sign * (hours * 3600 + minutes * 60)))
}

/// `2026-11-26T14:02:11.123456+03:00`.
fn parse_iso(line: &str) -> Option<(f64, &str)> {
    let (token, rest) = take_token(line)?;
    let (date, time) = token.split_once('T')?;
    let mut fields = date.split('-');
    let year: i64 = fields.next()?.parse().ok()?;
    let month: i64 = fields.next()?.parse().ok()?;
    let day: i64 = fields.next()?.parse().ok()?;
    if fields.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (clock, offset) = split_offset(time)?;
    let seconds = parse_clock(clock)?;
    let total = days_from_civil(year, month, day) * 86_400 + seconds - offset;
    Some((total as f64, rest))
}

/// Returns the timestamp, whether it carried a year, and the rest of the line.
fn parse_timestamp(line: &str) -> Option<(f64, bool, &str)> {
    let first = line.trim_start().chars().next()?;
    if first.is_ascii_digit() {
        let (timestamp, rest) = parse_iso(line)?;
        Some((timestamp, true, rest))
    } else {
        let (timestamp, rest) = parse_classic(line)?;
        Some((timestamp, false, rest))
    }
}

fn find_field(text: &str, prefix: &str) -> Option<String> {
    for token in text.split_whitespace() {
        if let Some(value) = token.strip_prefix(prefix) {
            if !value.is_empty() {
                return Some(value.trim_end_matches(',').to_string());
            }
        }
    }
    None
}

fn failed(user: &str, ip: &str, invalid_user: bool) -> Option<EventKind> {
    let ip: IpAddr = ip.parse().ok()?;
    Some(EventKind::FailedLogin {
        user: user.to_string(),
        ip,
        invalid_user,
    })
}

fn accepted(user: &str, ip: &str, method: &str) -> Option<EventKind> {
    let ip: IpAddr = ip.parse().ok()?;
    Some(EventKind::AcceptedLogin {
        user: user.to_string(),
        ip,
        method: method.to_string(),
    })
}

fn invalid(user: &str, ip: &str) -> Option<EventKind> {
    let ip: IpAddr = ip.parse().ok()?;
    Some(EventKind::InvalidUser {
        user: user.to_string(),
        ip,
    })
}

fn su_failure(user: &str) -> Option<EventKind> {
    Some(EventKind::SuFailure {
        user: user.to_string(),
    })
}

fn parse_sshd(message: &str) -> Option<EventKind> {
    let tokens: Vec<&str> = message.split_whitespace().collect();
    match tokens.as_slice() {
        ["Failed", _, "for", "invalid", "user", user, "from", ip, ..] => failed(user, ip, true),
        ["Failed", _, "for", user, "from", ip, ..] => failed(user, ip, false),
        ["Accepted", method, "for", user, "from", ip, ..] => accepted(user, ip, method),
        ["Invalid", "user", user, "from", ip, ..] => invalid(user, ip),
        _ => None,
    }
}

fn parse_sudo(message: &str) -> Option<EventKind> {
    let text = message.trim();
    if text.starts_with("pam_unix(sudo:auth): authentication failure") {
        let user = find_field(text, "user=")?;
        return Some(EventKind::SudoFailure { user });
    }
    let (user, rest) = text.split_once(" : ")?;
    let user = user.trim().to_string();
    if rest.contains("incorrect password attempt") {
        return Some(EventKind::SudoFailure { user });
    }
    if rest.contains("NOT in sudoers") {
        return Some(EventKind::NotInSudoers { user });
    }
    None
}

fn parse_su(message: &str) -> Option<EventKind> {
    let tokens: Vec<&str> = message.split_whitespace().collect();
    match tokens.as_slice() {
        ["FAILED", "SU", _, _, user, ..] => su_failure(user),
        _ => None,
    }
}

fn parse_useradd(message: &str) -> Option<EventKind> {
    if !message.starts_with("new user:") {
        return None;
    }
    let name = find_field(message, "name=")?;
    Some(EventKind::AccountCreated { name })
}

/// Parses one log line. Returns `None` for lines that are not relevant.
pub fn parse_line(line: &str) -> Option<LogEvent> {
    let (timestamp, has_year, rest) = parse_timestamp(line)?;
    let (_host, rest) = take_token(rest)?;
    let (program, message) = rest.trim_start().split_once(": ")?;
    let program = program.split('[').next().unwrap_or(program);
    let kind = match program {
        "sshd" | "sshd-session" => parse_sshd(message)?,
        "sudo" => parse_sudo(message)?,
        "su" | "su-l" => parse_su(message)?,
        "useradd" => parse_useradd(message)?,
        _ => return None,
    };
    Some(LogEvent {
        timestamp,
        has_year,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(line: &str) -> EventKind {
        parse_line(line).unwrap().kind
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn parses_failed_logins() {
        let plain = "Nov 26 14:02:11 srv sshd[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2";
        assert_eq!(
            kind(plain),
            EventKind::FailedLogin {
                user: "root".to_string(),
                ip: ip("203.0.113.5"),
                invalid_user: false,
            }
        );
        let invalid = "Nov 26 14:02:12 srv sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4243 ssh2";
        assert_eq!(
            kind(invalid),
            EventKind::FailedLogin {
                user: "admin".to_string(),
                ip: ip("203.0.113.5"),
                invalid_user: true,
            }
        );
    }

    #[test]
    fn parses_accepted_and_invalid_user_lines() {
        let accepted = "Nov 26 14:05:00 srv sshd[9]: Accepted publickey for bob from 198.51.100.7 port 50000 ssh2";
        assert_eq!(
            kind(accepted),
            EventKind::AcceptedLogin {
                user: "bob".to_string(),
                ip: ip("198.51.100.7"),
                method: "publickey".to_string(),
            }
        );
        let invalid = "Nov 26 14:05:01 srv sshd[9]: Invalid user oracle from 2001:db8::1 port 22";
        assert_eq!(
            kind(invalid),
            EventKind::InvalidUser {
                user: "oracle".to_string(),
                ip: ip("2001:db8::1"),
            }
        );
    }

    #[test]
    fn parses_sudo_su_and_useradd_lines() {
        let pam = "Nov 26 14:06:00 srv sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 ruser=bob rhost=  user=bob";
        assert_eq!(kind(pam), EventKind::SudoFailure { user: "bob".to_string() });
        let attempts = "Nov 26 14:06:01 srv sudo:      bob : 3 incorrect password attempts ; TTY=pts/0 ; USER=root";
        assert_eq!(kind(attempts), EventKind::SudoFailure { user: "bob".to_string() });
        let denied = "Nov 26 14:06:02 srv sudo:    eve : user NOT in sudoers ; TTY=pts/1 ; USER=root";
        assert_eq!(kind(denied), EventKind::NotInSudoers { user: "eve".to_string() });
        let su = "Nov 26 14:06:03 srv su[55]: FAILED SU (to root) bob on pts/0";
        assert_eq!(kind(su), EventKind::SuFailure { user: "bob".to_string() });
        let add = "Nov 26 14:06:04 srv useradd[77]: new user: name=evil, UID=1001, GID=1001, home=/home/evil";
        assert_eq!(kind(add), EventKind::AccountCreated { name: "evil".to_string() });
    }

    #[test]
    fn ignores_irrelevant_and_malformed_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("garbage").is_none());
        assert!(parse_line("Nov 26 14:02:11 srv cron[1]: (root) CMD (run-parts)").is_none());
        assert!(parse_line("Nov 26 14:02:11 srv sshd[1]: Server listening on 0.0.0.0 port 22.").is_none());
        let hostname = "Nov 26 14:02:11 srv sshd[1]: Failed password for root from evil.example.com port 22";
        assert!(parse_line(hostname).is_none());
        assert!(parse_line("Xxx 26 14:02:11 srv sshd[1]: Invalid user a from 1.2.3.4").is_none());
    }

    #[test]
    fn classic_timestamps_are_relative_and_year_less() {
        let a = parse_line("Nov 26 14:02:11 srv sshd[1]: Invalid user a from 1.2.3.4 port 1").unwrap();
        let b = parse_line("Nov 26 14:02:41 srv sshd[1]: Invalid user a from 1.2.3.4 port 1").unwrap();
        let padded = parse_line("Nov  6 14:02:41 srv sshd[1]: Invalid user a from 1.2.3.4 port 1").unwrap();
        assert!(!a.has_year);
        assert_eq!(b.timestamp - a.timestamp, 30.0);
        assert!(padded.timestamp < a.timestamp);
    }

    #[test]
    fn iso_timestamps_honor_the_utc_offset() {
        let utc = "2026-11-26T14:02:11Z srv sshd[1]: Invalid user a from 1.2.3.4 port 1";
        let plus3 = "2026-11-26T14:02:11.123456+03:00 srv sshd[1]: Invalid user a from 1.2.3.4 port 1";
        let a = parse_line(utc).unwrap();
        let b = parse_line(plus3).unwrap();
        assert!(a.has_year && b.has_year);
        assert_eq!(a.timestamp - b.timestamp, 3.0 * 3600.0);
        assert_eq!(a.timestamp, 1_795_701_731.0);
    }

    #[test]
    fn civil_dates_convert_to_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2001, 1, 1) + 365, days_from_civil(2002, 1, 1));
    }
}
