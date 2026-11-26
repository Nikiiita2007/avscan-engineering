//! Version parsing and a small built-in advisory database.
//!
//! The database is a hand-maintained snapshot of well-known advisories. It is
//! not exhaustive; confirm findings with the vendor advisory before acting.

use std::cmp::Ordering;

use crate::report::Severity;

/// Package ecosystem of an advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    PyPi,
}

/// A known vulnerability fixed in a given release.
#[derive(Debug)]
pub struct Advisory {
    pub ecosystem: Ecosystem,
    pub package: &'static str,
    pub fixed_in: &'static str,
    pub id: &'static str,
    pub severity: Severity,
    pub summary: &'static str,
}

pub static ADVISORIES: [Advisory; 11] = [
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "lodash",
        fixed_in: "4.17.21",
        id: "CVE-2021-23337",
        severity: Severity::High,
        summary: "command injection via template",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "minimist",
        fixed_in: "1.2.6",
        id: "CVE-2021-44906",
        severity: Severity::Critical,
        summary: "prototype pollution",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "axios",
        fixed_in: "0.21.2",
        id: "CVE-2021-3749",
        severity: Severity::High,
        summary: "regular expression denial of service",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "node-fetch",
        fixed_in: "2.6.7",
        id: "CVE-2022-0235",
        severity: Severity::High,
        summary: "forwards secure headers to untrusted sites",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "jsonwebtoken",
        fixed_in: "9.0.0",
        id: "CVE-2022-23529",
        severity: Severity::High,
        summary: "insecure key retrieval handling",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "requests",
        fixed_in: "2.31.0",
        id: "CVE-2023-32681",
        severity: Severity::Medium,
        summary: "Proxy-Authorization header leak",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "pyyaml",
        fixed_in: "5.4",
        id: "CVE-2020-14343",
        severity: Severity::Critical,
        summary: "arbitrary code execution in full_load",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "jinja2",
        fixed_in: "2.11.3",
        id: "CVE-2020-28493",
        severity: Severity::Medium,
        summary: "regular expression denial of service in urlize",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "flask",
        fixed_in: "2.2.5",
        id: "CVE-2023-30861",
        severity: Severity::High,
        summary: "session cookie disclosure behind caching proxies",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "pillow",
        fixed_in: "10.0.1",
        id: "CVE-2023-4863",
        severity: Severity::High,
        summary: "libwebp heap buffer overflow",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "urllib3",
        fixed_in: "1.26.5",
        id: "CVE-2021-33503",
        severity: Severity::High,
        summary: "regular expression denial of service in URL parsing",
    },
];

/// Extracts the leading numeric version from a spec such as `^4.17.20`,
/// `~1.2`, `>=2.0.0 <3` or `1.2.3-beta.1`. Returns `None` for `latest`, `*`, etc.
pub fn parse_version(raw: &str) -> Option<Vec<u64>> {
    let trimmed = raw.trim().trim_start_matches(|c: char| !c.is_ascii_digit());
    let mut parts = Vec::new();
    for piece in trimmed.split('.') {
        let digits: String = piece.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        parts.push(digits.parse().ok()?);
        if digits.len() != piece.len() {
            break;
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

/// Compares two versions component-wise; missing components count as zero.
pub fn compare(a: &[u64], b: &[u64]) -> Ordering {
    let len = a.len().max(b.len());
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// Advisories that affect `package` when the declared version is `declared`.
pub fn check(ecosystem: Ecosystem, package: &str, declared: &str) -> Vec<&'static Advisory> {
    let Some(version) = parse_version(declared) else {
        return Vec::new();
    };
    let package = package.to_ascii_lowercase();
    let mut hits = Vec::new();
    for advisory in &ADVISORIES {
        if advisory.ecosystem != ecosystem || advisory.package != package {
            continue;
        }
        let Some(fixed) = parse_version(advisory.fixed_in) else {
            continue;
        };
        if compare(&version, &fixed) == Ordering::Less {
            hits.push(advisory);
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_specs() {
        assert_eq!(parse_version("^4.17.20"), Some(vec![4, 17, 20]));
        assert_eq!(parse_version("~1.2"), Some(vec![1, 2]));
        assert_eq!(parse_version(">=2.0.0 <3"), Some(vec![2, 0, 0]));
        assert_eq!(parse_version("1.2.3-beta.1"), Some(vec![1, 2, 3]));
        assert_eq!(parse_version("latest"), None);
        assert_eq!(parse_version("*"), None);
    }

    #[test]
    fn compares_with_implicit_zeros() {
        assert_eq!(compare(&[1, 2], &[1, 2, 0]), Ordering::Equal);
        assert_eq!(compare(&[1, 2, 3], &[1, 10]), Ordering::Less);
        assert_eq!(compare(&[2], &[1, 99, 99]), Ordering::Greater);
    }

    #[test]
    fn flags_only_versions_below_the_fix() {
        let old = check(Ecosystem::Npm, "lodash", "4.17.20");
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].id, "CVE-2021-23337");
        assert!(check(Ecosystem::Npm, "lodash", "4.17.21").is_empty());
        assert!(check(Ecosystem::Npm, "lodash", "5.0.0").is_empty());
    }

    #[test]
    fn ecosystem_and_case_are_respected() {
        assert!(check(Ecosystem::PyPi, "lodash", "1.0.0").is_empty());
        assert_eq!(check(Ecosystem::PyPi, "PyYAML", "5.3").len(), 1);
        assert!(check(Ecosystem::Npm, "unknown-package", "0.0.1").is_empty());
    }

    #[test]
    fn every_advisory_has_a_parsable_fixed_version() {
        for advisory in &ADVISORIES {
            assert!(
                parse_version(advisory.fixed_in).is_some(),
                "{}",
                advisory.id
            );
        }
    }
}
