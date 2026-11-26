//! Secret detection: well-known token formats plus an entropy-based heuristic
//! for hard-coded credentials. Findings never contain a full secret.

use std::sync::OnceLock;

use regex::Regex;

use crate::report::{Finding, Kind, Severity};

const MAX_LINE_LEN: usize = 4000;
const MIN_ENTROPY: f64 = 3.0;
const GENERIC_PATTERN: &str = concat!(
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|",
    r"auth[_-]?token|token)\b\s*[:=]\s*[\x22']?([^\s\x22',;]{8,})"
);

struct RuleSpec {
    id: &'static str,
    severity: Severity,
    description: &'static str,
    pattern: &'static str,
}

static SPECS: [RuleSpec; 7] = [
    RuleSpec {
        id: "aws-access-key-id",
        severity: Severity::Critical,
        description: "AWS access key id",
        pattern: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    },
    RuleSpec {
        id: "github-token",
        severity: Severity::Critical,
        description: "GitHub token",
        pattern: r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    },
    RuleSpec {
        id: "slack-token",
        severity: Severity::High,
        description: "Slack token",
        pattern: r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    },
    RuleSpec {
        id: "private-key",
        severity: Severity::Critical,
        description: "private key material",
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY",
    },
    RuleSpec {
        id: "google-api-key",
        severity: Severity::High,
        description: "Google API key",
        pattern: r"\bAIza[0-9A-Za-z_-]{35}\b",
    },
    RuleSpec {
        id: "stripe-live-key",
        severity: Severity::Critical,
        description: "Stripe live secret key",
        pattern: r"\bsk_live_[0-9A-Za-z]{24,}\b",
    },
    RuleSpec {
        id: "jwt",
        severity: Severity::Medium,
        description: "JSON Web Token",
        pattern: r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    },
];

struct Rule {
    spec: &'static RuleSpec,
    regex: Regex,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        SPECS
            .iter()
            .map(|spec| Rule {
                spec,
                regex: Regex::new(spec.pattern).expect("valid regex"),
            })
            .collect()
    })
}

fn generic_regex() -> &'static Regex {
    static GENERIC: OnceLock<Regex> = OnceLock::new();
    GENERIC.get_or_init(|| Regex::new(GENERIC_PATTERN).expect("valid regex"))
}

/// Hides most of a secret: only the first four characters stay visible.
pub fn mask(value: &str) -> String {
    if value.chars().count() <= 8 {
        return "****".to_string();
    }
    let head: String = value.chars().take(4).collect();
    format!("{head}***")
}

fn entropy(value: &str) -> f64 {
    let mut counts = [0usize; 256];
    for byte in value.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let len = value.len() as f64;
    let mut total = 0.0;
    for &count in counts.iter().filter(|&&c| c > 0) {
        let p = count as f64 / len;
        total -= p * p.log2();
    }
    total
}

fn is_placeholder(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    let template = v.contains("${") || v.contains("{{") || v.starts_with('<');
    let dummy = v.contains("changeme") || v.contains("example") || v.contains("xxxx");
    let hint = v.contains("your_") || v.contains("placeholder") || v.starts_with('$');
    template || dummy || hint
}

fn generic_finding(line: &str, file: &str, line_no: usize) -> Option<Finding> {
    let caps = generic_regex().captures(line)?;
    let value = caps.get(1)?.as_str();
    if is_placeholder(value) || entropy(value) < MIN_ENTROPY {
        return None;
    }
    let finding = Finding::new(
        Kind::Secret,
        "generic-credential",
        Severity::Medium,
        file,
        line_no,
        "hard-coded credential assigned to a secret-like name",
    );
    Some(finding.with_evidence(mask(value)))
}

/// Scans text line by line. `file` is only used to label the findings.
pub fn scan_text(text: &str, file: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.len() > MAX_LINE_LEN {
            continue;
        }
        let line_no = idx + 1;
        let mut known = false;
        for rule in rules() {
            let Some(found) = rule.regex.find(line) else {
                continue;
            };
            known = true;
            let finding = Finding::new(
                Kind::Secret,
                rule.spec.id,
                rule.spec.severity,
                file,
                line_no,
                rule.spec.description,
            );
            findings.push(finding.with_evidence(mask(found.as_str())));
        }
        if !known {
            if let Some(finding) = generic_finding(line, file, line_no) {
                findings.push(finding);
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_of(text: &str) -> Vec<String> {
        scan_text(text, "f").into_iter().map(|f| f.rule).collect()
    }

    fn aws_key() -> String {
        format!("AKIA{}", "ABCDEFGHIJKLMNOP")
    }

    #[test]
    fn detects_aws_key_and_masks_it() {
        let key = aws_key();
        let findings = scan_text(&format!("key = {key}\n"), "f");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "aws-access-key-id");
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].evidence.as_deref(), Some("AKIA***"));
    }

    #[test]
    fn detects_other_token_formats() {
        let github = format!("ghp_{}", "a1B2c3D4".repeat(5));
        let slack = format!("xoxb-{}", "123456789012-abcdefghij");
        let google = format!("AIza{}", "A".repeat(35));
        let stripe = format!("sk_live_{}", "a1B2c3D4".repeat(3));
        let pem = format!("-----BEGIN {} PRIVATE KEY-----", "RSA");
        assert_eq!(rules_of(&github), ["github-token"]);
        assert_eq!(rules_of(&slack), ["slack-token"]);
        assert_eq!(rules_of(&google), ["google-api-key"]);
        assert_eq!(rules_of(&stripe), ["stripe-live-key"]);
        assert_eq!(rules_of(&pem), ["private-key"]);
    }

    #[test]
    fn detects_generic_credentials() {
        let findings = scan_text("password = Zx9fQ2mLp7Vb\napi_key: Qw3rT7yU1oPz\n", "f");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule, "generic-credential");
        assert_eq!(findings[1].line, 2);
    }

    #[test]
    fn ignores_placeholders_and_low_entropy() {
        assert!(rules_of("password = ${DB_PASSWORD}").is_empty());
        assert!(rules_of("token = changeme-please").is_empty());
        assert!(rules_of("secret = your_secret_here").is_empty());
        assert!(rules_of("password = aaaaaaaaaaaa").is_empty());
        assert!(rules_of("just some text").is_empty());
    }

    #[test]
    fn evidence_never_contains_the_full_secret() {
        let secret = "Zx9fQ2mLp7Vb";
        let findings = scan_text(&format!("password = {secret}"), "f");
        let evidence = findings[0].evidence.clone().unwrap();
        assert_ne!(evidence, secret);
        assert!(evidence.ends_with("***"));
        assert_eq!(mask("short"), "****");
    }

    #[test]
    fn entropy_orders_random_above_repetitive() {
        assert!(entropy("Zx9fQ2mLp7Vb") > entropy("aaaaaaaaaaaa"));
        assert!(entropy("aaaaaaaaaaaa") < MIN_ENTROPY);
    }
}
