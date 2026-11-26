//! Report model of the scanner (serialized as the JSON report).

use serde::Serialize;

/// Finding severity, ordered from least to most serious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// What kind of problem a finding describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Secret,
    VulnerableDependency,
    Dockerfile,
}

/// One problem found in a file. `evidence` never holds a full secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub kind: Kind,
    pub rule: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl Finding {
    pub fn new(
        kind: Kind,
        rule: &str,
        severity: Severity,
        file: &str,
        line: usize,
        message: &str,
    ) -> Self {
        Self {
            kind,
            rule: rule.to_string(),
            severity,
            file: file.to_string(),
            line,
            message: message.to_string(),
            evidence: None,
        }
    }

    pub fn with_evidence(mut self, evidence: String) -> Self {
        self.evidence = Some(evidence);
        self
    }
}

/// Number of findings per severity (counted before truncation).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// The full scan result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub truncated: bool,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

impl Report {
    /// Sorts findings (most serious first), fills the summary and cuts the
    /// list to `max_findings` entries.
    pub fn finish(&mut self, max_findings: usize) {
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file.cmp(&b.file))
                .then(a.line.cmp(&b.line))
        });
        let mut summary = Summary::default();
        for finding in &self.findings {
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
            }
        }
        self.summary = summary;
        if self.findings.len() > max_findings {
            self.findings.truncate(max_findings);
            self.truncated = true;
        }
    }

    /// True if at least one high or critical finding exists.
    pub fn has_serious(&self) -> bool {
        self.summary.critical + self.summary.high > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity, file: &str, line: usize) -> Finding {
        Finding::new(Kind::Secret, "rule", severity, file, line, "message")
    }

    #[test]
    fn finish_sorts_counts_and_truncates() {
        let mut report = Report::default();
        report.findings.push(finding(Severity::Low, "b", 1));
        report.findings.push(finding(Severity::Critical, "z", 9));
        report.findings.push(finding(Severity::Critical, "a", 3));
        report.findings.push(finding(Severity::Medium, "a", 1));
        report.finish(3);
        assert_eq!(report.summary.critical, 2);
        assert_eq!(report.summary.medium, 1);
        assert_eq!(report.summary.low, 1);
        assert!(report.truncated);
        assert_eq!(report.findings.len(), 3);
        assert_eq!(report.findings[0].file, "a");
        assert_eq!(report.findings[1].file, "z");
        assert!(report.has_serious());
    }

    #[test]
    fn evidence_is_skipped_when_absent() {
        let plain = serde_json::to_value(finding(Severity::Low, "f", 1)).unwrap();
        assert!(plain.get("evidence").is_none());
        let masked = finding(Severity::Low, "f", 1).with_evidence("AKIA***".to_string());
        let value = serde_json::to_value(masked).unwrap();
        assert_eq!(value["evidence"], "AKIA***");
        assert_eq!(value["severity"], "low");
        assert_eq!(value["kind"], "secret");
    }
}
