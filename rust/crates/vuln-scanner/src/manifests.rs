//! Dependency manifests: `package.json` and `requirements.txt`.

use serde_json::Value;

use crate::report::{Finding, Kind};
use crate::versions::{check, Advisory, Ecosystem};

/// One declared dependency and where it was found.
struct Dep<'a> {
    name: &'a str,
    spec: &'a str,
    file: &'a str,
    line: usize,
}

fn dependency_finding(adv: &Advisory, dep: &Dep<'_>) -> Finding {
    let name = dep.name;
    let spec = dep.spec;
    let id = adv.id;
    let summary = adv.summary;
    let fixed = adv.fixed_in;
    let message = format!("{name} {spec}: {id}, {summary} (fixed in {fixed})");
    Finding::new(
        Kind::VulnerableDependency,
        adv.id,
        adv.severity,
        dep.file,
        dep.line,
        &message,
    )
}

fn find_line(text: &str, needle: &str) -> usize {
    for (idx, line) in text.lines().enumerate() {
        if line.contains(needle) {
            return idx + 1;
        }
    }
    1
}

fn check_section(root: &Value, section: &str, file: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(deps) = root.get(section).and_then(Value::as_object) else {
        return findings;
    };
    for (name, spec) in deps {
        let Some(spec) = spec.as_str() else {
            continue;
        };
        let line = find_line(text, &format!("\"{name}\""));
        let dep = Dep {
            name,
            spec,
            file,
            line,
        };
        for adv in check(Ecosystem::Npm, name, spec) {
            findings.push(dependency_finding(adv, &dep));
        }
    }
    findings
}

/// Checks `dependencies`, `devDependencies` and `optionalDependencies`.
/// The declared minimum of a range (for example `^4.17.20`) is what is compared.
pub fn analyze_package_json(text: &str, file: &str) -> Vec<Finding> {
    let Ok(root) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    findings.extend(check_section(&root, "dependencies", file, text));
    findings.extend(check_section(&root, "devDependencies", file, text));
    findings.extend(check_section(&root, "optionalDependencies", file, text));
    findings
}

fn is_operator(c: char) -> bool {
    c == '=' || c == '<' || c == '>' || c == '!' || c == '~'
}

/// Splits `Name[extra]==1.2.3` into a normalized name and a version. Only exact
/// pins and compatible-release (`~=`) specifiers are considered.
fn split_requirement(spec: &str) -> Option<(String, String)> {
    let op_start = spec.find(is_operator)?;
    let (raw_name, rest) = spec.split_at(op_start);
    let base = raw_name.split('[').next().unwrap_or("").trim();
    let name = base.to_ascii_lowercase().replace('_', "-");
    let op_len = rest.find(|c: char| !is_operator(c)).unwrap_or(rest.len());
    let (op, tail) = rest.split_at(op_len);
    let version = tail.split(',').next().unwrap_or("").trim();
    let is_pin = op == "==" || op == "===" || op == "~=";
    if !is_pin || name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version.to_string()))
}

/// Checks pinned requirements of a `requirements.txt`.
pub fn analyze_requirements(text: &str, file: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        let spec_text = line.split(';').next().unwrap_or(line);
        let Some((name, version)) = split_requirement(spec_text) else {
            continue;
        };
        let dep = Dep {
            name: &name,
            spec: &version,
            file,
            line: idx + 1,
        };
        for adv in check(Ecosystem::PyPi, &name, &version) {
            findings.push(dependency_finding(adv, &dep));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_json_flags_vulnerable_ranges() {
        let text = "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.20\",\n    \"left-pad\": \"1.0.0\"\n  },\n  \"devDependencies\": {\"minimist\": \"1.2.5\"}\n}";
        let findings = analyze_package_json(text, "package.json");
        assert_eq!(findings.len(), 2);
        let lodash = findings
            .iter()
            .find(|f| f.rule == "CVE-2021-23337")
            .unwrap();
        assert_eq!(lodash.line, 3);
        assert!(lodash.message.contains("fixed in 4.17.21"));
        assert!(findings.iter().any(|f| f.rule == "CVE-2021-44906"));
    }

    #[test]
    fn package_json_accepts_fixed_versions_and_bad_input() {
        let fixed = "{\"dependencies\": {\"lodash\": \"^4.17.21\", \"axios\": \"latest\"}}";
        assert!(analyze_package_json(fixed, "p").is_empty());
        assert!(analyze_package_json("not json", "p").is_empty());
        assert!(analyze_package_json("[]", "p").is_empty());
    }

    #[test]
    fn requirements_flags_pinned_vulnerable_versions() {
        let text = "# deps\nrequests==2.25.0\nPyYAML==5.3 # yaml\nflask>=1.0\n-r other.txt\n";
        let findings = analyze_requirements(text, "requirements.txt");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[1].rule, "CVE-2020-14343");
    }

    #[test]
    fn requirements_handle_extras_markers_and_normalization() {
        let text = "Pillow[extra]==9.0.0 ; python_version > '3'\nPy_YAML==5.4\nurllib3<=1.0\n";
        let findings = analyze_requirements(text, "requirements.txt");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "CVE-2023-4863");
    }

    #[test]
    fn split_requirement_rules() {
        assert_eq!(
            split_requirement("requests==2.0"),
            Some(("requests".to_string(), "2.0".to_string()))
        );
        assert_eq!(split_requirement("requests>=2.0"), None);
        assert_eq!(split_requirement("requests"), None);
        assert_eq!(split_requirement("==1.0"), None);
    }
}
