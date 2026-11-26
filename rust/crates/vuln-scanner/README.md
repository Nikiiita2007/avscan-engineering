# vuln-scanner

Module `vuln_scanner` of the AVScan Rust ecosystem. It scans project files and
produces a JSON report. Secrets in the report are always masked.

## What it checks

- Secrets in Dockerfile, package.json, requirements*.txt, `.env*` and common
  config files (`yml`, `yaml`, `ini`, `cfg`, `conf`, `toml`): AWS, GitHub, Slack,
  Google, Stripe, JWT, private key headers and entropy-based hard-coded credentials.
- Vulnerable dependency versions from a small **built-in snapshot** database
  (npm and PyPI). It is not exhaustive: always confirm with the vendor advisory.
- Dockerfile practices: unpinned or `:latest` base images, end-of-life base images,
  no non-root `USER`, `curl | sh`, `chmod 777`, `ADD` with a remote URL.

## Usage

Standalone (prints the report as JSON, exit code 1 if a high or critical finding exists):

    vuln-scanner scan <path>...

As an AVScan module (no arguments; protocol over stdin/stdout, logs only to stderr):

- manifest: `rust/modules/vuln_scanner/module.json`
- config keys: `paths`, `max_depth`, `max_file_kb`, `max_findings`
- if `paths` is not empty the module scans on start
- event `vuln_scanner.scan` with `data.paths` triggers a scan
- result is published as event `vuln_scanner.report`

Note: forwarding bus events to modules is implemented in the orchestrator in stage 6.
