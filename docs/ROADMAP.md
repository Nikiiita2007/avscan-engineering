# Roadmap: Rust orchestrator and security modules

Branch: `feat/rust-orchestrator-modules`. The C++ code is not modified; all Rust code lives in `rust/` (Cargo workspace).

- [x] Stage 0: repository analysis, architecture, roadmap, branch, draft PR
- [ ] Stage 1: workspace, `avscan-protocol` and `avscan-manifest` crates, orchestrator skeleton, Rust CI
- [ ] Stage 2: orchestrator spawns modules, handshake, supervisor and restarts, event bus
- [ ] Stage 3: `vuln_scanner` MVP (rules, JSON report, tests)
- [ ] Stage 4: `net_analyzer` MVP (pcap/localhost, anomaly rules, events, tests)
- [ ] Stage 5: `log_hunter` MVP (log parsing, IOC, events, tests)
- [ ] Stage 6: CLI (clap), HTTP API, SSE, integration tests
- [ ] Stage 7: docs, example configs, final checks, PR ready for review

## Rules

- One commit and one push per stage (Conventional Commits, no force push).
- After every stage: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo build` must pass.
- No secrets in the repository; authentication via `gh auth` / `GH_TOKEN`.
- No external databases: files and in-memory structures only.

## Open questions / assumptions

- The frame length is little-endian (as in `libs/host/protocol.hpp`), not big-endian as the task text says. The wire format of the existing C++ host wins.
- `vuln_scanner` vs. the existing `vuln_parser` manifest: a new manifest is added under `rust/`, the existing one is not changed.
- The module transport (stdio vs. other) is confirmed against `libs/host/module_host.hpp` before Stage 2.
- `net_analyzer` MVP reads pcap files and listens on localhost only; no raw-socket capture.
