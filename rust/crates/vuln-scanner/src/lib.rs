//! Scanner for secrets, vulnerable dependencies and risky Dockerfile practices.
//!
//! The library is used by the standalone `vuln-scanner scan` command and by the
//! AVScan module runtime in [`module`].

pub mod dockerfile;
pub mod manifests;
pub mod module;
pub mod report;
pub mod scan;
pub mod secrets;
#[cfg(test)]
mod test_util;
pub mod versions;
