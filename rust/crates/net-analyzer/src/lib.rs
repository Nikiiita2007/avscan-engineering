//! Passive network traffic analyzer.
//!
//! Pipeline: [`pcap`] reads captures, [`decode`] parses packets, [`dns`] parses
//! DNS questions, [`analyzer`] applies the [`rules`] and produces [`alert`]s.
//! [`listen`] feeds the same pipeline from a localhost TCP stream and [`module`]
//! wraps everything in the AVScan module protocol.

pub mod alert;
pub mod analyzer;
pub mod decode;
pub mod dns;
pub mod listen;
pub mod module;
pub mod pcap;
pub mod rules;
#[cfg(test)]
mod test_util;
