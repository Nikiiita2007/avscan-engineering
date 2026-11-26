//! Authentication log analysis.
//!
//! Pipeline: [`parse`] turns log lines into events, [`hunter`] applies the
//! [`rules`] and produces [`alert`]s. [`follow`] feeds the same pipeline from a
//! growing file and [`module`] wraps everything in the AVScan module protocol.

pub mod alert;
pub mod follow;
pub mod hunter;
pub mod module;
pub mod net;
pub mod parse;
pub mod rules;
#[cfg(test)]
mod test_util;
