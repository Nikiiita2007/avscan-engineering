//! `vuln-scanner` binary: AVScan module (no arguments) or standalone scanner
//! (`vuln-scanner scan <path>...`).

use std::path::PathBuf;
use std::process::ExitCode;

use vuln_scanner::module;
use vuln_scanner::scan::{scan_paths, ScanOptions};

const USAGE: &str = "usage:\n  vuln-scanner scan <path>...   scan files and print a JSON report\n  vuln-scanner                  run as an AVScan module (protocol on stdin/stdout)";

fn cli_scan(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let paths: Vec<PathBuf> = args.iter().map(PathBuf::from).collect();
    let report = scan_paths(&paths, &ScanOptions::default());
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("vuln-scanner: cannot serialize the report: {e}");
            return ExitCode::FAILURE;
        }
    }
    if report.has_serious() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args.first().map(String::as_str) == Some("scan") {
        return cli_scan(&args[1..]);
    }
    if !args.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    match module::run(std::io::stdin().lock(), std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vuln-scanner: {e}");
            ExitCode::FAILURE
        }
    }
}
