//! `net-analyzer` binary: AVScan module (no arguments) or standalone tool.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use net_analyzer::alert::{Alert, Severity};
use net_analyzer::analyzer::analyze_reader;
use net_analyzer::listen::{AlertSink, Listener};
use net_analyzer::module;
use net_analyzer::rules::Rules;
use serde_json::json;

const USAGE: &str = "usage:\n  net-analyzer analyze <file.pcap>...   print a JSON report\n  net-analyzer listen <127.0.0.1:port>  analyze a pcap stream, one JSON alert per line\n  net-analyzer                          run as an AVScan module (protocol on stdin/stdout)";

fn analyze_one(path: &str) -> Result<serde_json::Value, String> {
    let file = File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut alerts: Vec<Alert> = Vec::new();
    let stats = analyze_reader(BufReader::new(file), &Rules::default(), |a| alerts.push(a))
        .map_err(|e| format!("{path}: {e}"))?;
    Ok(json!({ "file": path, "stats": stats, "alerts": alerts }))
}

fn cli_analyze(paths: &[String]) -> ExitCode {
    if paths.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let mut reports = Vec::new();
    let mut serious = false;
    for path in paths {
        match analyze_one(path) {
            Ok(report) => {
                let alerts = report["alerts"].as_array().cloned().unwrap_or_default();
                serious |= alerts.iter().any(|a| a["severity"] == "high");
                reports.push(report);
            }
            Err(e) => {
                eprintln!("net-analyzer: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    match serde_json::to_string_pretty(&json!({ "files": reports })) {
        Ok(text) => println!("{text}"),
        Err(e) => {
            eprintln!("net-analyzer: cannot serialize the report: {e}");
            return ExitCode::FAILURE;
        }
    }
    if serious {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn cli_listen(args: &[String]) -> ExitCode {
    let Some(text) = args.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Ok(addr) = text.parse::<SocketAddr>() else {
        eprintln!("net-analyzer: invalid address '{text}'");
        return ExitCode::from(2);
    };
    let sink: AlertSink = Arc::new(|alert: &Alert| {
        if let Ok(line) = serde_json::to_string(alert) {
            println!("{line}");
        }
    });
    let listener = match Listener::start(addr, Rules::default(), sink) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("net-analyzer: cannot listen on {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("net-analyzer: listening on {}", listener.addr);
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match args.first().map(String::as_str) {
        Some("analyze") => cli_analyze(&args[1..]),
        Some("listen") => cli_listen(&args[1..]),
        Some(_) => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        None => match module::run(std::io::stdin().lock(), Box::new(std::io::stdout())) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("net-analyzer: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

#[allow(dead_code)]
fn _severity_is_used(severity: Severity) -> Severity {
    severity
}
