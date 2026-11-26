//! `log-hunter` binary: AVScan module (no arguments) or standalone tool.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use log_hunter::alert::Alert;
use log_hunter::follow::{AlertSink, Follower, Notify};
use log_hunter::hunter::hunt_reader;
use log_hunter::module;
use log_hunter::rules::Rules;
use serde_json::json;

const USAGE: &str = "usage:\n  log-hunter analyze <auth.log>...   print a JSON report\n  log-hunter follow <auth.log>       print one JSON alert per line while the file grows\n  log-hunter                         run as an AVScan module (protocol on stdin/stdout)";

fn analyze_one(path: &str) -> Result<serde_json::Value, String> {
    let file = File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut alerts: Vec<Alert> = Vec::new();
    let stats = hunt_reader(BufReader::new(file), &Rules::default(), |a| alerts.push(a))
        .map_err(|e| format!("{path}: {e}"))?;
    Ok(json!({ "file": path, "stats": stats, "alerts": alerts }))
}

fn is_serious(alert: &serde_json::Value) -> bool {
    let severity = alert["severity"].as_str().unwrap_or("");
    severity == "high" || severity == "critical"
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
                serious |= alerts.iter().any(is_serious);
                reports.push(report);
            }
            Err(e) => {
                eprintln!("log-hunter: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    match serde_json::to_string_pretty(&json!({ "files": reports })) {
        Ok(text) => println!("{text}"),
        Err(e) => {
            eprintln!("log-hunter: cannot serialize the report: {e}");
            return ExitCode::FAILURE;
        }
    }
    if serious {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn cli_follow(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let sink: AlertSink = Arc::new(|alert: &Alert| {
        if let Ok(line) = serde_json::to_string(alert) {
            println!("{line}");
        }
    });
    let notify: Notify = Arc::new(|text: &str| eprintln!("log-hunter: {text}"));
    let _follower = Follower::start(PathBuf::from(path), Rules::default(), sink, notify);
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
        Some("follow") => cli_follow(&args[1..]),
        Some(_) => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        None => match module::run(std::io::stdin().lock(), Box::new(std::io::stdout())) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("log-hunter: {e}");
                ExitCode::FAILURE
            }
        },
    }
}
