//! Minimal HTTP client for the CLI commands that talk to a running
//! orchestrator. It speaks plain HTTP/1.1 over loopback TCP and needs no
//! extra dependencies. Responses are limited to 1 MiB.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cli::Command;

const MAX_RESPONSE: u64 = 1 << 20;
/// Longer than the server's 30 s wait for a module to answer a command.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);

fn module_path(id: &str, action: &str) -> Result<String> {
    let safe = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
    if id.is_empty() || id.starts_with('.') || !id.chars().all(safe) {
        bail!("invalid module id '{id}'");
    }
    Ok(format!("/modules/{id}/{action}"))
}

fn parse_response(raw: &[u8]) -> Result<(u16, String)> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .context("malformed HTTP response")?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .context("malformed HTTP status line")?;
    Ok((status, body.to_string()))
}

/// Sends one request and returns the HTTP status and the response body.
pub async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String)> {
    let body = body.unwrap_or("");
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        let mut raw = Vec::new();
        stream.take(MAX_RESPONSE).read_to_end(&mut raw).await?;
        Ok::<_, std::io::Error>(raw)
    };
    let outcome = tokio::time::timeout(REQUEST_TIMEOUT, exchange).await;
    let raw = outcome
        .context("request timed out")?
        .with_context(|| format!("cannot talk to {addr}"))?;
    parse_response(&raw)
}

/// Runs a client command, prints the response body and fails on non-2xx.
pub async fn run(command: &Command) -> Result<()> {
    let (addr, method, path, body) = match command {
        Command::Modules { api } => (api.addr, "GET", "/modules".to_string(), None),
        Command::Start { id, api } => (api.addr, "POST", module_path(id, "start")?, None),
        Command::Stop { id, api } => (api.addr, "POST", module_path(id, "stop")?, None),
        Command::Exec {
            id,
            name,
            args,
            api,
        } => {
            let args: Value = serde_json::from_str(args).context("--args must be valid JSON")?;
            if !args.is_object() {
                bail!("--args must be a JSON object");
            }
            let body = json!({ "name": name, "args": args }).to_string();
            (api.addr, "POST", module_path(id, "command")?, Some(body))
        }
        Command::Validate | Command::Serve { .. } => bail!("not a client command"),
    };
    let (status, text) = request(addr, method, &path, body.as_deref()).await?;
    println!("{}", text.trim());
    if !(200..300).contains(&status) {
        bail!("request failed with HTTP {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    use crate::api::router;
    use crate::supervisor::{Orchestrator, RunOptions};

    async fn serve_empty() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let orchestrator = Orchestrator::start(Vec::new(), RunOptions::default());
        let app = router(Arc::new(Mutex::new(orchestrator)));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    #[test]
    fn module_ids_are_checked() {
        assert_eq!(
            module_path("log_hunter", "stop").unwrap(),
            "/modules/log_hunter/stop"
        );
        for bad in ["", "..", ".hidden", "a/b", "a b", "a?x=1"] {
            assert!(module_path(bad, "stop").is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn parses_status_and_body() {
        let raw = b"HTTP/1.1 404 Not Found\r\ncontent-length: 2\r\n\r\n{}";
        assert_eq!(parse_response(raw).unwrap(), (404, "{}".to_string()));
        assert!(parse_response(b"garbage").is_err());
        assert!(parse_response(b"HTTP/1.1 abc\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn talks_to_a_real_api_server() {
        let addr = serve_empty().await;
        let (status, body) = request(addr, "GET", "/health", None).await.unwrap();
        assert_eq!(status, 200);
        assert!(body.contains("ok"));
        let (status, _) = request(addr, "POST", "/modules/missing/stop", None)
            .await
            .unwrap();
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn unreachable_server_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(request(addr, "GET", "/health", None).await.is_err());
    }
}
