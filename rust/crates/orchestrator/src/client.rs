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

/// Header line for the bearer token; refuses characters that could inject headers.
fn auth_header(token: Option<&str>) -> Result<String> {
    let Some(token) = token else {
        return Ok(String::new());
    };
    if token.is_empty() || token.chars().any(|c| c.is_control() || c == ' ') {
        bail!("the token must not be empty or contain spaces or control characters");
    }
    Ok(format!("Authorization: Bearer {token}\r\n"))
}

/// Sends one request and returns the HTTP status and the response body.
pub async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> Result<(u16, String)> {
    let body = body.unwrap_or("");
    let auth = auth_header(token)?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{auth}\
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
pub async fn run(command: &Command, token: Option<&str>) -> Result<()> {
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
        Command::Publish { topic, data, api } => {
            let data: Value = serde_json::from_str(data).context("--data must be valid JSON")?;
            if !data.is_object() {
                bail!("--data must be a JSON object");
            }
            let body = json!({ "topic": topic, "data": data }).to_string();
            (api.addr, "POST", "/events".to_string(), Some(body))
        }
        Command::History { limit, api } => {
            let path = match limit {
                Some(count) => format!("/events/recent?limit={count}"),
                None => "/events/recent".to_string(),
            };
            (api.addr, "GET", path, None)
        }
        Command::Validate | Command::Serve { .. } => bail!("not a client command"),
    };
    let (status, text) = request(addr, method, &path, body.as_deref(), token).await?;
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

    use crate::api::router_with_token;
    use crate::supervisor::{Orchestrator, RunOptions};

    async fn serve_empty(token: Option<&str>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let orchestrator = Orchestrator::start(Vec::new(), RunOptions::default());
        let shared = Arc::new(Mutex::new(orchestrator));
        let app = router_with_token(shared, token.map(str::to_string));
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

    #[test]
    fn token_header_is_built_and_checked() {
        assert_eq!(auth_header(None).unwrap(), "");
        let line = auth_header(Some("abc123")).unwrap();
        assert_eq!(line, "Authorization: Bearer abc123\r\n");
        for bad in ["", "a b", "a\r\nX-Evil: 1", "tab\there"] {
            assert!(auth_header(Some(bad)).is_err(), "accepted {bad:?}");
        }
    }

    #[tokio::test]
    async fn talks_to_a_real_api_server() {
        let addr = serve_empty(None).await;
        let (status, body) = request(addr, "GET", "/health", None, None).await.unwrap();
        assert_eq!(status, 200);
        assert!(body.contains("ok"));
        let (status, _) = request(addr, "POST", "/modules/missing/stop", None, None)
            .await
            .unwrap();
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn publish_and_history_reach_the_server() {
        let addr = serve_empty(None).await;
        let body = r#"{"topic":"host.ping","data":{}}"#;
        let (status, _) = request(addr, "POST", "/events", Some(body), None)
            .await
            .unwrap();
        assert_eq!(status, 202);
        let mut seen = String::new();
        for _ in 0..100 {
            let (status, text) = request(addr, "GET", "/events/recent?limit=5", None, None)
                .await
                .unwrap();
            assert_eq!(status, 200);
            seen = text;
            if seen.contains("host.ping") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(seen.contains("host.ping"), "history was {seen}");
    }

    #[tokio::test]
    async fn token_is_sent_and_enforced() {
        let token = "0123456789abcdef";
        let addr = serve_empty(Some(token)).await;
        let (denied, _) = request(addr, "GET", "/modules", None, None).await.unwrap();
        assert_eq!(denied, 401);
        let (wrong, _) = request(addr, "GET", "/modules", None, Some("wrong-token"))
            .await
            .unwrap();
        assert_eq!(wrong, 401);
        let (allowed, body) = request(addr, "GET", "/modules", None, Some(token))
            .await
            .unwrap();
        assert_eq!(allowed, 200);
        assert_eq!(body.trim(), "[]");
    }

    #[tokio::test]
    async fn unreachable_server_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(request(addr, "GET", "/health", None, None).await.is_err());
    }
}
