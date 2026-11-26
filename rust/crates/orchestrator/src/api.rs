//! HTTP API: module status, module control and a live SSE subscription.
//!
//! The API deliberately permits only loopback binds. `GET /modules` lists the
//! state of every module together with the capabilities of its manifest;
//! those names are the valid command names. Control routes:
//! `POST /modules/{id}/start`, `POST /modules/{id}/stop` and
//! `POST /modules/{id}/command` (body: `name`, optional `args`). The command
//! `name` must be a capability declared by the module. `POST /events`
//! (body: `topic`, optional object `data`) publishes an event from the host;
//! modules whose manifest subscribes to the topic receive it. SSE has no
//! replay; lag is reported explicitly, and `GET /events/recent` returns the
//! last events the orchestrator remembers (oldest first, no timestamps).
//!
//! Requests that a web page could send are refused with 403: a `Host` header
//! that is not a loopback name (DNS rebinding) and an `Origin` header that is
//! not this very server (cross-site requests). Clients without these headers,
//! such as curl and the CLI, are not affected.
//!
//! With a token every route except `GET /health` requires the header
//! `Authorization: Bearer <token>`; without one the API is open to every local
//! process. The token travels in clear text, which is acceptable on loopback.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::header::{AUTHORIZATION, HOST, ORIGIN, WWW_AUTHENTICATE};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::Mutex;

use crate::supervisor::{ControlError, ModuleInfo, ModuleStatus, Orchestrator, HISTORY_LIMIT};

pub type Shared = Arc<Mutex<Orchestrator>>;

/// How long a command request waits for the module's answer.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest accepted topic name of a published event.
const MAX_TOPIC_LEN: usize = 64;
/// How many events `GET /events/recent` returns without a `limit`.
const DEFAULT_RECENT: usize = 100;

type ApiError = (StatusCode, Json<Value>);

#[derive(Debug, Serialize)]
struct Status {
    id: String,
    state: &'static str,
    restart_attempt: Option<u32>,
    error: Option<String>,
    capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CommandRequest {
    name: String,
    #[serde(default)]
    args: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct PublishRequest {
    topic: String,
    #[serde(default)]
    data: Value,
}

#[derive(Debug, Deserialize)]
struct RecentQuery {
    limit: Option<usize>,
}

fn status(info: ModuleInfo) -> Status {
    let (state, restart_attempt, error) = match info.status {
        ModuleStatus::Starting => ("starting", None, None),
        ModuleStatus::Running => ("running", None, None),
        ModuleStatus::Restarting { attempt } => ("restarting", Some(attempt), None),
        ModuleStatus::Stopped => ("stopped", None, None),
        ModuleStatus::Failed(reason) => ("failed", None, Some(reason)),
    };
    Status {
        id: info.id,
        state,
        restart_attempt,
        error,
        capabilities: info.capabilities,
    }
}

fn fail(error: ControlError) -> ApiError {
    let code = match error {
        ControlError::UnknownModule(_) => StatusCode::NOT_FOUND,
        ControlError::AlreadyRunning | ControlError::NotRunning => StatusCode::CONFLICT,
        ControlError::QueueFull => StatusCode::TOO_MANY_REQUESTS,
    };
    (code, Json(json!({"error": error.to_string()})))
}

fn bad_request(text: &str) -> ApiError {
    (StatusCode::BAD_REQUEST, Json(json!({"error": text})))
}

fn forbidden(text: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({"error": text}))).into_response()
}

/// Lowercase letters, digits, `_` and `.`; no empty segments.
fn valid_topic(topic: &str) -> bool {
    let allowed = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.');
    let shaped = !topic.starts_with('.') && !topic.ends_with('.') && !topic.contains("..");
    (1..=MAX_TOPIC_LEN).contains(&topic.len()) && shaped && topic.chars().all(allowed)
}

/// Name part of a `Host` header value: the port is cut off, IPv6 brackets stay.
fn host_name(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority
            .find(']')
            .map_or(authority, |end| &authority[..=end]);
    }
    match authority.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => authority,
    }
}

fn is_loopback_host(authority: &str) -> bool {
    let name = host_name(authority);
    name == "127.0.0.1" || name == "[::1]" || name.eq_ignore_ascii_case("localhost")
}

/// Refuses requests that a web page could send. A `Host` that is not a
/// loopback name is a DNS rebinding attempt. An `Origin` must be this server
/// itself (`http://` plus the `Host` value); browsers send it on cross-site
/// requests, so a foreign page cannot control the API.
async fn guard_origin(request: Request, next: Next) -> Response {
    let headers = request.headers();
    let host = headers.get(HOST).and_then(|value| value.to_str().ok());
    if let Some(host) = host {
        if !is_loopback_host(host) {
            return forbidden("the Host header is not a loopback address");
        }
    }
    if let Some(origin) = headers.get(ORIGIN) {
        let authority = origin
            .to_str()
            .ok()
            .and_then(|value| value.strip_prefix("http://"));
        let same = match (authority, host) {
            (Some(authority), Some(host)) => authority.eq_ignore_ascii_case(host),
            _ => false,
        };
        if !same {
            return forbidden("cross-origin requests are not allowed");
        }
    }
    next.run(request).await
}

/// Compares in time that depends only on the length of the expected token.
fn same_token(given: &[u8], expected: &[u8]) -> bool {
    let mut diff = given.len() ^ expected.len();
    for (i, byte) in expected.iter().enumerate() {
        let other = given.get(i).copied().unwrap_or(0);
        diff |= usize::from(byte ^ other);
    }
    diff == 0
}

async fn require_token(State(token): State<Arc<String>>, request: Request, next: Next) -> Response {
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }
    let given = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match given {
        Some(given) if same_token(given.as_bytes(), token.as_bytes()) => next.run(request).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(WWW_AUTHENTICATE, "Bearer")],
            Json(json!({"error": "missing or invalid bearer token"})),
        )
            .into_response(),
    }
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn modules(State(shared): State<Shared>) -> Json<Vec<Status>> {
    let values = shared.lock().await.describe();
    Json(values.into_iter().map(status).collect())
}

async fn start(
    State(shared): State<Shared>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    shared.lock().await.start_module(&id).map_err(fail)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"module": id, "action": "start"})),
    ))
}

async fn stop(
    State(shared): State<Shared>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    shared.lock().await.stop_module(&id).map_err(fail)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"module": id, "action": "stop"})),
    ))
}

async fn command(
    State(shared): State<Shared>,
    Path(id): Path<String>,
    Json(request): Json<CommandRequest>,
) -> Result<Json<Value>, ApiError> {
    let queued = shared.lock().await.command(&id, request.name, request.args);
    let outcome = queued.map_err(fail)?;
    match tokio::time::timeout(COMMAND_TIMEOUT, outcome).await {
        Ok(Ok(result)) => Ok(Json(json!({"ok": result.ok, "error": result.error}))),
        Ok(Err(_)) => Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "module ended before it answered"})),
        )),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({"error": "module did not answer in time"})),
        )),
    }
}

/// Publishes an event from the host. The answer only says how many bus
/// receivers existed; modules decide by their `subscribes` list.
async fn publish(
    State(shared): State<Shared>,
    Json(request): Json<PublishRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if !valid_topic(&request.topic) {
        return Err(bad_request("invalid topic"));
    }
    let data = match request.data {
        Value::Null => json!({}),
        data @ Value::Object(_) => data,
        _ => return Err(bad_request("data must be a JSON object")),
    };
    let receivers = shared.lock().await.publish(&request.topic, data);
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"topic": request.topic, "receivers": receivers})),
    ))
}

/// The last events the orchestrator remembers, oldest first.
async fn recent(
    State(shared): State<Shared>,
    Query(query): Query<RecentQuery>,
) -> Json<Vec<Value>> {
    let limit = query.limit.unwrap_or(DEFAULT_RECENT).min(HISTORY_LIMIT);
    let events = shared.lock().await.recent(limit);
    let shown = |event: crate::bus::BusEvent| {
        json!({"topic": event.topic, "source": event.source, "data": event.data})
    };
    Json(events.into_iter().map(shown).collect())
}

async fn events(
    State(shared): State<Shared>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut receiver = shared.lock().await.subscribe();
    let stream = async_stream::stream! {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    let data = json!({
                        "topic": event.topic,
                        "source": event.source,
                        "data": event.data,
                    });
                    yield Ok(Event::default().event("module_event").data(data.to_string()));
                }
                Err(RecvError::Lagged(count)) => {
                    let data = json!({"dropped": count});
                    yield Ok(Event::default().event("lagged").data(data.to_string()));
                }
                Err(RecvError::Closed) => break,
            }
        }
    };
    let keep_alive = KeepAlive::new().interval(Duration::from_secs(15));
    Sse::new(stream).keep_alive(keep_alive)
}

/// The API without authentication.
pub fn router(shared: Shared) -> Router {
    router_with_token(shared, None)
}

/// SSE is live-only: clients receive events published after subscribing.
/// With `Some(token)` every route except `/health` needs that bearer token.
/// The Host and Origin guard runs first and covers every route.
pub fn router_with_token(shared: Shared, token: Option<String>) -> Router {
    let app = Router::new()
        .route("/health", get(health))
        .route("/modules", get(modules))
        .route("/modules/{id}/start", post(start))
        .route("/modules/{id}/stop", post(stop))
        .route("/modules/{id}/command", post(command))
        .route("/events", get(events).post(publish))
        .route("/events/recent", get(recent))
        .with_state(shared);
    let app = match token {
        Some(token) => {
            let guard = middleware::from_fn_with_state(Arc::new(token), require_token);
            app.layer(guard)
        }
        None => app,
    };
    app.layer(middleware::from_fn(guard_origin))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use avscan_manifest::{parse_manifest, HOST_API_VERSION};
    use axum::body::{to_bytes, Body};
    use tower::ServiceExt;

    use crate::supervisor::{ModuleSpec, RunOptions};

    fn app() -> Router {
        let orchestrator = Orchestrator::start(Vec::new(), RunOptions::default());
        router(Arc::new(Mutex::new(orchestrator)))
    }

    fn app_with_token(token: &str) -> Router {
        let orchestrator = Orchestrator::start(Vec::new(), RunOptions::default());
        router_with_token(Arc::new(Mutex::new(orchestrator)), Some(token.to_string()))
    }

    fn get_request(uri: &str, auth: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri(uri);
        if let Some(value) = auth {
            builder = builder.header("authorization", value);
        }
        builder.body(Body::empty()).unwrap()
    }

    fn request_with(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    fn publish_request(body: &str, auth: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/events")
            .header("content-type", "application/json");
        if let Some(value) = auth {
            builder = builder.header("authorization", value);
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    async fn status_of(app: Router, request: Request<Body>) -> StatusCode {
        app.oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn health_is_json() {
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["status"], "ok");
    }

    #[tokio::test]
    async fn modules_can_be_empty() {
        let req = Request::builder()
            .uri("/modules")
            .body(Body::empty())
            .unwrap();
        let response = app().oneshot(req).await.unwrap();
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value, json!([]));
    }

    #[tokio::test]
    async fn modules_list_their_capabilities() {
        let text = r#"{"id":"ghost_mod","name":"Ghost","version":"0.1.0","api_version":1,"entry":{"exe":"ghost"},"capabilities":["scan.run"],"restart":{"policy":"never","max_restarts":0}}"#;
        let spec = ModuleSpec {
            manifest: parse_manifest(text, HOST_API_VERSION).unwrap(),
            binary: PathBuf::from("definitely-missing-binary-xyz"),
            extra_args: Vec::new(),
            config_override: Map::new(),
        };
        let orchestrator = Orchestrator::start(vec![spec], RunOptions::default());
        let app = router(Arc::new(Mutex::new(orchestrator)));
        let response = app.oneshot(get_request("/modules", None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value[0]["id"], "ghost_mod");
        assert_eq!(value[0]["capabilities"], json!(["scan.run"]));
    }

    #[tokio::test]
    async fn recent_events_are_listed_oldest_first() {
        let orchestrator = Orchestrator::start(Vec::new(), RunOptions::default());
        orchestrator.publish("host.one", json!({ "n": 1 }));
        orchestrator.publish("host.two", json!({ "n": 2 }));
        for _ in 0..300 {
            if orchestrator.recent(10).len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let app = router(Arc::new(Mutex::new(orchestrator)));
        let response = app
            .clone()
            .oneshot(get_request("/events/recent", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 2);
        assert_eq!(value[0]["topic"], "host.one");
        assert_eq!(value[1]["source"], "host");
        assert_eq!(value[1]["data"]["n"], 2);
        let limited = app
            .oneshot(get_request("/events/recent?limit=1", None))
            .await
            .unwrap();
        let bytes = to_bytes(limited.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(value[0]["topic"], "host.two");
    }

    #[tokio::test]
    async fn recent_rejects_a_bad_limit_and_needs_the_token() {
        let bad = status_of(app(), get_request("/events/recent?limit=abc", None)).await;
        assert_eq!(bad, StatusCode::BAD_REQUEST);
        let token = "0123456789abcdef";
        let denied = status_of(app_with_token(token), get_request("/events/recent", None)).await;
        assert_eq!(denied, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn events_use_sse_content_type() {
        let req = Request::builder()
            .uri("/events")
            .body(Body::empty())
            .unwrap();
        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
    }

    #[tokio::test]
    async fn control_of_unknown_module_is_not_found() {
        for action in ["start", "stop"] {
            let req = Request::builder()
                .method("POST")
                .uri(format!("/modules/missing/{action}"))
                .body(Body::empty())
                .unwrap();
            let response = app().oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{action}");
        }
    }

    #[tokio::test]
    async fn command_for_unknown_module_is_not_found() {
        let req = Request::builder()
            .method("POST")
            .uri("/modules/missing/command")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"scan.run"}"#))
            .unwrap();
        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn foreign_hosts_are_refused() {
        let foreign = ["evil.example", "evil.example:8787", "10.0.0.5:8787"];
        let rebinding = ["127.0.0.1.evil.example", "localhost.evil.example"];
        for host in foreign.iter().chain(rebinding.iter()) {
            let req = request_with("GET", "/health", &[("host", host)]);
            let status = status_of(app(), req).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{host}");
        }
    }

    #[tokio::test]
    async fn loopback_hosts_are_accepted() {
        let local = [
            "127.0.0.1:8787",
            "localhost:8787",
            "LOCALHOST",
            "[::1]:8787",
        ];
        for host in local {
            let req = request_with("GET", "/health", &[("host", host)]);
            let status = status_of(app(), req).await;
            assert_eq!(status, StatusCode::OK, "{host}");
        }
    }

    #[tokio::test]
    async fn cross_site_requests_are_refused() {
        let host = ("host", "127.0.0.1:8787");
        let foreign = ["http://evil.example", "https://127.0.0.1:8787", "null"];
        let other = ["http://127.0.0.1:9999", "http://localhost:8787"];
        for origin in foreign.iter().chain(other.iter()) {
            let headers = [host, ("origin", origin)];
            let req = request_with("POST", "/modules/missing/stop", &headers);
            let status = status_of(app(), req).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{origin}");
        }
    }

    #[tokio::test]
    async fn same_origin_and_headerless_requests_pass_the_guard() {
        let host = ("host", "127.0.0.1:8787");
        let same = [host, ("origin", "http://127.0.0.1:8787")];
        let req = request_with("POST", "/modules/missing/stop", &same);
        assert_eq!(status_of(app(), req).await, StatusCode::NOT_FOUND);
        let req = request_with("POST", "/modules/missing/stop", &[host]);
        assert_eq!(status_of(app(), req).await, StatusCode::NOT_FOUND);
        let req = request_with("POST", "/modules/missing/stop", &[]);
        assert_eq!(status_of(app(), req).await, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_origin_without_a_host_is_refused() {
        let headers = [("origin", "http://127.0.0.1:8787")];
        let req = request_with("POST", "/modules/missing/stop", &headers);
        assert_eq!(status_of(app(), req).await, StatusCode::FORBIDDEN);
    }

    #[test]
    fn host_names_are_extracted() {
        assert_eq!(host_name("127.0.0.1:8787"), "127.0.0.1");
        assert_eq!(host_name("localhost"), "localhost");
        assert_eq!(host_name("[::1]:8787"), "[::1]");
        assert_eq!(host_name("[::1]"), "[::1]");
        assert!(is_loopback_host("[::1]:1"));
        assert!(!is_loopback_host("[::2]:1"));
    }

    #[tokio::test]
    async fn publish_accepts_valid_events() {
        let body = r#"{"topic":"vuln_scanner.scan","data":{"paths":["/srv"]}}"#;
        let response = app().oneshot(publish_request(body, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["topic"], "vuln_scanner.scan");
        assert_eq!(value["receivers"], 0);
        let no_data = status_of(app(), publish_request(r#"{"topic":"host.ping"}"#, None)).await;
        assert_eq!(no_data, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn publish_rejects_bad_topics_and_data() {
        let bad_bodies = [
            r#"{"topic":""}"#,
            r#"{"topic":"Bad.Topic"}"#,
            r#"{"topic":"a..b"}"#,
            r#"{"topic":".a"}"#,
            r#"{"topic":"a."}"#,
            r#"{"topic":"a b"}"#,
            r#"{"topic":"host.x","data":[1]}"#,
            r#"{"topic":"host.x","data":"text"}"#,
        ];
        for body in bad_bodies {
            let status = status_of(app(), publish_request(body, None)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        }
        let too_long = format!(r#"{{"topic":"{}"}}"#, "a".repeat(MAX_TOPIC_LEN + 1));
        let status = status_of(app(), publish_request(&too_long, None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_needs_the_token_when_one_is_set() {
        let token = "0123456789abcdef";
        let body = r#"{"topic":"host.ping"}"#;
        let denied = status_of(app_with_token(token), publish_request(body, None)).await;
        assert_eq!(denied, StatusCode::UNAUTHORIZED);
        let bearer = format!("Bearer {token}");
        let allowed = publish_request(body, Some(bearer.as_str()));
        let status = status_of(app_with_token(token), allowed).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[test]
    fn topic_names_are_checked() {
        for good in ["a", "host.shutdown", "vuln_scanner.scan", "a1.b2.c3"] {
            assert!(valid_topic(good), "rejected {good:?}");
        }
        for bad in ["", "A", "a-b", "a/b", "a..b", ".a", "a.", "a b", "ä"] {
            assert!(!valid_topic(bad), "accepted {bad:?}");
        }
    }

    #[tokio::test]
    async fn token_protects_everything_except_health() {
        let token = "0123456789abcdef";
        let good_auth = format!("Bearer {token}");
        let bad_auth = "Bearer wrong-token";

        let open = status_of(app_with_token(token), get_request("/health", None)).await;
        assert_eq!(open, StatusCode::OK);
        let none = status_of(app_with_token(token), get_request("/modules", None)).await;
        assert_eq!(none, StatusCode::UNAUTHORIZED);
        let bad = get_request("/modules", Some(bad_auth));
        assert_eq!(
            status_of(app_with_token(token), bad).await,
            StatusCode::UNAUTHORIZED
        );
        let wrong_scheme = get_request("/modules", Some(token));
        assert_eq!(
            status_of(app_with_token(token), wrong_scheme).await,
            StatusCode::UNAUTHORIZED
        );
        let good = get_request("/modules", Some(good_auth.as_str()));
        assert_eq!(status_of(app_with_token(token), good).await, StatusCode::OK);
        let events = get_request("/events", None);
        assert_eq!(
            status_of(app_with_token(token), events).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn the_guard_runs_before_the_token_check() {
        let token = "0123456789abcdef";
        let headers = [("host", "evil.example")];
        let req = request_with("GET", "/health", &headers);
        let status = status_of(app_with_token(token), req).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn tokens_are_compared_exactly() {
        assert!(same_token(b"secret-token", b"secret-token"));
        assert!(!same_token(b"secret-token", b"secret-tokeN"));
        assert!(!same_token(b"secret", b"secret-token"));
        assert!(!same_token(b"secret-token-and-more", b"secret-token"));
        assert!(!same_token(b"", b"secret-token"));
    }

    #[test]
    fn failure_details_and_restart_attempts_are_preserved() {
        let info = |value: ModuleStatus| ModuleInfo {
            id: "x".to_string(),
            status: value,
            capabilities: vec!["scan.run".to_string()],
        };
        let failed = status(info(ModuleStatus::Failed("reason".into())));
        assert_eq!(failed.state, "failed");
        assert_eq!(failed.error.as_deref(), Some("reason"));
        assert_eq!(failed.capabilities, ["scan.run"]);
        let restarting = status(info(ModuleStatus::Restarting { attempt: 2 }));
        assert_eq!(restarting.restart_attempt, Some(2));
    }
}
