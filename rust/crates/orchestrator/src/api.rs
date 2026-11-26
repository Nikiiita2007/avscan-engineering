//! HTTP API: module status, module control and a live SSE subscription.
//!
//! The API deliberately permits only loopback binds. Control routes:
//! `POST /modules/{id}/start`, `POST /modules/{id}/stop` and
//! `POST /modules/{id}/command` (body: `name`, optional `args`). The command
//! `name` must be a capability declared by the module. SSE has no replay;
//! lag is reported explicitly.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::Mutex;

use crate::supervisor::{ControlError, ModuleStatus, Orchestrator};

pub type Shared = Arc<Mutex<Orchestrator>>;

/// How long a command request waits for the module's answer.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

type ApiError = (StatusCode, Json<Value>);

#[derive(Debug, Serialize)]
struct Status {
    id: String,
    state: &'static str,
    restart_attempt: Option<u32>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CommandRequest {
    name: String,
    #[serde(default)]
    args: Map<String, Value>,
}

fn status(id: String, value: ModuleStatus) -> Status {
    let (state, restart_attempt, error) = match value {
        ModuleStatus::Starting => ("starting", None, None),
        ModuleStatus::Running => ("running", None, None),
        ModuleStatus::Restarting { attempt } => ("restarting", Some(attempt), None),
        ModuleStatus::Stopped => ("stopped", None, None),
        ModuleStatus::Failed(reason) => ("failed", None, Some(reason)),
    };
    Status {
        id,
        state,
        restart_attempt,
        error,
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

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn modules(State(shared): State<Shared>) -> Json<Vec<Status>> {
    let values = shared.lock().await.statuses();
    Json(values.into_iter().map(|(id, s)| status(id, s)).collect())
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

/// SSE is live-only: clients receive events published after subscribing.
pub fn router(shared: Shared) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/modules", get(modules))
        .route("/modules/{id}/start", post(start))
        .route("/modules/{id}/stop", post(stop))
        .route("/modules/{id}/command", post(command))
        .route("/events", get(events))
        .with_state(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::supervisor::RunOptions;

    fn app() -> Router {
        let orchestrator = Orchestrator::start(Vec::new(), RunOptions::default());
        router(Arc::new(Mutex::new(orchestrator)))
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

    #[test]
    fn failure_details_and_restart_attempts_are_preserved() {
        let failed = status("x".into(), ModuleStatus::Failed("reason".into()));
        assert_eq!(failed.state, "failed");
        assert_eq!(failed.error.as_deref(), Some("reason"));
        let restarting = status("x".into(), ModuleStatus::Restarting { attempt: 2 });
        assert_eq!(restarting.restart_attempt, Some(2));
    }
}
