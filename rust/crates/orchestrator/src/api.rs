//! Read-only API and bounded live SSE subscription.
//!
//! The API deliberately permits only loopback binds. Event replay and scan
//! commands are not implemented in this increment. Lag is reported explicitly.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Json, Router};
use futures_core::Stream;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio::sync::broadcast::error::RecvError;

use crate::supervisor::{ModuleStatus, Orchestrator};

pub type Shared = Arc<Mutex<Orchestrator>>;

#[derive(Debug, Serialize)]
struct Status {
    id: String,
    state: &'static str,
    restart_attempt: Option<u32>,
    error: Option<String>,
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

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn modules(State(shared): State<Shared>) -> Json<Vec<Status>> {
    let values = shared.lock().await.statuses();
    Json(values.into_iter().map(|(id, s)| status(id, s)).collect())
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
        .route("/events", get(events))
        .with_state(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::supervisor::RunOptions;

    fn app() -> Router {
        let orchestrator = Orchestrator::start(Vec::new(), RunOptions::default());
        router(Arc::new(Mutex::new(orchestrator)))
    }

    #[tokio::test]
    async fn health_is_json() {
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["status"], "ok");
    }

    #[tokio::test]
    async fn modules_can_be_empty() {
        let req = Request::builder().uri("/modules").body(Body::empty()).unwrap();
        let response = app().oneshot(req).await.unwrap();
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value, json!([]));
    }

    #[tokio::test]
    async fn events_use_sse_content_type() {
        let req = Request::builder().uri("/events").body(Body::empty()).unwrap();
        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
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
