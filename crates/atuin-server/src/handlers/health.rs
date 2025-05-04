use axum::{Json, http, response::IntoResponse};
use tracing::debug;

use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

pub async fn health_check() -> impl IntoResponse {
    debug!("Handling health check request");
    (
        http::StatusCode::OK,
        Json(HealthResponse { status: "healthy" }),
    )
}
