use atuin_common::api::{ErrorResponse, IndexResponse};
use atuin_server_database::Database;
use axum::{Json, extract::State, http, response::IntoResponse};
use tracing::debug;

use crate::router::AppState;

pub mod health;
pub mod history;
pub mod record;
pub mod status;
pub mod user;
pub mod v0;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn index<DB: Database>(state: State<AppState<DB>>) -> Json<IndexResponse> {
    debug!("Handling index request");
    let homage = r#""Through the fathomless deeps of space swims the star turtle Great A'Tuin, bearing on its back the four giant elephants who carry on their shoulders the mass of the Discworld." -- Sir Terry Pratchett"#;

    // Error with a -1 response
    // It's super unlikely this will happen
    let count = state.database.total_history().await.unwrap_or(-1);
    debug!("Total history count: {}", count);

    let version = state
        .settings
        .fake_version
        .clone()
        .unwrap_or(VERSION.to_string());
    debug!("Server version: {}", version);

    debug!("Returning index response");
    Json(IndexResponse {
        homage: homage.to_string(),
        total_history: count,
        version,
    })
}

impl IntoResponse for ErrorResponseStatus<'_> {
    fn into_response(self) -> axum::response::Response {
        debug!("Converting ErrorResponseStatus to response with status: {:?}", self.status);
        (self.status, Json(self.error)).into_response()
    }
}

pub struct ErrorResponseStatus<'a> {
    pub error: ErrorResponse<'a>,
    pub status: http::StatusCode,
}

pub trait RespExt<'a> {
    fn with_status(self, status: http::StatusCode) -> ErrorResponseStatus<'a>;
    fn reply(reason: &'a str) -> Self;
}

impl<'a> RespExt<'a> for ErrorResponse<'a> {
    fn with_status(self, status: http::StatusCode) -> ErrorResponseStatus<'a> {
        ErrorResponseStatus {
            error: self,
            status,
        }
    }

    fn reply(reason: &'a str) -> ErrorResponse<'a> {
        Self {
            reason: reason.into(),
        }
    }
}
