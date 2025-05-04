use axum::{Json, extract::State, http::StatusCode};
use tracing::{debug, instrument, error};

use super::{ErrorResponse, ErrorResponseStatus, RespExt};
use crate::router::{AppState, UserAuth};
use atuin_server_database::Database;

use atuin_common::api::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[instrument(skip_all, fields(user.id = user.id))]
pub async fn status<DB: Database>(
    UserAuth(user): UserAuth,
    state: State<AppState<DB>>,
) -> Result<Json<StatusResponse>, ErrorResponseStatus<'static>> {
    debug!("Handling status request for user {}", user.id);
    let db = &state.0.database;

    debug!("Calling db.deleted_history");
    let deleted = db.deleted_history(&user).await.unwrap_or(vec![]);
    debug!("db.deleted_history returned {} deleted items", deleted.len());

    debug!("Attempting to get cached history count");
    let count = match db.count_history_cached(&user).await {
        // By default read out the cached value
        Ok(count) => {
            debug!("Using cached history count: {}", count);
            count
        }

        // If that fails, fallback on a full COUNT. Cache is built on a POST
        // only
        Err(e) => {
            debug!("Failed to get cached history count: {:?}, falling back to full count", e);
            match db.count_history(&user).await {
                Ok(count) => {
                    debug!("Using full history count: {}", count);
                    count
                }
                Err(e) => {
                    error!("failed to query history count: {}", e);
                    return Err(ErrorResponse::reply("failed to query history count")
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR));
                }
            }
        }
    };

    tracing::debug!(user = user.username, "requested sync status");
    debug!("Returning status response");

    Ok(Json(StatusResponse {
        count,
        deleted,
        username: user.username,
        version: VERSION.to_string(),
        page_size: state.settings.page_size,
    }))
}
