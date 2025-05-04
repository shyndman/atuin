use axum::Json;
use tracing::{debug, instrument};

use crate::handlers::ErrorResponseStatus;
use crate::router::UserAuth;

use atuin_common::api::*;

#[instrument(skip_all, fields(user.id = user.id))]
pub async fn get(
    UserAuth(user): UserAuth,
) -> Result<Json<MeResponse>, ErrorResponseStatus<'static>> {
    debug!("Handling get me request for user {}", user.id);
    debug!("Returning MeResponse with username: {}", user.username);
    Ok(Json(MeResponse {
        username: user.username,
    }))
}
