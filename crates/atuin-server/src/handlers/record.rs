use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;
use tracing::{debug, instrument};

use super::{ErrorResponse, ErrorResponseStatus, RespExt};
use crate::router::UserAuth;
use atuin_server_database::Database;

use atuin_common::record::{EncryptedData, Record};

#[instrument(skip_all, fields(user.id = user.id))]
pub async fn post<DB: Database>(
    UserAuth(user): UserAuth,
) -> Result<(), ErrorResponseStatus<'static>> {
    debug!("Handling deprecated record post request for user {}", user.id);
    // anyone who has actually used the old record store (a very small number) will see this error
    // upon trying to sync.
    // 1. The status endpoint will say that the server has nothing
    // 2. The client will try to upload local records
    // 3. Sync will fail with this error

    // If the client has no local records, they will see the empty index and do nothing. For the
    // vast majority of users, this is the case.
    debug!("Returning deprecated record store error");
    return Err(
        ErrorResponse::reply("record store deprecated; please upgrade")
            .with_status(StatusCode::BAD_REQUEST),
    );
}

#[instrument(skip_all, fields(user.id = user.id))]
pub async fn index<DB: Database>(UserAuth(user): UserAuth) -> axum::response::Response {
    debug!("Handling deprecated record index request for user {}", user.id);
    let ret = json!({
        "hosts": {}
    });
    debug!("Returning empty hosts JSON");

    ret.to_string().into_response()
}

#[instrument(skip_all, fields(user.id = user.id))]
pub async fn next(
    UserAuth(user): UserAuth,
) -> Result<Json<Vec<Record<EncryptedData>>>, ErrorResponseStatus<'static>> {
    debug!("Handling deprecated record next request for user {}", user.id);
    let records = Vec::new();
    debug!("Returning empty records vector");

    Ok(Json(records))
}
