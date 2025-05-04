use async_trait::async_trait;
use atuin_common::api::{ATUIN_CARGO_VERSION, ATUIN_HEADER_VERSION, ErrorResponse};
use axum::{
    Router,
    extract::{FromRequestParts, Request},
    http::{self, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use tracing::debug;
use eyre::Result;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use super::handlers;
use crate::{
    handlers::{ErrorResponseStatus, RespExt},
    metrics,
    settings::Settings,
};
use atuin_server_database::{Database, DbError, models::User};

pub struct UserAuth(pub User);

#[async_trait]
impl<DB: Send + Sync> FromRequestParts<AppState<DB>> for UserAuth
where
    DB: Database,
{
    type Rejection = ErrorResponseStatus<'static>;

    async fn from_request_parts(
        req: &mut Parts,
        state: &AppState<DB>,
    ) -> Result<Self, Self::Rejection> {
        debug!("Extracting user authentication from request parts");
        let auth_header = req
            .headers
            .get(http::header::AUTHORIZATION)
            .ok_or_else(|| {
                ErrorResponse::reply("missing authorization header")
                    .with_status(http::StatusCode::BAD_REQUEST)
            })?;
        debug!("Authorization header found");
        let auth_header = auth_header.to_str().map_err(|_| {
            ErrorResponse::reply("invalid authorization header encoding")
                .with_status(http::StatusCode::BAD_REQUEST)
        })?;
        debug!("Authorization header decoded");
        let (typ, token) = auth_header.split_once(' ').ok_or_else(|| {
            ErrorResponse::reply("invalid authorization header encoding")
                .with_status(http::StatusCode::BAD_REQUEST)
        })?;
        debug!("Authorization header split into type '{}' and token", typ);

        if typ != "Token" {
            return Err(
                ErrorResponse::reply("invalid authorization header encoding")
                    .with_status(http::StatusCode::BAD_REQUEST),
            );
        }

        debug!("Querying database for session user with token");
        let user = state
            .database
            .get_session_user(token)
            .await
            .map_err(|e| match e {
                DbError::NotFound => ErrorResponse::reply("session not found")
                    .with_status(http::StatusCode::FORBIDDEN),
                DbError::Other(e) => {
                    tracing::error!(error = ?e, "could not query user session");
                    ErrorResponse::reply("could not query user session")
                        .with_status(http::StatusCode::INTERNAL_SERVER_ERROR)
                }
            })?;
        debug!("Session user found: {:?}", user.username);

        Ok(UserAuth(user))
    }
}

async fn teapot() -> impl IntoResponse {
    debug!("Handling fallback route (teapot)");
    // This used to return 418: 🫖
    // Much as it was fun, it wasn't as useful or informative as it should be
    (http::StatusCode::NOT_FOUND, "404 not found")
}

async fn clacks_overhead(request: Request, next: Next) -> Response {
    debug!("Running clacks_overhead middleware");
    let mut response = next.run(request).await;

    let gnu_terry_value = "GNU Terry Pratchett, Kris Nova";
    let gnu_terry_header = "X-Clacks-Overhead";

    debug!("Adding X-Clacks-Overhead header");
    response
        .headers_mut()
        .insert(gnu_terry_header, gnu_terry_value.parse().unwrap());
    response
}

/// Ensure that we only try and sync with clients on the same major version
async fn semver(request: Request, next: Next) -> Response {
    debug!("Running semver middleware");
    let mut response = next.run(request).await;
    debug!("Adding Atuin version header: {}", ATUIN_CARGO_VERSION);
    response
        .headers_mut()
        .insert(ATUIN_HEADER_VERSION, ATUIN_CARGO_VERSION.parse().unwrap());

    response
}

#[derive(Clone)]
pub struct AppState<DB: Database> {
    pub database: DB,
    pub settings: Settings<DB::Settings>,
}

pub fn router<DB: Database>(database: DB, settings: Settings<DB::Settings>) -> Router {
    debug!("Building main application router");
    let routes = Router::new()
        .route("/", get(handlers::index))
        .route("/healthz", get(handlers::health::health_check))
        .route("/sync/count", get(handlers::history::count))
        .route("/sync/history", get(handlers::history::list))
        .route("/sync/calendar/:focus", get(handlers::history::calendar))
        .route("/sync/status", get(handlers::status::status))
        .route("/history", post(handlers::history::add))
        .route("/history", delete(handlers::history::delete))
        .route("/user/:username", get(handlers::user::get))
        .route("/account", delete(handlers::user::delete))
        .route("/account/password", patch(handlers::user::change_password))
        .route("/register", post(handlers::user::register))
        .route("/login", post(handlers::user::login))
        .route("/record", post(handlers::record::post::<DB>))
        .route("/record", get(handlers::record::index::<DB>))
        .route("/record/next", get(handlers::record::next))
        .route("/api/v0/me", get(handlers::v0::me::get))
        .route("/api/v0/account/verify", post(handlers::user::verify_user))
        .route(
            "/api/v0/account/send-verification",
            post(handlers::user::send_verification),
        )
        .route("/api/v0/record", post(handlers::v0::record::post))
        .route("/api/v0/record", get(handlers::v0::record::index))
        .route("/api/v0/record/next", get(handlers::v0::record::next))
        .route("/api/v0/store", delete(handlers::v0::store::delete));
    debug!("Defined application routes");

    let path = settings.path.as_str();
    let router_with_path = if path.is_empty() {
        debug!("No path prefix configured");
        routes
    } else {
        debug!("Nesting routes under path prefix: {}", path);
        Router::new().nest(path, routes)
    };

    debug!("Adding fallback handler and application state");
    let router_with_state = router_with_path
        .fallback(teapot)
        .with_state(AppState { database, settings });

    debug!("Applying middleware layers");
    let final_router = router_with_state.layer(
        ServiceBuilder::new()
            .layer(axum::middleware::from_fn(clacks_overhead))
            .layer(TraceLayer::new_for_http())
            .layer(axum::middleware::from_fn(metrics::track_metrics))
            .layer(axum::middleware::from_fn(semver)),
    );
    debug!("Router build complete");
    final_router
}
