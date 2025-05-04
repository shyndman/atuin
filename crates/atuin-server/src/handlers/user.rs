use std::borrow::Borrow;
use std::collections::HashMap;
use std::time::Duration;

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use metrics::counter;

use postmark::{Query, reqwest::PostmarkClient};

use rand::rngs::OsRng;
use tracing::{debug, error, info, instrument};

use super::{ErrorResponse, ErrorResponseStatus, RespExt};
use crate::router::{AppState, UserAuth};
use atuin_server_database::{
    Database, DbError,
    models::{NewSession, NewUser},
};

use reqwest::header::CONTENT_TYPE;

use atuin_common::{api::*, utils::crypto_random_string};

pub fn verify_str(hash: &str, password: &str) -> bool {
    debug!("Verifying password against hash");
    let arg2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    let Ok(hash) = PasswordHash::new(hash) else {
        debug!("Failed to parse password hash");
        return false;
    };
    let is_verified = arg2.verify_password(password.as_bytes(), &hash).is_ok();
    debug!("Password verification result: {}", is_verified);
    is_verified
}

// Try to send a Discord webhook once - if it fails, we don't retry. "At most once", and best effort.
// Don't return the status because if this fails, we don't really care.
async fn send_register_hook(url: &str, username: String, registered: String) {
    debug!("Attempting to send register webhook to {}", url);
    let hook = HashMap::from([
        ("username", username),
        ("content", format!("{registered} has just signed up!")),
    ]);

    let client = reqwest::Client::new();

    let resp = client
        .post(url)
        .timeout(Duration::new(5, 0))
        .header(CONTENT_TYPE, "application/json")
        .json(&hook)
        .send()
        .await;

    match resp {
        Ok(_) => info!("register webhook sent ok!"),
        Err(e) => error!("failed to send register webhook: {}", e),
    }
}

#[instrument(skip_all, fields(user.username = username.as_str()))]
pub async fn get<DB: Database>(
    Path(username): Path<String>,
    state: State<AppState<DB>>,
) -> Result<Json<UserResponse>, ErrorResponseStatus<'static>> {
    debug!("Handling get user request for username: {}", username);
    let db = &state.0.database;
    debug!("Calling db.get_user");
    let user = match db.get_user(username.as_ref()).await {
        Ok(user) => {
            debug!("User found: {}", user.username);
            user
        }
        Err(DbError::NotFound) => {
            debug!("user not found: {}", username);
            return Err(ErrorResponse::reply("user not found").with_status(StatusCode::NOT_FOUND));
        }
        Err(DbError::Other(err)) => {
            error!("database error: {}", err);
            return Err(ErrorResponse::reply("database error")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    debug!("Returning user response");
    Ok(Json(UserResponse {
        username: user.username,
    }))
}

#[instrument(skip_all)]
pub async fn register<DB: Database>(
    state: State<AppState<DB>>,
    Json(register): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ErrorResponseStatus<'static>> {
    debug!("Handling register request for username: {}", register.username);
    if !state.settings.open_registration {
        debug!("Registration is closed");
        return Err(
            ErrorResponse::reply("this server is not open for registrations")
                .with_status(StatusCode::BAD_REQUEST),
        );
    }
    debug!("Registration is open");

    debug!("Validating username characters");
    for c in register.username.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => {}
            _ => {
                debug!("Invalid character '{}' in username", c);
                return Err(ErrorResponse::reply(
                    "Only alphanumeric and hyphens (-) are allowed in usernames",
                )
                .with_status(StatusCode::BAD_REQUEST));
            }
        }
    }
    debug!("Username characters are valid");

    debug!("Hashing password");
    let hashed = hash_secret(&register.password);
    debug!("Password hashed");

    let new_user = NewUser {
        email: register.email.clone(),
        username: register.username.clone(),
        password: hashed,
    };
    debug!("Created NewUser struct");

    let db = &state.0.database;
    debug!("Calling db.add_user");
    let user_id = match db.add_user(&new_user).await {
        Ok(id) => {
            debug!("User added successfully with ID: {}", id);
            id
        }
        Err(e) => {
            error!("failed to add user: {}", e);
            debug!("db.add_user failed");
            return Err(
                ErrorResponse::reply("failed to add user").with_status(StatusCode::BAD_REQUEST)
            );
        }
    };

    // 24 bytes encoded as base64
    debug!("Generating session token");
    let token = crypto_random_string::<24>();
    debug!("Session token generated");

    let new_session = NewSession {
        user_id,
        token: (&token).into(),
    };
    debug!("Created NewSession struct");

    if let Some(url) = &state.settings.register_webhook_url {
        debug!("Sending register webhook");
        // Could probs be run on another thread, but it's ok atm
        send_register_hook(
            url,
            state.settings.register_webhook_username.clone(),
            register.username,
        )
        .await;
        debug!("Register webhook sent");
    }

    counter!("atuin_users_registered", 1);
    debug!("Incremented atuin_users_registered counter");

    debug!("Calling db.add_session");
    match db.add_session(&new_session).await {
        Ok(_) => {
            debug!("Session added successfully");
            debug!("Returning register response with session token");
            Ok(Json(RegisterResponse { session: token }))
        }
        Err(e) => {
            error!("failed to add session: {}", e);
            debug!("db.add_session failed");
            Err(ErrorResponse::reply("failed to register user")
                .with_status(StatusCode::BAD_REQUEST))
        }
    }
}

#[instrument(skip_all, fields(user.id = user.id))]
pub async fn delete<DB: Database>(
    UserAuth(user): UserAuth,
    state: State<AppState<DB>>,
) -> Result<Json<DeleteUserResponse>, ErrorResponseStatus<'static>> {
    debug!("Handling delete user request for user {}", user.id);
    debug!("request to delete user {}", user.id);

    let db = &state.0.database;
    debug!("Calling db.delete_user");
    if let Err(e) = db.delete_user(&user).await {
        error!("failed to delete user: {}", e);
        debug!("db.delete_user failed");

        return Err(ErrorResponse::reply("failed to delete user")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR));
    };
    debug!("db.delete_user successful");

    counter!("atuin_users_deleted", 1);
    debug!("Incremented atuin_users_deleted counter");

    debug!("Returning delete user response");
    Ok(Json(DeleteUserResponse {}))
}

#[instrument(skip_all, fields(user.id = user.id))]
pub async fn send_verification<DB: Database>(
    UserAuth(user): UserAuth,
    state: State<AppState<DB>>,
) -> Result<Json<SendVerificationResponse>, ErrorResponseStatus<'static>> {
    debug!("Handling send verification request for user {}", user.id);
    let settings = state.0.settings;
    debug!("request to verify user {}", user.username);

    if !settings.mail.enabled {
        debug!("Mail is not enabled, returning email_sent: false, verified: false");
        return Ok(Json(SendVerificationResponse {
            email_sent: false,
            verified: false,
        }));
    }
    debug!("Mail is enabled");

    if user.verified.is_some() {
        debug!("User is already verified, returning email_sent: false, verified: true");
        return Ok(Json(SendVerificationResponse {
            email_sent: false,
            verified: true,
        }));
    }
    debug!("User is not yet verified");

    // TODO: if we ever add another mail provider, can match on them all here.
    let postmark_token = match settings.mail.postmark.token {
        Some(token) => {
            debug!("Postmark token found");
            token
        }
        _ => {
            error!("Failed to verify email: got None for postmark token");
            debug!("Postmark token not found, returning mail not configured error");
            return Err(ErrorResponse::reply("mail not configured")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    let db = &state.0.database;
    debug!("Calling db.user_verification_token");
    let verification_token = db
        .user_verification_token(user.id)
        .await
        .expect("Failed to verify"); // TODO: Handle this error properly
    debug!("Generated verification token");

    debug!("Generated verification token, emailing user");

    let client = PostmarkClient::builder()
        .base_url("https://api.postmarkapp.com/")
        .server_token(postmark_token)
        .build();
    debug!("Postmark client built");

    let req = postmark::api::email::SendEmailRequest::builder()
        .from(settings.mail.verification.from.clone()) // Clone from for logging
        .subject(settings.mail.verification.subject.clone()) // Clone subject for logging
        .to(user.email.clone()) // Clone email for logging
        .body(postmark::api::Body::text(format!(
            "Please run the following command to finalize your Atuin account verification. It is valid for 15 minutes:\n\natuin account verify --token '{}'",
            verification_token
        )))
        .build();
    debug!("Postmark email request built");

    debug!("Executing Postmark email request");
    req.execute(&client)
        .await
        .expect("postmark email request failed"); // TODO: Handle this error properly
    debug!("Email sent successfully");

    debug!("Returning send verification response");
    Ok(Json(SendVerificationResponse {
        email_sent: true,
        verified: false,
    }))
}

#[instrument(skip_all, fields(user.id = user.id))]
pub async fn verify_user<DB: Database>(
    UserAuth(user): UserAuth,
    state: State<AppState<DB>>,
    Json(token_request): Json<VerificationTokenRequest>,
) -> Result<Json<VerificationTokenResponse>, ErrorResponseStatus<'static>> {
    debug!("Handling verify user request for user {}", user.id);
    debug!("Token request: {:?}", token_request);
    let db = state.0.database;

    if user.verified.is_some() {
        debug!("User is already verified, returning verified: true");
        return Ok(Json(VerificationTokenResponse { verified: true }));
    }
    debug!("User is not yet verified");

    debug!("Calling db.user_verification_token");
    let token = db.user_verification_token(user.id).await.map_err(|e| {
        error!("Failed to read user token: {e}");
        debug!("db.user_verification_token failed");

        ErrorResponse::reply("Failed to verify").with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    debug!("Received verification token from DB");

    if token_request.token == token {
        debug!("Provided token matches token from DB, verifying user");
        db.verify_user(user.id).await.map_err(|e| {
            error!("Failed to verify user: {e}");
            debug!("db.verify_user failed");

            ErrorResponse::reply("Failed to verify").with_status(StatusCode::INTERNAL_SERVER_ERROR)
        })?;
        debug!("User verified successfully");
    } else {
        info!(
            "Incorrect verification token {} vs {}",
            token_request.token, token
        );
        debug!("Provided token does not match token from DB, returning verified: false");

        return Ok(Json(VerificationTokenResponse { verified: false }));
    }

    debug!("Returning verified: true response");
    Ok(Json(VerificationTokenResponse { verified: true }))
}

#[instrument(skip_all, fields(user.id = user.id, change_password))]
pub async fn change_password<DB: Database>(
    UserAuth(mut user): UserAuth,
    state: State<AppState<DB>>,
    Json(change_password): Json<ChangePasswordRequest>,
) -> Result<Json<ChangePasswordResponse>, ErrorResponseStatus<'static>> {
    debug!("Handling change password request for user {}", user.id);
    let db = &state.0.database;

    debug!("Verifying current password");
    let verified = verify_str(
        user.password.as_str(),
        change_password.current_password.borrow(),
    );
    if !verified {
        debug!("Current password verification failed");
        return Err(
            ErrorResponse::reply("password is not correct").with_status(StatusCode::UNAUTHORIZED)
        );
    }
    debug!("Current password verified successfully");

    debug!("Hashing new password");
    let hashed = hash_secret(&change_password.new_password);
    debug!("New password hashed");
    user.password = hashed;

    debug!("Calling db.update_user_password");
    if let Err(e) = db.update_user_password(&user).await {
        error!("failed to change user password: {}", e);
        debug!("db.update_user_password failed");

        return Err(ErrorResponse::reply("failed to change user password")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR));
    };
    debug!("db.update_user_password successful");

    debug!("Password changed successfully, returning response");
    Ok(Json(ChangePasswordResponse {}))
}

#[instrument(skip_all, fields(user.username = login.username.as_str()))]
pub async fn login<DB: Database>(
    state: State<AppState<DB>>,
    login: Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ErrorResponseStatus<'static>> {
    debug!("Handling login request for username: {}", login.username);
    let db = &state.0.database;
    debug!("Calling db.get_user");
    let user = match db.get_user(login.username.borrow()).await {
        Ok(u) => {
            debug!("User found: {}", u.username);
            u
        }
        Err(DbError::NotFound) => {
            debug!("User not found: {}", login.username);
            return Err(ErrorResponse::reply("user not found").with_status(StatusCode::NOT_FOUND));
        }
        Err(DbError::Other(e)) => {
            error!("failed to get user {}: {}", login.username.clone(), e);
            debug!("db.get_user failed");

            return Err(ErrorResponse::reply("database error")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    debug!("Calling db.get_user_session");
    let session = match db.get_user_session(&user).await {
        Ok(u) => {
            debug!("User session found for user id={}", user.id);
            u
        }
        Err(DbError::NotFound) => {
            debug!("user session not found for user id={}", user.id);
            return Err(ErrorResponse::reply("user not found").with_status(StatusCode::NOT_FOUND));
        }
        Err(DbError::Other(err)) => {
            error!("database error for user {}: {}", login.username, err);
            debug!("db.get_user_session failed");
            return Err(ErrorResponse::reply("database error")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    debug!("Verifying password");
    let verified = verify_str(user.password.as_str(), login.password.borrow());

    if !verified {
        debug!(user = user.username, "login failed");
        return Err(
            ErrorResponse::reply("password is not correct").with_status(StatusCode::UNAUTHORIZED)
        );
    }
    debug!("Password verified successfully");

    debug!(user = user.username, "login success");
    debug!("Returning login response with session token");

    Ok(Json(LoginResponse {
        session: session.token,
    }))
}

fn hash_secret(password: &str) -> String {
    debug!("Hashing secret");
    let arg2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    let salt = SaltString::generate(&mut OsRng);
    let hash = arg2.hash_password(password.as_bytes(), &salt).unwrap();
    debug!("Secret hashed");
    hash.to_string()
}
