mod errors;
mod models;

use crate::app_state::AuthCodeState;
use crate::oauth::clients::ClientValidation;
use crate::oauth::primitives::AuthCode;
use crate::routes::authorize::errors::AuthErr;
use crate::routes::authorize::models::AuthorizeParameters;
use crate::AppState;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::Form;
use std::time::{Duration, Instant};

pub async fn get_authorize(
    State(app_state): State<AppState>,
    Query(params): Query<AuthorizeParameters>,
) -> impl IntoResponse {
    handle_auth_request(app_state, params).await
}

pub async fn post_authorize(
    State(app_state): State<AppState>,
    Form(params): Form<AuthorizeParameters>,
) -> impl IntoResponse {
    handle_auth_request(app_state, params).await
}

async fn handle_auth_request(
    app_state: AppState,
    params: AuthorizeParameters,
) -> Result<Redirect, AuthErr> {
    let AuthorizeParameters {
        scope,
        response_type,
        client_id,
        redirect_uri,
        state,
        nonce,
        pkce_code_challenge,
        response_mode,
    } = params;

    let valid_redirect_url = app_state
        .validate_redirect(&client_id, redirect_uri)
        .await?;

    // TODO authorize{}

    let auth_code = AuthCode::new_random();
    let auth_code_redirect = valid_redirect_url.auth_code_redirect(&auth_code, state);

    let code_expiry = Instant::now()
        .checked_add(Duration::from_secs(60))
        .ok_or(AuthErr::InternalServerError)?;

    let auth_code_state = AuthCodeState {
        expiry: code_expiry,
        scope,
        response_type,
        client_id,
        nonce,
        pkce_code_challenge,
        redirect_uri: valid_redirect_url.url(),
    };

    let mut guard = app_state.active_auth_code_flows.lock().await;
    guard.insert(auth_code, auth_code_state);

    Ok(Redirect::to(auth_code_redirect.as_str()))
}
