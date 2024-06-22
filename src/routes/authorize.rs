use crate::app_state::AuthCodeState;
use crate::oauth::clients::ClientValidation;
use crate::oauth::primitives::AuthCode;
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use openidconnect::core::{CoreResponseMode, CoreResponseType};
use openidconnect::{ClientId, CsrfToken, Nonce, PkceCodeChallenge, ResponseTypes};
use serde::Deserialize;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Deserialize)]
pub struct AuthorizeParameters {
    scope: String,
    response_type: ResponseTypes<CoreResponseType>,
    client_id: ClientId,
    redirect_uri: Url,
    state: Option<CsrfToken>,
    nonce: Option<Nonce>,
    #[serde(flatten)]
    pkce_code_challenge: Option<PkceCodeChallenge>,
    response_mode: Option<CoreResponseMode>,
}

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

pub enum AuthErr {
    InvalidClientId(ClientId),
    InvalidRedirectUri(Url),
    InternalServerError,
    FailedClientAuth,
}

impl IntoResponse for AuthErr {
    fn into_response(self) -> Response {
        match self {
            AuthErr::InvalidClientId(client_id) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid client id: {}", client_id.as_str()),
            )
                .into_response(),
            AuthErr::InvalidRedirectUri(url) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid redirect_uri: {url}"),
            )
                .into_response(),
            AuthErr::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            AuthErr::FailedClientAuth => {
                (StatusCode::UNAUTHORIZED, "Invalid client").into_response()
            }
        }
    }
}
