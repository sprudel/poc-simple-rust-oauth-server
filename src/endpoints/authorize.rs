use crate::primitives::AuthCode;
use crate::{AppState, AuthCodeState};
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
        mut redirect_uri,
        state,
        nonce,
        pkce_code_challenge,
        response_mode,
    } = params;
    let client_config = app_state
        .config
        .clients
        .get(&client_id)
        .ok_or_else(|| AuthErr::InvalidClientId(client_id.clone()))?;
    if client_config.redirect_uri != redirect_uri || redirect_uri.cannot_be_a_base() {
        return Err(AuthErr::InvalidRedirectUri(redirect_uri));
    }
    let orig_redirect_uri = redirect_uri.clone();
    if let Some(state) = state {
        redirect_uri
            .query_pairs_mut()
            .append_pair("state", state.secret());
    }

    // TODO authorize{}

    let auth_code = AuthCode::new_random();
    redirect_uri
        .query_pairs_mut()
        .append_pair("code", auth_code.as_str());

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
        redirect_uri: orig_redirect_uri,
    };
    let mut guard = app_state.active_auth_code_flows.lock().await;
    guard.insert(auth_code, auth_code_state);

    Ok(Redirect::to(redirect_uri.as_str()))
}

enum AuthErr {
    InvalidClientId(ClientId),
    InvalidRedirectUri(Url),
    InternalServerError,
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
        }
    }
}
