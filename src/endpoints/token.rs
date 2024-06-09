use crate::primitives::{AuthCode, ClientId};
use crate::{AppState};
use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{debug_handler, Form, Json};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use openidconnect::core::CoreTokenType;
use openidconnect::{AccessToken, EmptyExtraTokenFields, StandardTokenResponse};
use serde::Deserialize;
use std::time::Instant;
use subtle::ConstantTimeEq;
use url::Url;

#[debug_handler]
pub async fn token(
    State(app_state): State<AppState>,
    authenticated_client: Option<AuthenticatedClient>,
    Form(auth_token_request): Form<OAuthTokenRequest>,
) -> Result<impl IntoResponse, TokenError> {
    let client = authenticated_client
        .or_else(|| {
            auth_token_request.client_secret().and_then(|secret| {
                map_authenticated_client(
                    app_state.clone(),
                    auth_token_request.client_id().clone(),
                    secret,
                )
            })
        })
        .ok_or(TokenError::ClientUnAuthenticated)?;

    match auth_token_request {
        OAuthTokenRequest::AuthorizationCode {
            code,
            redirect_uri,
            client_id,
            ..
        } => {
            let mut guard = app_state.active_auth_code_flows.lock().await;
            let auth_state = guard
                .remove(&code)
                .filter(|auth_state| auth_state.expiry > Instant::now())
                .filter(|auth_state| {
                    auth_state.client_id == client.client_id
                        && auth_state.client_id == client_id
                        && auth_state.redirect_uri == redirect_uri
                })
                .ok_or(TokenError::AuthFlowNotFound)?;
            Ok(Json(StandardTokenResponse::new(
                AccessToken::new("dummy_access_token".to_string()),
                CoreTokenType::Bearer,
                EmptyExtraTokenFields {},
            )))
        }
        _ => Err(TokenError::FlowNotSupported),
    }
}

#[derive(Deserialize)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum OAuthTokenRequest {
    AuthorizationCode {
        code: AuthCode,
        redirect_uri: Url,
        client_id: ClientId,
        client_secret: Option<String>,
    },
    Password {
        username: String,
        password: String,
        client_id: ClientId,
        client_secret: Option<String>,
    },
    ClientCredentials {
        client_id: ClientId,
        client_secret: Option<String>,
    },
    RefreshToken {
        refresh_token: String,
        client_id: ClientId,
        client_secret: Option<String>,
    },
}

impl OAuthTokenRequest {
    fn client_id(&self) -> &ClientId {
        match self {
            OAuthTokenRequest::AuthorizationCode { client_id, .. } => client_id,
            OAuthTokenRequest::Password { client_id, .. } => client_id,
            OAuthTokenRequest::ClientCredentials { client_id, .. } => client_id,
            OAuthTokenRequest::RefreshToken { client_id, .. } => client_id,
        }
    }
    fn client_secret(&self) -> Option<&str> {
        match self {
            OAuthTokenRequest::AuthorizationCode { client_secret, .. } => client_secret.as_deref(),
            OAuthTokenRequest::Password { client_secret, .. } => client_secret.as_deref(),
            OAuthTokenRequest::ClientCredentials { client_secret, .. } => client_secret.as_deref(),
            OAuthTokenRequest::RefreshToken { client_secret, .. } => client_secret.as_deref(),
        }
    }
}

pub struct AuthenticatedClient {
    client_id: ClientId,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedClient
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let invalid_err = || (StatusCode::UNAUTHORIZED, "Invalid authorization header");
        let header_split = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or_else(invalid_err)?
            .to_str()
            .map_err(|_| invalid_err())?
            .split_once(' ')
            .ok_or_else(invalid_err)?;
        match header_split {
            ("Basic", value) => {
                let decoded = BASE64_STANDARD.decode(value).map_err(|_| invalid_err())?;
                let decoded_str = String::from_utf8(decoded).map_err(|_| invalid_err())?;
                let (client_id, client_secret) =
                    decoded_str.split_once(':').ok_or_else(invalid_err)?;
                let client_id = ClientId::new(client_id);
                let app_state = AppState::from_ref(state);
                map_authenticated_client(app_state, client_id, client_secret)
                    .ok_or((StatusCode::UNAUTHORIZED, "Invalid credentials"))
            }
            _ => Err(invalid_err()),
        }
    }
}

fn map_authenticated_client(
    state: AppState,
    client_id: ClientId,
    client_secret: &str,
) -> Option<AuthenticatedClient> {
    let is_authenticated_client = state
        .config
        .clients
        .get(&client_id)
        .map(|c| c.secret.as_bytes().ct_eq(client_secret.as_bytes()).into())
        .unwrap_or(false);
    if is_authenticated_client {
        Some(AuthenticatedClient { client_id })
    } else {
        None
    }
}

pub enum TokenError {
    ClientUnAuthenticated,
    AuthFlowNotFound,
    FlowNotSupported,
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        match self {
            TokenError::ClientUnAuthenticated => {
                (StatusCode::UNAUTHORIZED, "Client unauthenticated").into_response()
            }
            TokenError::AuthFlowNotFound => {
                (StatusCode::UNAUTHORIZED, "AuthFlow not found").into_response()
            }
            TokenError::FlowNotSupported => {
                (StatusCode::BAD_REQUEST, "Flow not supported").into_response()
            }
        }
    }
}
