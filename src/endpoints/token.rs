use crate::primitives::{AuthCode, ClientId};
use crate::{ActiveAuthCodeFlows, AppState};
use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{debug_handler, Form, RequestPartsExt};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use url::Url;

#[debug_handler]
pub async fn token(
    State(app_state): State<AppState>,
    authenticated_client: Option<AuthenticatedClient>,
    Form(auth_token_request): Form<OAuthTokenRequest>,
) -> impl IntoResponse {
    ""
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
                let is_authenticated = app_state
                    .config
                    .clients
                    .get(&client_id)
                    .map(|c| c.secret.as_bytes().ct_eq(client_secret.as_bytes()).into())
                    .unwrap_or(false);
                if is_authenticated {
                    Ok(AuthenticatedClient { client_id })
                } else {
                    Err((StatusCode::UNAUTHORIZED, "Invalid credentials"))
                }
            }
            _ => Err(invalid_err()),
        }
    }
}
