use crate::app_state::AppState;
use crate::oauth::clients::{AuthenticatedClient, ClientValidation};
use crate::oauth::primitives::AuthCode;
use crate::routes::auth::token::errors::TokenError;
use async_trait::async_trait;
use axum::extract::{FromRef, FromRequest, FromRequestParts, Request};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::{Form, RequestExt};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use openidconnect::{ClientId, ClientSecret};
use serde::Deserialize;
use url::Url;

#[derive(Deserialize)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
enum OAuthTokenRequest {
    AuthorizationCode {
        code: AuthCode,
        redirect_uri: Url,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
    },
    Password {
        username: String,
        password: String,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
    },
    ClientCredentials {
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
    },
    RefreshToken {
        refresh_token: String,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
    },
}

impl OAuthTokenRequest {
    pub fn client_id(&self) -> &ClientId {
        match self {
            OAuthTokenRequest::AuthorizationCode { client_id, .. } => client_id,
            OAuthTokenRequest::Password { client_id, .. } => client_id,
            OAuthTokenRequest::ClientCredentials { client_id, .. } => client_id,
            OAuthTokenRequest::RefreshToken { client_id, .. } => client_id,
        }
    }
    pub fn client_secret(&self) -> Option<&ClientSecret> {
        match self {
            OAuthTokenRequest::AuthorizationCode { client_secret, .. } => client_secret.as_ref(),
            OAuthTokenRequest::Password { client_secret, .. } => client_secret.as_ref(),
            OAuthTokenRequest::ClientCredentials { client_secret, .. } => client_secret.as_ref(),
            OAuthTokenRequest::RefreshToken { client_secret, .. } => client_secret.as_ref(),
        }
    }
}

struct BasicAuthHeader {
    client_id: ClientId,
    client_secret: ClientSecret,
}

impl BasicAuthHeader {
    async fn from_parts(parts: &mut Parts) -> Option<Self> {
        let header_split = parts
            .headers
            .get(AUTHORIZATION)?
            .to_str()
            .ok()?
            .split_once(' ')?;
        match header_split {
            ("Basic", value) => {
                let decoded = BASE64_STANDARD.decode(value).ok()?;
                let decoded_str = String::from_utf8(decoded).ok()?;
                let (client_id, client_secret) = decoded_str.split_once(':')?;
                Some(BasicAuthHeader {
                    client_id: ClientId::new(client_id.to_string()),
                    client_secret: ClientSecret::new(client_secret.to_string()),
                })
            }
            _ => None,
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for BasicAuthHeader
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ();
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        BasicAuthHeader::from_parts(parts).await.ok_or(())
    }
}

pub enum ValidatedOauthTokenRequest {
    AuthorizationCode {
        code: AuthCode,
        redirect_uri: Url,
        client: ValidatedClient,
    },
    Password {
        username: String,
        password: String,
        client: ValidatedClient,
    },
    ClientCredentials {
        client: ValidatedClient,
    },
    RefreshToken {
        refresh_token: String,
        client: ValidatedClient,
    },
}

impl ValidatedOauthTokenRequest {
    fn from_request_and_validated_client(req: OAuthTokenRequest, client: ValidatedClient) -> Self {
        match req {
            OAuthTokenRequest::AuthorizationCode {
                code, redirect_uri, ..
            } => ValidatedOauthTokenRequest::AuthorizationCode {
                code,
                redirect_uri,
                client,
            },
            OAuthTokenRequest::Password {
                username, password, ..
            } => ValidatedOauthTokenRequest::Password {
                username,
                password,
                client,
            },
            OAuthTokenRequest::ClientCredentials { .. } => {
                ValidatedOauthTokenRequest::ClientCredentials { client }
            }
            OAuthTokenRequest::RefreshToken { refresh_token, .. } => {
                ValidatedOauthTokenRequest::RefreshToken {
                    refresh_token,
                    client,
                }
            }
        }
    }
}

pub enum ValidatedClient {
    AuthenticatedConfidentialClient(ClientId),
}

impl From<AuthenticatedClient> for ValidatedClient {
    fn from(value: AuthenticatedClient) -> Self {
        ValidatedClient::AuthenticatedConfidentialClient(value.client_id)
    }
}

#[async_trait]
impl<S> FromRequest<S> for ValidatedOauthTokenRequest
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = TokenError;

    async fn from_request(mut req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let basic_auth_authenticated_client = req
            .extract_parts_with_state::<BasicAuthHeader, S>(state)
            .await
            .ok();
        let Form(request_body) = Form::<OAuthTokenRequest>::from_request(req, state)
            .await
            .map_err(|_| TokenError::BadRequest)?;
        let (client_id, client_secret) = match (
            basic_auth_authenticated_client.as_ref(),
            request_body.client_secret(),
        ) {
            (Some(basic_auth), _) => (&basic_auth.client_id, &basic_auth.client_secret),
            (None, Some(secret)) => (request_body.client_id(), secret),
            _ => return Err(TokenError::ClientUnAuthenticated),
        };

        let app_state = AppState::from_ref(state);
        let validated_client = app_state
            .authenticate_client(client_id, client_secret.secret().as_str())
            .await?
            .into();

        Ok(
            ValidatedOauthTokenRequest::from_request_and_validated_client(
                request_body,
                validated_client,
            ),
        )
    }
}
