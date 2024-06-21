use crate::endpoints::authorize::{AuthErr, ClientValidation};
use crate::primitives::AuthCode;
use crate::AppState;
use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{debug_handler, Form, Json};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJwsSigningAlgorithm, CoreTokenResponse,
    CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, ClientId, EmptyAdditionalClaims, EmptyExtraTokenFields, IssuerUrl,
    JsonWebTokenError, RefreshToken, StandardClaims, SubjectIdentifier,
};
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
    let client = match (authenticated_client, auth_token_request.client_secret()) {
        (Some(c), _) => c,
        (None, Some(secret)) => app_state
            .authenticate_client(auth_token_request.client_id(), secret)
            .await
            .map_err(|_| TokenError::ClientUnAuthenticated)?,
        _ => Err(TokenError::ClientUnAuthenticated)?,
    };

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
            let key = &app_state.config.json_web_key;
            let access_token = AccessToken::new("dummy_access_token".to_string());
            let id_token = CoreIdToken::new(
                CoreIdTokenClaims::new(
                    IssuerUrl::from_url(app_state.config.issuer.clone()),
                    vec![Audience::new(client_id.as_str().to_string())],
                    // The ID token expiration is usually much shorter than that of the access or refresh
                    // tokens issued to clients.
                    Utc::now() + Duration::seconds(300),
                    // The issue time is usually the current time.
                    Utc::now(),
                    // Set the standard claims defined by the OpenID Connect Core spec.
                    StandardClaims::new(
                        // Stable subject identifiers are recommended in place of e-mail addresses or other
                        // potentially unstable identifiers. This is the only required claim.
                        SubjectIdentifier::new("5f83e0ca-2b8e-4e8c-ba0a-f80fe9bc3632".to_string()),
                    ),
                    // OpenID Connect Providers may supply custom claims by providing a struct that
                    // implements the AdditionalClaims trait. This requires manually using the
                    // generic IdTokenClaims struct rather than the CoreIdTokenClaims type alias,
                    // however.
                    EmptyAdditionalClaims {},
                )
                .set_nonce(auth_state.nonce),
                // The private key used for signing the ID token. For confidential clients (those able
                // to maintain a client secret), a CoreHmacKey can also be used, in conjunction
                // with one of the CoreJwsSigningAlgorithm::HmacSha* signing algorithms. When using an
                // HMAC-based signing algorithm, the UTF-8 representation of the client secret should
                // be used as the HMAC key.
                key,
                // Uses the RS256 signature algorithm. This crate supports any RS*, PS*, or HS*
                // signature algorithm.
                CoreJwsSigningAlgorithm::EdDsaEd25519,
                // When returning the ID token alongside an access token (e.g., in the Authorization Code
                // flow), it is recommended to pass the access token here to set the `at_hash` claim
                // automatically.
                Some(&access_token),
                // When returning the ID token alongside an authorization code (e.g., in the implicit
                // flow), it is recommended to pass the authorization code here to set the `c_hash` claim
                // automatically.
                None,
            )
            .map_err(TokenError::JsonWebTokenError)?;
            let mut token_response = CoreTokenResponse::new(
                access_token,
                CoreTokenType::Bearer,
                CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
            );
            token_response
                .set_refresh_token(Some(RefreshToken::new("dummy_refresh_token".to_string())));
            Ok(Json(token_response))
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
    pub client_id: ClientId,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedClient
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AuthErr;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header_split = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthErr::FailedClientAuth)?
            .to_str()
            .map_err(|_| AuthErr::FailedClientAuth)?
            .split_once(' ')
            .ok_or(AuthErr::FailedClientAuth)?;
        match header_split {
            ("Basic", value) => {
                let decoded = BASE64_STANDARD
                    .decode(value)
                    .map_err(|_| AuthErr::FailedClientAuth)?;
                let decoded_str =
                    String::from_utf8(decoded).map_err(|_| AuthErr::FailedClientAuth)?;
                let (client_id, client_secret) = decoded_str
                    .split_once(':')
                    .ok_or(AuthErr::FailedClientAuth)?;
                let client_id = ClientId::new(client_id.to_string());
                let app_state = AppState::from_ref(state);
                app_state
                    .authenticate_client(&client_id, client_secret)
                    .await
            }
            _ => Err(AuthErr::FailedClientAuth),
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
    JsonWebTokenError(JsonWebTokenError),
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
            TokenError::JsonWebTokenError(_) => (StatusCode::INTERNAL_SERVER_ERROR).into_response(),
        }
    }
}
