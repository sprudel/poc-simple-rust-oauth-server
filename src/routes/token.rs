mod errors;
mod models;

use crate::oauth::clients::{AuthenticatedClient, ClientValidation};
use crate::routes::token::errors::TokenError;
use crate::routes::token::models::OAuthTokenRequest;
use crate::AppState;
use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::IntoResponse;
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
    RefreshToken, StandardClaims, SubjectIdentifier,
};
use std::time::Instant;

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
                    auth_state.client_id == *client.client_id()
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

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedClient
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = TokenError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header_split = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(TokenError::ClientUnAuthenticated)?
            .to_str()
            .map_err(|_| TokenError::ClientUnAuthenticated)?
            .split_once(' ')
            .ok_or(TokenError::ClientUnAuthenticated)?;
        match header_split {
            ("Basic", value) => {
                let decoded = BASE64_STANDARD
                    .decode(value)
                    .map_err(|_| TokenError::ClientUnAuthenticated)?;
                let decoded_str =
                    String::from_utf8(decoded).map_err(|_| TokenError::ClientUnAuthenticated)?;
                let (client_id, client_secret) = decoded_str
                    .split_once(':')
                    .ok_or(TokenError::ClientUnAuthenticated)?;
                let client_id = ClientId::new(client_id.to_string());
                let app_state = AppState::from_ref(state);
                app_state
                    .authenticate_client(&client_id, client_secret)
                    .await
                    .map_err(TokenError::from)
            }
            _ => Err(TokenError::ClientUnAuthenticated),
        }
    }
}
