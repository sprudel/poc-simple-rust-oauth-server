mod errors;
mod models;

use crate::oauth::clients::ValidatedClient;
use crate::routes::auth::token::errors::TokenError;
use crate::routes::auth::token::models::ValidatedOauthTokenRequest;
use crate::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::{debug_handler, Json};
use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJwsSigningAlgorithm, CoreTokenResponse,
    CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, EmptyAdditionalClaims, EmptyExtraTokenFields, IssuerUrl,
    PkceCodeChallenge, RefreshToken, StandardClaims,
};
use std::time::Instant;

#[debug_handler]
pub async fn token(
    State(app_state): State<AppState>,
    auth_token_request: ValidatedOauthTokenRequest,
) -> Result<impl IntoResponse, TokenError> {
    match auth_token_request {
        ValidatedOauthTokenRequest::AuthorizationCode {
            code,
            redirect_uri,
            client,
            code_verifier,
        } => {
            let mut guard = app_state.active_auth_code_flows.lock().await;
            let auth_state = guard
                .remove(&code)
                .filter(|auth_state| auth_state.expiry > Instant::now())
                .filter(|auth_state| auth_state.redirect_uri == redirect_uri)
                .filter(|auth_state| match client {
                    ValidatedClient::AuthenticatedConfidentialClient(client_id) => {
                        auth_state.client_id == client_id
                    }
                    ValidatedClient::PublicClient(client_id) => {
                        auth_state.client_id == client_id
                            && code_verifier.is_some()
                            && auth_state.pkce_code_challenge.is_some()
                    }
                })
                .filter(
                    |auth_state| match (&auth_state.pkce_code_challenge, code_verifier) {
                        (Some(challenge), Some(verifier)) => {
                            &PkceCodeChallenge::from_code_verifier_sha256(&verifier) == challenge
                        }
                        (None, None) => true,
                        _ => false,
                    },
                )
                .ok_or(TokenError::AuthFlowNotFound)?;

            let key = &app_state.config.json_web_key;
            let access_token = AccessToken::new("dummy_access_token".to_string());
            let id_token = CoreIdToken::new(
                CoreIdTokenClaims::new(
                    IssuerUrl::from_url(app_state.config.issuer.clone()),
                    vec![Audience::new(auth_state.client_id.as_str().to_string())],
                    // The ID token expiration is usually much shorter than that of the access or refresh
                    // tokens issued to clients.
                    Utc::now() + Duration::seconds(300),
                    // The issue time is usually the current time.
                    Utc::now(),
                    // Set the standard claims defined by the OpenID Connect Core spec.
                    StandardClaims::new(
                        // Stable subject identifiers are recommended in place of e-mail addresses or other
                        // potentially unstable identifiers. This is the only required claim.
                        auth_state.subject,
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
            .map_err(TokenError::JsonWebToken)?;
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
