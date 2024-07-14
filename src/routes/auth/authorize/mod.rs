mod errors;
mod models;

use crate::app_state::Config;
use crate::oauth::clients::ClientValidation;
use crate::oauth::primitives::AuthCode;
use crate::repositories::auth_code_flows::AuthCodeState;
use crate::repositories::users::User;
use crate::routes::auth::authorize::errors::AuthErr;
use crate::routes::auth::authorize::models::AuthorizeParameters;
use crate::AppState;
use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::Form;
use chrono::TimeDelta;
use openidconnect::core::{CoreAuthenticationFlow, CoreGenderClaim};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, CsrfToken, EmptyAdditionalClaims, IdTokenClaims, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    SubjectIdentifier, TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_cookies::{Cookie, Cookies, PrivateCookies};

pub async fn get_authorize(
    State(app_state): State<AppState>,
    auth_cookie: AuthCookies,
    Query(params): Query<AuthorizeParameters>,
) -> impl IntoResponse {
    handle_auth_request(app_state, auth_cookie, params).await
}

pub async fn post_authorize(
    State(app_state): State<AppState>,
    auth_cookie: AuthCookies,
    Form(params): Form<AuthorizeParameters>,
) -> impl IntoResponse {
    handle_auth_request(app_state, auth_cookie, params).await
}

async fn handle_auth_request(
    app_state: AppState,
    auth_cookie: AuthCookies,
    params: AuthorizeParameters,
) -> Result<Redirect, AuthErr> {
    let valid_redirect_url = app_state
        .validate_redirect(&params.client_id, &params.redirect_uri)
        .await?;

    // TODO check user is authenticated and has access to client
    let authenticated_user = match auth_cookie.user_session {
        UserSession::Authenticated(user_id, issued_at)
            if !issued_at.is_older_than(app_state.config.max_auth_session_time) =>
        {
            user_id
        }
        _ => {
            return trigger_login(app_state, auth_cookie, params).await;
        }
    };

    let AuthorizeParameters {
        scope,
        response_type,
        client_id,
        redirect_uri: _,
        state,
        nonce,
        pkce_code_challenge,
        response_mode: _,
    } = params;

    let auth_code = AuthCode::new_random();
    let auth_code_redirect = valid_redirect_url.auth_code_redirect(&auth_code, state);

    let code_expiry = chrono::Utc::now().add(TimeDelta::minutes(5));

    let auth_code_state = AuthCodeState {
        expiry: code_expiry,
        scope,
        response_type,
        client_id,
        nonce,
        pkce_code_challenge,
        redirect_uri: valid_redirect_url.url(),
        subject: authenticated_user,
    };

    app_state
        .repositories
        .auth_code_flow
        .insert(&auth_code, auth_code_state)
        .await;

    Ok(Redirect::to(auth_code_redirect.as_str()))
}

async fn trigger_login(
    app_state: AppState,
    auth_cookie: AuthCookies,
    params: AuthorizeParameters,
) -> Result<Redirect, AuthErr> {
    let client = app_state
        .services
        .external_identity_provider
        .client()
        .await?
        .set_redirect_uri(RedirectUrl::from_url(
            app_state.config.issuer.join("/auth/callback").unwrap(),
        ));

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes([
            Scope::new("email".to_string()),
            Scope::new("profile".to_string()),
        ])
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    auth_cookie.set_external_auth(Some(&ExternalAuth(
        pkce_verifier,
        csrf_token,
        nonce,
        params,
    )));

    Ok(Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
pub struct Callback {
    state: CsrfToken,
    code: AuthorizationCode,
}

pub async fn callback(
    State(app_state): State<AppState>,
    auth_cookie: AuthCookies,
    Query(callback): Query<Callback>,
) -> Result<Redirect, AuthErr> {
    if matches!(&auth_cookie.user_session, UserSession::Authenticated(_, _)) {
        return Err(AuthErr::InvalidFlowState);
    }
    let ExternalAuth(pkce_verifier, orig_state, nonce, orig_auth_param) = auth_cookie
        .get_external_auth()
        .ok_or(AuthErr::InvalidFlowState)?;
    if callback.state.secret() != orig_state.secret() {
        return Err(AuthErr::InvalidFlowState);
    }
    let client = app_state
        .services
        .external_identity_provider
        .client()
        .await?
        .set_redirect_uri(RedirectUrl::from_url(
            app_state.config.issuer.join("/auth/callback").unwrap(),
        ));

    let token_response = client
        .exchange_code(callback.code)
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|_| AuthErr::InvalidFlowState)?;

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response.id_token().ok_or(AuthErr::InvalidFlowState)?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &nonce)
        .map_err(|_| AuthErr::InvalidFlowState)?;

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            &id_token
                .signing_alg()
                .map_err(|_| AuthErr::InvalidFlowState)?,
        )
        .map_err(|_| AuthErr::InvalidFlowState)?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(AuthErr::InvalidFlowState);
        }
    }

    let user = get_or_signup_user(&app_state, claims).await;

    let subject = SubjectIdentifier::new(user.id.to_string());

    auth_cookie.set_external_auth(None);
    auth_cookie.set_user_session(UserSession::Authenticated(subject, IssuedAt::now()));

    Ok(Redirect::to(
        format!(
            "/auth/authorize?{}",
            serde_urlencoded::to_string(orig_auth_param).unwrap()
        )
        .as_str(),
    ))
}

async fn get_or_signup_user(
    app_state: &AppState,
    claims: &IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>,
) -> User {
    match app_state
        .repositories
        .users
        .get_user_by_external_id(claims.subject())
        .await
    {
        None => {
            app_state
                .repositories
                .users
                .create(User {
                    id: std::time::SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64,
                    external_id: Some(claims.subject().to_string()),
                    email: claims.email().unwrap().to_string(),
                    email_verified: claims.email_verified().unwrap(),
                })
                .await
        }
        Some(u) => u,
    }
}

pub async fn logout(auth_cookies: AuthCookies) -> impl IntoResponse {
    // TODO validate logout redirect etc
    auth_cookies.set_user_session(UserSession::UnAuthenticated);
    "Successfully logged out"
}

#[derive(Serialize, Deserialize, Clone)]
pub enum UserSession {
    UnAuthenticated,
    #[serde(rename = "A")]
    Authenticated(SubjectIdentifier, IssuedAt),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IssuedAt(u64);

impl IssuedAt {
    pub fn now() -> Self {
        IssuedAt(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }

    pub fn is_older_than(&self, duration: Duration) -> bool {
        UNIX_EPOCH.add(Duration::from_secs(self.0)).add(duration) < SystemTime::now()
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExternalAuth(PkceCodeVerifier, CsrfToken, Nonce, AuthorizeParameters);

pub struct AuthCookies {
    user_session: UserSession,
    cookies: Cookies,
    config: Arc<Config>,
}

impl AuthCookies {
    pub fn set_user_session(&self, state: UserSession) {
        let value = serde_json::to_string(&state).unwrap();
        let cookie = Cookie::new(AUTH_COOKIE_NAME, value);
        // TODO correct cookie parameters
        self.private_cookies().add(cookie);
    }

    pub fn get_external_auth(&self) -> Option<ExternalAuth> {
        self.private_cookies()
            .get(EXTERNAL_AUTH_COOKIE_NAME)
            .and_then(|c| serde_json::from_str::<ExternalAuth>(c.value()).ok())
    }

    pub fn set_external_auth(&self, external_auth: Option<&ExternalAuth>) {
        if let Some(external_auth) = external_auth {
            let value = serde_json::to_string(external_auth).unwrap();
            let cookies = Cookie::new(EXTERNAL_AUTH_COOKIE_NAME, value);
            // TODO correct cookie parameters
            self.private_cookies().add(cookies);
        } else {
            self.private_cookies()
                .remove(Cookie::new(EXTERNAL_AUTH_COOKIE_NAME, ""))
        }
    }

    fn private_cookies(&self) -> PrivateCookies {
        self.cookies.private(&self.config.cookie_secret)
    }
}

const AUTH_COOKIE_NAME: &str = "AUTH";
const EXTERNAL_AUTH_COOKIE_NAME: &str = "EXTERNAL_AUTH";
#[async_trait]
impl<S> FromRequestParts<S> for AuthCookies
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cookies = Cookies::from_request_parts(parts, state).await?;
        let config = AppState::from_ref(state).config;

        let existing_cookie = cookies
            .private(&config.cookie_secret)
            .get(AUTH_COOKIE_NAME)
            .and_then(|c| serde_json::from_str::<UserSession>(c.value()).ok());

        if let Some(state) = existing_cookie {
            Ok(AuthCookies {
                user_session: state,
                cookies,
                config,
            })
        } else {
            let state = UserSession::UnAuthenticated;
            Ok(AuthCookies {
                user_session: state,
                cookies,
                config,
            })
        }
    }
}
