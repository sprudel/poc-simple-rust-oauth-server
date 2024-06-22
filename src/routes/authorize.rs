mod errors;
mod models;

use crate::app_state::{AuthCodeState, Config};
use crate::oauth::clients::ClientValidation;
use crate::oauth::primitives::AuthCode;
use crate::routes::authorize::errors::AuthErr;
use crate::routes::authorize::models::AuthorizeParameters;
use crate::AppState;
use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::Form;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_cookies::{Cookie, Cookies, PrivateCookies};

pub async fn get_authorize(
    State(app_state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<AuthorizeParameters>,
) -> impl IntoResponse {
    handle_auth_request(app_state, cookies, params).await
}

pub async fn post_authorize(
    State(app_state): State<AppState>,
    cookies: Cookies,
    Form(params): Form<AuthorizeParameters>,
) -> impl IntoResponse {
    handle_auth_request(app_state, cookies, params).await
}

async fn handle_auth_request(
    app_state: AppState,
    cookies: Cookies,
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

#[derive(Serialize, Deserialize)]
pub enum AuthCookieState {
    UnAuthenticated,
    Authenticated(UserId),
}

#[derive(Serialize, Deserialize)]
pub struct UserId(pub String);

pub struct AuthCookie {
    state: AuthCookieState,
    cookies: Cookies,
    config: Arc<Config>,
}

impl AuthCookie {
    pub fn set_state(&self, state: AuthCookieState) {
        let value = serde_json::to_string(&state).unwrap();
        let cookie = Cookie::new(AUTH_COOKIE_NAME, value);
        // TODO correct cookie parameters
        self.private_cookies().add(cookie);
    }

    pub fn get_state(&self) -> &AuthCookieState {
        &self.state
    }

    fn private_cookies(&self) -> PrivateCookies {
        self.cookies.private(&self.config.cookie_secret)
    }
}

const AUTH_COOKIE_NAME: &str = "AUTH";
#[async_trait]
impl<S> FromRequestParts<S> for AuthCookie
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
            .and_then(|c| serde_json::from_str::<AuthCookieState>(c.value()).ok());

        if let Some(state) = existing_cookie {
            Ok(AuthCookie {
                state,
                cookies,
                config,
            })
        } else {
            let state = AuthCookieState::UnAuthenticated;
            Ok(AuthCookie {
                state,
                cookies,
                config,
            })
        }
    }
}
