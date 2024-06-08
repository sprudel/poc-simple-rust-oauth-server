use crate::primitives::AuthCode;
use crate::{ClientConfig, Config};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use openidconnect::http::Uri;
use openidconnect::AuthorizationRequest;
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::str::FromStr;
use url::Url;

#[derive(Deserialize)]
pub struct AuthorizeParameters {
    scope: String,
    response_type: ResponseType,
    client_id: String,
    redirect_uri: Url,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: CodeChallengeMethod,
}

pub struct ResponseType {
    code: bool,
    id_token: bool,
    token: bool,
}

impl<'de> Deserialize<'de> for ResponseType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let mut response_type = ResponseType {
            code: false,
            id_token: false,
            token: false,
        };
        for single_response_type in s.split(' ') {
            match single_response_type {
                "code" => response_type.code = true,
                "id_token" => response_type.id_token = true,
                "token" => response_type.token = true,
                other => {
                    return Err(D::Error::custom(format!(
                        "Invalid repsonse type '{}'",
                        other
                    )))
                }
            }
        }
        Ok(response_type)
    }
}

#[derive(Deserialize)]
enum CodeChallengeMethod {
    #[serde(rename = "plain")]
    Plain,
    #[serde(rename = "S256")]
    Sha256,
}
impl Default for CodeChallengeMethod {
    fn default() -> Self {
        CodeChallengeMethod::Plain
    }
}

pub async fn get_authorize(
    State(config): State<Config>,
    Query(params): Query<AuthorizeParameters>,
) -> impl IntoResponse {
    handle_auth_request(config, params).await
}

pub async fn post_authorize(
    State(config): State<Config>,
    Form(params): Form<AuthorizeParameters>,
) -> impl IntoResponse {
    handle_auth_request(config, params).await
}

async fn handle_auth_request(
    config: Config,
    params: AuthorizeParameters,
) -> Result<Redirect, AuthErr> {
    let AuthorizeParameters {
        scope,
        response_type,
        client_id,
        mut redirect_uri,
        state,
        nonce,
        code_challenge,
        code_challenge_method,
    } = params;
    let client_config = config
        .clients
        .get(&client_id)
        .ok_or(AuthErr::InvalidClientId(client_id))?;
    if client_config.redirect_uri != redirect_uri || redirect_uri.cannot_be_a_base() {
        return Err(AuthErr::InvalidRedirectUri(redirect_uri));
    }
    if let Some(state) = state {
        redirect_uri.query_pairs_mut().append_pair("state", &state);
    }

    let auth_code = AuthCode::new_random();
    redirect_uri
        .query_pairs_mut()
        .append_pair("code", &auth_code);

    Ok(Redirect::to(redirect_uri.as_str()))
}

enum AuthErr {
    InvalidClientId(String),
    InvalidRedirectUri(Url),
}

impl IntoResponse for AuthErr {
    fn into_response(self) -> Response {
        match self {
            AuthErr::InvalidClientId(client_id) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid client id: {client_id}"),
            )
                .into_response(),
            AuthErr::InvalidRedirectUri(url) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid redirect_uri: {url}"),
            )
                .into_response(),
        }
    }
}
