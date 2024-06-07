use axum::extract::Query;
use axum::response::IntoResponse;
use axum::Form;
use openidconnect::http::Uri;
use openidconnect::AuthorizationRequest;
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::str::FromStr;

#[derive(Deserialize)]
struct RawAuthorizeParameters {
    scope: String,
    response_type: ResponseType,
    client_id: String,
    #[serde(deserialize_with = "parse_uri")]
    redirect_uri: Uri,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: CodeChallengeMethod,
}

struct ResponseType {
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

fn parse_uri<'de, D>(deserializer: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    Uri::from_str(s).map_err(|e| D::Error::custom(e.to_string()))
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

pub async fn get_authorize(Query(params): Query<RawAuthorizeParameters>) -> impl IntoResponse {}

pub async fn post_authorize(Form(params): Form<RawAuthorizeParameters>) -> impl IntoResponse {}

async fn handle_auth_request(params: RawAuthorizeParameters) -> impl IntoResponse {}
