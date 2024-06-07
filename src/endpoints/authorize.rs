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
    response_type: String,
    client_id: String,
    #[serde(deserialize_with = "parse_uri")]
    redirect_uri: Uri,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: CodeChallengeMethod,
}

fn parse_uri<'de, D>(deserializer: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    // custom parsing logic here
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
