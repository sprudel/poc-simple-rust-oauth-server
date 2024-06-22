use crate::oauth::primitives::AuthCode;
use openidconnect::ClientId;
use serde::Deserialize;
use url::Url;

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
    pub fn client_id(&self) -> &ClientId {
        match self {
            OAuthTokenRequest::AuthorizationCode { client_id, .. } => client_id,
            OAuthTokenRequest::Password { client_id, .. } => client_id,
            OAuthTokenRequest::ClientCredentials { client_id, .. } => client_id,
            OAuthTokenRequest::RefreshToken { client_id, .. } => client_id,
        }
    }
    pub fn client_secret(&self) -> Option<&str> {
        match self {
            OAuthTokenRequest::AuthorizationCode { client_secret, .. } => client_secret.as_deref(),
            OAuthTokenRequest::Password { client_secret, .. } => client_secret.as_deref(),
            OAuthTokenRequest::ClientCredentials { client_secret, .. } => client_secret.as_deref(),
            OAuthTokenRequest::RefreshToken { client_secret, .. } => client_secret.as_deref(),
        }
    }
}
