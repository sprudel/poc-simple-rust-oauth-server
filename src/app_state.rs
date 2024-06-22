use crate::oauth::clients::{ClientConfig, ClientValidation};
use crate::oauth::primitives::AuthCode;
use async_trait::async_trait;
use axum::extract::FromRef;
use openidconnect::core::{CoreEdDsaPrivateSigningKey, CoreResponseType};
use openidconnect::{ClientId, Nonce, PkceCodeChallenge, ResponseTypes};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tower_cookies::Key;
use url::Url;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub config: Arc<Config>,
    pub active_auth_code_flows: Arc<ActiveAuthCodeFlows>,
}

pub struct Config {
    pub cookie_secret: Key,
    pub issuer: Url,
    pub json_web_key: CoreEdDsaPrivateSigningKey,
    pub clients: HashMap<ClientId, ClientConfig>,
}

#[async_trait]
impl ClientValidation for AppState {
    async fn client_config(&self, client_id: &ClientId) -> Option<&ClientConfig> {
        self.config.clients.get(client_id)
    }
}

type ActiveAuthCodeFlows = Mutex<HashMap<AuthCode, AuthCodeState>>;

pub struct AuthCodeState {
    pub expiry: Instant,
    pub scope: String,
    pub response_type: ResponseTypes<CoreResponseType>,
    pub client_id: ClientId,
    pub nonce: Option<Nonce>,
    pub pkce_code_challenge: Option<PkceCodeChallenge>,
    pub redirect_uri: Url,
}
