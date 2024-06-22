use crate::oauth::clients::{ClientConfig, ClientValidation};
use crate::oauth::primitives::AuthCode;
use async_trait::async_trait;
use axum::extract::FromRef;
use openidconnect::core::{CoreEdDsaPrivateSigningKey, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    ClientId, ClientSecret, Nonce, PkceCodeChallenge, ResponseTypes, SubjectIdentifier,
};
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
    pub external_identity_provider: ExternalIdentityProvider,
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
    pub subject: SubjectIdentifier,
}

pub struct ExternalIdentityProvider {
    pub provider_metadata: CoreProviderMetadata,
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
}
