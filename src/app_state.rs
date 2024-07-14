use crate::oauth::clients::ClientValidation;
pub use crate::oauth::clients::{ClientConfig, ClientType};
use crate::repositories::Repositories;
pub use crate::services::external_identity_provider::ExternalIdentityProviderConfig;
use crate::services::external_identity_provider::ExternalIdentityProviderService;
use axum::extract::FromRef;
use openidconnect::core::CoreEdDsaPrivateSigningKey;
use openidconnect::ClientId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tower_cookies::Key;
use url::Url;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub config: Arc<Config>,
    pub services: Arc<Services>,
    pub repositories: Arc<Repositories>,
}

pub struct Config {
    pub max_auth_session_time: Duration,
    pub cookie_secret: Key,
    pub issuer: Url,
    pub json_web_key: CoreEdDsaPrivateSigningKey,
    pub clients: HashMap<ClientId, ClientConfig>,
    pub external_identity_provider: ExternalIdentityProviderConfig,
}

pub struct Services {
    pub external_identity_provider: ExternalIdentityProviderService,
}

impl ClientValidation for AppState {
    async fn client_config(&self, client_id: &ClientId) -> Option<&ClientConfig> {
        self.config.clients.get(client_id)
    }
}
