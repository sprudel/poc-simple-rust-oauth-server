use crate::services::external_identity_provider::ExternalIdentityServiceError::FailedToDiscoverProvider;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{Client, ClientId, ClientSecret, IssuerUrl};
use std::fmt::{Display, Formatter};
use tracing::info;

pub struct ExternalIdentityProviderService {
    config: ExternalIdentityProviderConfig,
}

#[derive(Debug, Clone)]
pub struct ExternalIdentityProviderConfig {
    pub issuer: IssuerUrl,
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
}

impl ExternalIdentityProviderService {
    pub fn new(config: ExternalIdentityProviderConfig) -> Self {
        Self { config }
    }

    pub async fn client(&self) -> Result<CoreClient, ExternalIdentityServiceError> {
        info!("Discovering provider {}", self.config.issuer.as_str());
        let provider_metadata =
            CoreProviderMetadata::discover_async(self.config.issuer.clone(), async_http_client)
                .await
                .map_err(|e| FailedToDiscoverProvider(e.to_string()))?;
        Ok(Client::from_provider_metadata(
            provider_metadata,
            self.config.client_id.clone(),
            Some(self.config.client_secret.clone()),
        ))
    }
}

pub enum ExternalIdentityServiceError {
    FailedToDiscoverProvider(String),
}

impl Display for ExternalIdentityServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FailedToDiscoverProvider(e) => {
                write!(f, "Failed to discover provider: {e}")
            }
        }
    }
}
