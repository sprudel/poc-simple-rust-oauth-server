use crate::oauth::primitives::AuthCode;
use openidconnect::{ClientId, ClientSecret, CsrfToken};
use subtle::ConstantTimeEq;
use url::Url;

pub trait ClientValidation {
    async fn client_config(&self, client_id: &ClientId) -> Option<&ClientConfig>;
    async fn validate_redirect(
        &self,
        client_id: &ClientId,
        redirect_url: &Url,
    ) -> Result<ValidRedirectUrl, ClientValidationError> {
        let client_config = self
            .client_config(client_id)
            .await
            .ok_or_else(|| ClientValidationError::InvalidClient(client_id.clone()))?;
        if client_config.redirect_uris.contains(redirect_url) && !redirect_url.cannot_be_a_base() {
            Ok(ValidRedirectUrl(redirect_url.clone()))
        } else {
            Err(ClientValidationError::InvalidRedirect(redirect_url.clone()))
        }
    }

    async fn validate_client(
        &self,
        client_id: &ClientId,
        client_secret: Option<&ClientSecret>,
    ) -> Result<ValidatedClient, ClientValidationError> {
        match (self.client_config(client_id).await, client_secret) {
            (
                Some(ClientConfig {
                    client_type: ClientType::Confidential(secret),
                    ..
                }),
                Some(client_secret),
            ) if secret
                .secret()
                .as_bytes()
                .ct_eq(client_secret.secret().as_bytes())
                .into() =>
            {
                Ok(ValidatedClient::AuthenticatedConfidentialClient(
                    client_id.clone(),
                ))
            }
            (
                Some(ClientConfig {
                    client_type: ClientType::Public,
                    ..
                }),
                None,
            ) => Ok(ValidatedClient::PublicClient(client_id.clone())),
            (Some(_), _) => Err(ClientValidationError::FailedClientAuth),
            _ => Err(ClientValidationError::InvalidClient(client_id.clone())),
        }
    }
}

pub enum ClientValidationError {
    InvalidClient(ClientId),
    FailedClientAuth,
    InvalidRedirect(Url),
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub client_type: ClientType,
    pub redirect_uris: Vec<Url>,
}

#[derive(Debug, Clone)]
pub enum ClientType {
    Confidential(ClientSecret),
    Public,
    MachineToMachine(ClientSecret),
}

pub struct ValidRedirectUrl(Url);

impl ValidRedirectUrl {
    pub fn auth_code_redirect(&self, code: &AuthCode, state: Option<CsrfToken>) -> Url {
        let mut redirect_url = self.0.clone();
        if let Some(state) = state {
            redirect_url
                .query_pairs_mut()
                .append_pair("state", state.secret());
        }
        redirect_url
            .query_pairs_mut()
            .append_pair("code", code.as_str());
        redirect_url
    }

    pub fn url(&self) -> Url {
        self.0.clone()
    }
}

pub enum ValidatedClient {
    AuthenticatedConfidentialClient(ClientId),
    PublicClient(ClientId),
}
