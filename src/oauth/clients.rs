use crate::oauth::primitives::AuthCode;
use async_trait::async_trait;
use openidconnect::{ClientId, CsrfToken};
use subtle::ConstantTimeEq;
use url::Url;

#[async_trait]
pub trait ClientValidation {
    async fn client_config(&self, client_id: &ClientId) -> Option<&ClientConfig>;
    async fn validate_redirect(
        &self,
        client_id: &ClientId,
        redirect_url: Url,
    ) -> Result<ValidRedirectUrl, ClientValidationError> {
        let client_config = self
            .client_config(client_id)
            .await
            .ok_or_else(|| ClientValidationError::InvalidClient(client_id.clone()))?;
        if client_config.redirect_uris.contains(&redirect_url) && !redirect_url.cannot_be_a_base() {
            Ok(ValidRedirectUrl(redirect_url))
        } else {
            Err(ClientValidationError::InvalidRedirect(redirect_url))
        }
    }

    async fn authenticate_client(
        &self,
        client_id: &ClientId,
        secret: &str,
    ) -> Result<AuthenticatedClient, ClientValidationError> {
        match self.client_config(client_id).await {
            Some(ClientConfig { secret, .. })
                if secret.as_bytes().ct_eq(secret.as_bytes()).into() =>
            {
                Ok(AuthenticatedClient {
                    client_id: client_id.clone(),
                })
            }
            Some(_) => Err(ClientValidationError::InvalidClientAuth),
            _ => Err(ClientValidationError::InvalidClient(client_id.clone())),
        }
    }
}

pub enum ClientValidationError {
    InvalidClient(ClientId),
    InvalidClientAuth,
    InvalidRedirect(Url),
}

pub struct ClientConfig {
    pub secret: String,
    pub redirect_uris: Vec<Url>,
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

pub struct AuthenticatedClient {
    pub client_id: ClientId,
}

impl AuthenticatedClient {
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }
}
