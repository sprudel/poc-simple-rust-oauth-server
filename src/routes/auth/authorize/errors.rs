use crate::oauth::clients::ClientValidationError;
use crate::services::external_identity_provider::ExternalIdentityServiceError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use openidconnect::ClientId;
use url::Url;

pub enum AuthErr {
    InvalidClientId(ClientId),
    InvalidRedirectUri(Url),
    InternalServerError,
    FailedClientAuth,
    InvalidFlowState,
}

impl From<ClientValidationError> for AuthErr {
    fn from(err: ClientValidationError) -> Self {
        match err {
            ClientValidationError::InvalidClient(id) => AuthErr::InvalidClientId(id),
            ClientValidationError::FailedClientAuth => AuthErr::FailedClientAuth,
            ClientValidationError::InvalidRedirect(url) => AuthErr::InvalidRedirectUri(url),
        }
    }
}

impl From<ExternalIdentityServiceError> for AuthErr {
    fn from(_value: ExternalIdentityServiceError) -> Self {
        // TODO log issues
        AuthErr::InternalServerError
    }
}

impl IntoResponse for AuthErr {
    fn into_response(self) -> Response {
        match self {
            AuthErr::InvalidClientId(client_id) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid client id: {}", client_id.as_str()),
            )
                .into_response(),
            AuthErr::InvalidRedirectUri(url) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid redirect_uri: {url}"),
            )
                .into_response(),
            AuthErr::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            AuthErr::FailedClientAuth => {
                (StatusCode::UNAUTHORIZED, "Invalid client").into_response()
            }
            AuthErr::InvalidFlowState => {
                (StatusCode::UNAUTHORIZED, "Invalid state").into_response()
            }
        }
    }
}
