use crate::oauth::clients::ClientValidationError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use openidconnect::JsonWebTokenError;

pub enum TokenError {
    ClientUnAuthenticated,
    AuthFlowNotFound,
    FlowNotSupported,
    JsonWebToken(JsonWebTokenError),
    BadRequest(String),
}

impl From<ClientValidationError> for TokenError {
    fn from(_err: ClientValidationError) -> Self {
        // TODO log original error
        TokenError::ClientUnAuthenticated
    }
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        match self {
            TokenError::ClientUnAuthenticated => {
                (StatusCode::UNAUTHORIZED, "Client unauthenticated").into_response()
            }
            TokenError::AuthFlowNotFound => {
                (StatusCode::UNAUTHORIZED, "AuthFlow not found").into_response()
            }
            TokenError::FlowNotSupported => {
                (StatusCode::BAD_REQUEST, "Flow not supported").into_response()
            }
            TokenError::JsonWebToken(_) => (StatusCode::INTERNAL_SERVER_ERROR).into_response(),
            TokenError::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid request body: {}", message),
            )
                .into_response(),
        }
    }
}
