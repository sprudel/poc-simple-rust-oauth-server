use crate::app_state::AppState;
use crate::routes::auth::authorize::{callback, get_authorize, logout, post_authorize};
use crate::routes::auth::token::token;
use crate::routes::well_known::jwks;
use axum::routing::{get, post};
use axum::Router;
use tower_cookies::CookieManagerLayer;

mod authorize;
mod token;

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/jwk", get(jwks))
        .route("/authorize", get(get_authorize).post(post_authorize))
        .route("/token", post(token))
        .route("/callback", get(callback))
        .route("/logout", get(logout))
        .layer(CookieManagerLayer::new())
}
