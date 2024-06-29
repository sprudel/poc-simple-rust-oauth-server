use crate::app_state::AppState;
use crate::routes::auth::auth_routes;
use crate::routes::well_known::wellknown_endpoint;
use axum::routing::get;
use axum::Router;

mod auth;
mod well_known;

pub fn main_router() -> Router<AppState> {
    Router::new()
        .route("/", get(root))
        .route("/.well-known/openid-configuration", get(wellknown_endpoint))
        .nest("/auth", auth_routes())
}

async fn root() -> &'static str {
    "Hello, World!"
}
