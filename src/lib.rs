use crate::endpoints::wellknown_endpoint;
use axum::routing::get;
use axum::Router;
use std::ops::Deref;
use std::sync::Arc;
use url::Url;

mod endpoints;

pub fn create_app() -> Router {
    let state = Config(Arc::new(InnerConfig {
        issuer: Url::parse("http://localhost:3000").unwrap(),
    }));

    Router::new()
        .route("/", get(root))
        .route("/.well-known/openid-configuration", get(wellknown_endpoint))
        .with_state(state)
}
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

#[derive(Clone)]
struct Config(Arc<InnerConfig>);

impl Deref for Config {
    type Target = InnerConfig;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

struct InnerConfig {
    issuer: Url,
}
