use crate::routes::authorize::{get_authorize, post_authorize};
use crate::routes::token::token;
use crate::routes::{jwks, wellknown_endpoint};
use axum::routing::{get, post};
use axum::Router;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use openidconnect::core::CoreEdDsaPrivateSigningKey;
use openidconnect::{ClientId, JsonWebKeyId};
use std::collections::HashMap;
use std::sync::Arc;
use tower_cookies::{CookieManagerLayer, Key};
use url::Url;

mod app_state;
mod oauth;
mod routes;

use crate::app_state::AppState;
use crate::app_state::Config;
use crate::oauth::clients::ClientConfig;
pub fn create_app() -> Router {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    let mut clients = HashMap::new();
    clients.insert(
        ClientId::new("demo".to_string()),
        ClientConfig {
            secret: "test".into(),
            redirect_uris: vec!["https://oidcdebugger.com/debug".parse().unwrap()],
        },
    );

    let app_state = AppState {
        config: (Arc::new(Config {
            cookie_secret: Key::generate(),
            issuer: Url::parse("http://localhost:3000").unwrap(),
            json_web_key: CoreEdDsaPrivateSigningKey::from_ed25519_pem(
                signing_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_str(),
                Some(JsonWebKeyId::new("default".into())),
            )
            .unwrap(),
            clients,
        })),
        active_auth_code_flows: Arc::new(Default::default()),
    };

    Router::new()
        .route("/", get(root))
        .route("/.well-known/openid-configuration", get(wellknown_endpoint))
        .route("/jwk", get(jwks))
        .route("/authorize", get(get_authorize).post(post_authorize))
        .route("/token", post(token))
        .layer(CookieManagerLayer::new())
        .with_state(app_state)
}
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}
