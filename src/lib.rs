use crate::endpoints::authorize::{get_authorize, post_authorize};
use crate::endpoints::{jwks, wellknown_endpoint};
use crate::primitives::ClientId;
use axum::http::Uri;
use axum::routing::get;
use axum::Router;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use openidconnect::core::CoreResponseType::Code;
use openidconnect::core::{CoreEdDsaPrivateSigningKey, CoreJsonWebKey, CoreRsaPrivateSigningKey};
use openidconnect::AuthenticationFlow::AuthorizationCode;
use openidconnect::JsonWebKeyId;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

mod endpoints;
mod primitives;

pub fn create_app() -> Router {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    let mut clients = HashMap::new();
    clients.insert(
        ClientId::new("demo"),
        ClientConfig {
            secret: "test".into(),
            redirect_uri: "https://oidcdebugger.com/debug".parse().unwrap(),
        },
    );
    let mut state = Config(Arc::new(InnerConfig {
        issuer: Url::parse("http://localhost:3000").unwrap(),
        json_web_key: CoreEdDsaPrivateSigningKey::from_ed25519_pem(
            signing_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_str(),
            Some(JsonWebKeyId::new("default".into())),
        )
        .unwrap(),
        clients,
    }));

    Router::new()
        .route("/", get(root))
        .route("/.well-known/openid-configuration", get(wellknown_endpoint))
        .route("/jwk", get(jwks))
        .route("/authorize", get(get_authorize).post(post_authorize))
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
    json_web_key: CoreEdDsaPrivateSigningKey,
    clients: HashMap<ClientId, ClientConfig>,
}

struct ClientConfig {
    secret: String,
    redirect_uri: Url,
}
