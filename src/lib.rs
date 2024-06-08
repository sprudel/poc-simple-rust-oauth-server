use crate::endpoints::authorize::{get_authorize, post_authorize, ResponseType};
use crate::endpoints::token::token;
use crate::endpoints::{jwks, wellknown_endpoint};
use crate::primitives::{
    AuthCode, ClientId, CodeChallengeMethod, CodeChallengeParam, NonceParam, StateParam,
};
use axum::extract::FromRef;
use axum::http::Uri;
use axum::routing::{get, post};
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
use std::time::Instant;
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

    let app_state = AppState {
        config: (Arc::new(Config {
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
        .with_state(app_state)
}
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

#[derive(Clone, FromRef)]
struct AppState {
    config: Arc<Config>,
    active_auth_code_flows: Arc<ActiveAuthCodeFlows>,
}

struct Config {
    issuer: Url,
    json_web_key: CoreEdDsaPrivateSigningKey,
    clients: HashMap<ClientId, ClientConfig>,
}

struct ClientConfig {
    secret: String,
    redirect_uri: Url,
}

type ActiveAuthCodeFlows = Mutex<HashMap<AuthCode, AuthCodeState>>;

struct AuthCodeState {
    expiry: Instant,
    scope: String,
    response_type: ResponseType,
    client_id: ClientId,
    nonce: Option<NonceParam>,
    code_challenge: Option<CodeChallengeParam>,
    code_challenge_method: CodeChallengeMethod,
}
