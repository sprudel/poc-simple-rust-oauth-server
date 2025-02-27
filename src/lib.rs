use crate::routes::main_router;
use axum::Router;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use openidconnect::core::CoreEdDsaPrivateSigningKey;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, JsonWebKeyId};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tower_cookies::Key;
use url::Url;

mod app_state;
mod oauth;
mod routes;
mod services;

mod repositories;

use crate::app_state::AppState;
use crate::app_state::Services;
use crate::services::external_identity_provider::ExternalIdentityProviderService;

use crate::repositories::Repositories;
pub use app_state::{ClientConfig, ClientType, Config, ExternalIdentityProviderConfig};

pub fn create_config(issuer: Url) -> Config {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    let mut clients = HashMap::new();
    clients.insert(
        ClientId::new("demo".to_string()),
        ClientConfig {
            client_type: ClientType::Confidential(ClientSecret::new("test".into())),
            redirect_uris: vec!["https://oidcdebugger.com/debug".parse().unwrap()],
        },
    );
    clients.insert(
        ClientId::new("integration-test".to_string()),
        ClientConfig {
            client_type: ClientType::Confidential(ClientSecret::new("test-secret".into())),
            redirect_uris: vec!["http://redirect".parse().unwrap()],
        },
    );

    Config {
        max_auth_session_time: Duration::from_secs(60 * 5),
        cookie_secret: Key::generate(),
        issuer,
        json_web_key: CoreEdDsaPrivateSigningKey::from_ed25519_pem(
            signing_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_str(),
            Some(JsonWebKeyId::new("default".into())),
        )
        .unwrap(),
        clients,
        external_identity_provider: ExternalIdentityProviderConfig {
            issuer: IssuerUrl::new("http://localhost:8080/realms/test".to_string()).unwrap(),
            client_id: ClientId::new("test".to_string()),
            client_secret: ClientSecret::new("jRSpi3urLgbKOFyOycgrlRWsvFEFuMSG".to_string()),
        },
    }
}

pub fn create_app(config: Config, pg_pool: PgPool) -> Router {
    let services = Services {
        external_identity_provider: ExternalIdentityProviderService::new(
            config.external_identity_provider.clone(),
        ),
    };

    let app_state = AppState {
        config: (Arc::new(config)),
        services: Arc::new(services),
        repositories: Arc::new(Repositories::new(pg_pool)),
    };

    main_router().with_state(app_state)
}
