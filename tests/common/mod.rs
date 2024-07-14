use dotenv::dotenv;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use openidconnect::core::CoreEdDsaPrivateSigningKey;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, JsonWebKeyId};
use simple_oauth_server::{
    create_app, ClientConfig, ClientType, Config, ExternalIdentityProviderConfig,
};
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use tower_cookies::Key;
use tower_http::trace::TraceLayer;
use url::Url;

static LOG_INITIALIZED: OnceLock<()> = OnceLock::new();

#[macro_export]
macro_rules! start_test_server {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f).split("::{{closure}}::f").next().unwrap();
        $crate::common::test_server_with_isolated_database(&name)
    }};
}

pub async fn test_server_with_isolated_database(db_name: &str) -> TestConfig {
    LOG_INITIALIZED.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter("simple_oauth_server=debug,tower=debug")
            .init()
    });
    dotenv().ok();
    let trace_layer = TraceLayer::new_for_http();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (config, test_config) = test_config(port);
    let mut url: Url = std::env::var("DATABASE_URL").unwrap().parse().unwrap();
    url.set_path(db_name);

    if sqlx::Postgres::database_exists(url.as_str()).await.unwrap() {
        sqlx::Postgres::drop_database(url.as_str()).await.unwrap()
    }
    sqlx::Postgres::create_database(url.as_str()).await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(url.as_str())
        .await
        .unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();

    let app = create_app(config, pool).layer(trace_layer);
    tokio::spawn(async { axum::serve(listener, app).await.unwrap() });

    test_config
}

pub fn test_config(port: u16) -> (Config, TestConfig) {
    let mut issuer_url = Url::parse("http://localhost").unwrap();
    issuer_url.set_port(Some(port)).unwrap();

    let test_config = TestConfig {
        issuer: issuer_url.clone(),
        auth_code_client: (
            ClientId::new("integration-test".to_string()),
            ClientSecret::new("test-secret".into()),
            "http://redirect".parse().unwrap(),
        ),
        public_auth_code_client: (
            ClientId::new("integration-test-public".to_string()),
            "http://redirect".parse().unwrap(),
        ),
    };

    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    let mut clients = HashMap::new();
    clients.insert(
        test_config.auth_code_client.0.clone(),
        ClientConfig {
            client_type: ClientType::Confidential(test_config.auth_code_client.1.clone()),
            redirect_uris: vec![test_config.auth_code_client.2.clone()],
        },
    );
    clients.insert(
        test_config.public_auth_code_client.0.clone(),
        ClientConfig {
            client_type: ClientType::Public,
            redirect_uris: vec![test_config.public_auth_code_client.1.clone()],
        },
    );

    let config = Config {
        max_auth_session_time: Duration::from_secs(60 * 5),
        cookie_secret: Key::generate(),
        issuer: issuer_url,
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
    };
    (config, test_config)
}

pub struct TestConfig {
    pub issuer: Url,
    pub auth_code_client: (ClientId, ClientSecret, Url),
    pub public_auth_code_client: (ClientId, Url),
}
