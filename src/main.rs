use axum::{http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router, async_trait};
use axum::response::Response;
use oxide_auth::endpoint::{OAuthError, OwnerConsent, Scope, Scopes, Solicitation, Template, WebRequest};
use oxide_auth::frontends::simple::endpoint::{Error, Generic, Vacant};
use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::primitives::generator::RandomGenerator;
use oxide_auth::primitives::issuer::TokenMap;
use oxide_auth::primitives::prelude::{Client, ClientMap};
use oxide_auth::primitives::registrar::RegisteredUrl;
use oxide_auth_async::endpoint::access_token::AccessTokenFlow;
use oxide_auth_async::endpoint::authorization::AuthorizationFlow;
use oxide_auth_async::endpoint::OwnerSolicitor;
use oxide_auth_async::primitives::{Authorizer, Issuer, Registrar};
use oxide_auth_axum::{OAuthRequest, OAuthResponse, WebError};
use serde::{Deserialize, Serialize};

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new().route("/", get(root)).route("/authorize", get(get_authorize));

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}


async fn get_authorize(request: OAuthRequest) -> Result<impl IntoResponse, CustomError> {
  let mut endpoint = EndpointImpl::new();
    let secret = "test".as_bytes();
    endpoint.registrar.register_client(Client::confidential("test", RegisteredUrl::Semantic("http://localhost:3001".parse().unwrap()), "openid".parse().unwrap(), secret));
    AuthorizationFlow::prepare(endpoint)?.execute(request).await.map(IntoResponse::into_response)
}

struct ApproveAllGrants {}

#[async_trait]
impl OwnerSolicitor<OAuthRequest> for ApproveAllGrants {
    async fn check_consent(&mut self, req: &mut OAuthRequest, solicitation: Solicitation<'_>) -> OwnerConsent<<OAuthRequest as WebRequest>::Response> {
        OwnerConsent::Authorized("default".into())
    }
}

struct EndpointImpl {
    authorizer: AuthMap<RandomGenerator>,
    registrar: ClientMap,
    issuer: TokenMap<RandomGenerator>,
    solicitor: ApproveAllGrants,
    scopes: Vacant,
    response: Vacant,
}

impl EndpointImpl {
    fn new() -> Self {
        EndpointImpl {
            authorizer: AuthMap::new(RandomGenerator::new(16)),
            registrar: ClientMap::new(),
            issuer: TokenMap::new(RandomGenerator::new(16)),
            solicitor: ApproveAllGrants{},
            scopes: Vacant,
            response: Vacant,
        }
    }
}

impl oxide_auth_async::endpoint::Endpoint<OAuthRequest> for EndpointImpl {
    type Error = CustomError;

    fn registrar(&self) -> Option<&(dyn Registrar + Sync)> {
        Some(&self.registrar)
    }

    fn authorizer_mut(&mut self) -> Option<&mut (dyn Authorizer + Send)> {
        Some(&mut self.authorizer)
    }

    fn issuer_mut(&mut self) -> Option<&mut (dyn Issuer + Send)> {
        Some(&mut self.issuer)
    }

    fn owner_solicitor(&mut self) -> Option<&mut (dyn OwnerSolicitor<OAuthRequest> + Send)> {
        Some(&mut self.solicitor)
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<OAuthRequest>> {
        Some(&mut self.scopes)
    }

    fn response(&mut self, request: &mut OAuthRequest, kind: Template) -> Result<OAuthResponse, Self::Error> {
        Ok(Default::default())
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        CustomError::OauthError(err)
    }

    fn web_error(&mut self, err: WebError) -> Self::Error {
        CustomError::WebError(err)
    }
}

#[derive(Debug)]
enum CustomError {
    OauthError(OAuthError),
    WebError(WebError)
}

impl IntoResponse for CustomError {
    fn into_response(self) -> Response {
        match self {
            CustomError::OauthError(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
            CustomError::WebError(e) =>  e.into_response()
        }
    }
}