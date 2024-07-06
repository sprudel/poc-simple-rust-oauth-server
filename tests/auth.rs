use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl,
    TokenResponse,
};
use reqwest::redirect::Policy;
use reqwest::StatusCode;
use simple_oauth_server::create_app;
use std::collections::HashMap;
use url::Url;

async fn start_test_server() -> Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut issuer_url = Url::parse("http://localhost").unwrap();
    issuer_url.set_port(Some(port)).unwrap();

    let app = create_app(issuer_url.clone());
    tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    issuer_url
}

#[tokio::test]
async fn provider_discovery() {
    let url = start_test_server().await;
    let provider_metadata =
        CoreProviderMetadata::discover_async(IssuerUrl::from_url(url), async_http_client).await;

    assert!(
        provider_metadata.is_ok(),
        "{:?}",
        provider_metadata.unwrap_err()
    );
    let _metadata = provider_metadata.unwrap();
}

#[tokio::test]
async fn auth_code_flow() {
    let url = start_test_server().await;
    let provider_metadata =
        CoreProviderMetadata::discover_async(IssuerUrl::from_url(url), async_http_client)
            .await
            .unwrap();
    let dummy_redirect = "http://redirect";

    let oidc_client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new("integration-test".to_string()),
        Some(ClientSecret::new("test-secret".to_string())),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new(dummy_redirect.to_string()).unwrap());
    let (url, state, nonce) = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .url();

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(Policy::custom(move |attempt| {
            if attempt.url().as_str().starts_with(dummy_redirect) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .unwrap();
    let body = client.get(url).send().await.unwrap().text().await.unwrap();
    let keycloak_form_url = body
        .split_once("action=\"")
        .and_then(|(_, r)| r.split_once('"'))
        .map(|(u, _)| u)
        .expect("login form post url");

    assert!(
        !keycloak_form_url.contains(state.secret()),
        "original state is not passed to keycloak"
    );
    assert!(
        !keycloak_form_url.contains(nonce.secret()),
        "original nonce is not passed to keycloak"
    );

    let res = client
        .post(keycloak_form_url)
        .form(&[("username", "test"), ("password", "test")])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let final_redirect = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .and_then(|u| Url::parse(u).ok())
        .expect("missing final redirect");
    let query_params: HashMap<_, _> = final_redirect.query_pairs().collect();

    assert_eq!(
        query_params.get("state").expect("state"),
        state.secret(),
        "IDP returns correct state parameter"
    );
    let code = query_params
        .get("code")
        .expect("code returned as parameter");

    let token_response = oidc_client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(async_http_client)
        .await
        .expect("token response");

    let _id_token = token_response
        .id_token()
        .expect("id token")
        .claims(&oidc_client.id_token_verifier(), &nonce)
        .expect("id_token claim");
}
