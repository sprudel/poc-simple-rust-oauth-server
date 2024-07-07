mod common;

use crate::common::start_test_server;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthorizationCode, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, TokenResponse,
};
use reqwest::redirect::Policy;
use reqwest::StatusCode;
use std::collections::HashMap;
use url::Url;

#[tokio::test]
async fn provider_discovery() {
    let config = start_test_server().await;
    let provider_metadata =
        CoreProviderMetadata::discover_async(IssuerUrl::from_url(config.issuer), async_http_client)
            .await;

    assert!(
        provider_metadata.is_ok(),
        "{:?}",
        provider_metadata.unwrap_err()
    );
    let _metadata = provider_metadata.unwrap();
}

#[tokio::test]
async fn auth_code_flow() {
    let config = start_test_server().await;
    let provider_metadata =
        CoreProviderMetadata::discover_async(IssuerUrl::from_url(config.issuer), async_http_client)
            .await
            .unwrap();
    let (client_id, client_secret, dummy_redirect) = config.auth_code_client;

    let oidc_client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            // Set the URL the user will be redirected to after the authorization process.
            .set_redirect_uri(RedirectUrl::from_url(dummy_redirect.clone()));
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
            if attempt.url().as_str().starts_with(dummy_redirect.as_str()) {
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

    // second auth code flow does not show login page
    let (url, state, _nonce) = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .url();

    let second_flow_response = client.get(url).send().await.unwrap();
    let second_redirect = second_flow_response
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .and_then(|u| Url::parse(u).ok())
        .expect("missing second redirect");

    let query_params: HashMap<_, _> = second_redirect.query_pairs().collect();

    assert_eq!(
        query_params.get("state").expect("state"),
        state.secret(),
        "IDP returns correct state parameter"
    );
}

#[tokio::test]
async fn auth_code_flow_with_pkce() {
    let config = start_test_server().await;
    let provider_metadata =
        CoreProviderMetadata::discover_async(IssuerUrl::from_url(config.issuer), async_http_client)
            .await
            .unwrap();
    let (client_id, dummy_redirect) = config.public_auth_code_client;

    let oidc_client = CoreClient::from_provider_metadata(provider_metadata, client_id, None)
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::from_url(dummy_redirect.clone()));
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge.clone())
        .url();

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(Policy::custom(move |attempt| {
            if attempt.url().as_str().starts_with(dummy_redirect.as_str()) {
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
    assert!(
        !keycloak_form_url.contains(pkce_challenge.as_str()),
        "pkce challenge is not passed to keycloak"
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
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .expect("token response");

    let _id_token = token_response
        .id_token()
        .expect("id token")
        .claims(&oidc_client.id_token_verifier(), &nonce)
        .expect("id_token claim");
}
