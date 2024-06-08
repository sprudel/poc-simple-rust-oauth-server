use crate::Config;
use anyhow;
use axum::extract::{Request, State};
use axum::response::IntoResponse;
use axum::Json;
use openidconnect::core::{
    CoreClaimName, CoreJsonWebKey, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
};
use openidconnect::{
    AuthUrl, AuthorizationRequest, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySet,
    JsonWebKeySetUrl, PrivateSigningKey, ProviderMetadata, ResponseTypes, Scope, TokenUrl,
    UserInfoUrl,
};
use std::ops::Deref;
use std::sync::Arc;
use url::Url;

pub mod authorize;
pub mod token;

pub async fn wellknown_endpoint(config: State<Arc<Config>>) -> Json<CoreProviderMetadata> {
    Json(generate_provider_metadata(&config.issuer))
}

fn generate_provider_metadata(baseurl: &Url) -> CoreProviderMetadata {
    let issuer = IssuerUrl::from_url(baseurl.clone());
    let auth_url = AuthUrl::from_url(baseurl.join("authorize").unwrap());
    let jwk_url = JsonWebKeySetUrl::from_url(baseurl.join("jwk").unwrap());
    let token_url = TokenUrl::from_url(baseurl.join("token").unwrap());
    let user_info_url = UserInfoUrl::from_url(baseurl.join("userinfo").unwrap());

    let provider_metadata = CoreProviderMetadata::new(
        // Parameters required by the OpenID Connect Discovery spec.
        issuer,
        auth_url,
        jwk_url,
        // Supported response types (flows).
        vec![
            // Recommended: support the code flow.
            ResponseTypes::new(vec![CoreResponseType::Code]),
            // Optional: support the implicit flow.
            ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]), // Other flows including hybrid flows may also be specified here.
        ],
        // For user privacy, the Pairwise subject identifier type is preferred. This prevents
        // distinct relying parties (clients) from knowing whether their users represent the same
        // real identities. This identifier type is only useful for relying parties that don't
        // receive the 'email', 'profile' or other personally-identifying scopes.
        // The Public subject identifier type is also supported.
        vec![CoreSubjectIdentifierType::Pairwise],
        // Support the RS256 signature algorithm.
        vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
        // OpenID Connect Providers may supply custom metadata by providing a struct that
        // implements the AdditionalProviderMetadata trait. This requires manually using the
        // generic ProviderMetadata struct rather than the CoreProviderMetadata type alias,
        // however.
        EmptyAdditionalProviderMetadata {},
    )
    // Specify the token endpoint (required for the code flow).
    .set_token_endpoint(Some(token_url))
    // Recommended: support the UserInfo endpoint.
    .set_userinfo_endpoint(Some(user_info_url))
    // Recommended: specify the supported scopes.
    .set_scopes_supported(Some(vec![
        Scope::new("openid".to_string()),
        Scope::new("email".to_string()),
        Scope::new("profile".to_string()),
    ]))
    // Recommended: specify the supported ID token claims.
    .set_claims_supported(Some(vec![
        // Providers may also define an enum instead of using CoreClaimName.
        CoreClaimName::new("sub".to_string()),
        CoreClaimName::new("aud".to_string()),
        CoreClaimName::new("email".to_string()),
        CoreClaimName::new("email_verified".to_string()),
        CoreClaimName::new("exp".to_string()),
        CoreClaimName::new("iat".to_string()),
        CoreClaimName::new("iss".to_string()),
        CoreClaimName::new("name".to_string()),
        CoreClaimName::new("given_name".to_string()),
        CoreClaimName::new("family_name".to_string()),
        CoreClaimName::new("picture".to_string()),
        CoreClaimName::new("locale".to_string()),
    ]));
    provider_metadata
}

pub async fn jwks(config: State<Arc<Config>>) -> impl IntoResponse {
    let key = config.json_web_key.as_verification_key();
    Json(CoreJsonWebKeySet::new(vec![key]))
}
