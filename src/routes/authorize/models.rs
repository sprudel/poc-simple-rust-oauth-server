use openidconnect::core::{CoreResponseMode, CoreResponseType};
use openidconnect::{ClientId, CsrfToken, Nonce, PkceCodeChallenge, ResponseTypes};
use serde::Deserialize;
use url::Url;

#[derive(Deserialize)]
pub struct AuthorizeParameters {
    pub scope: String,
    pub response_type: ResponseTypes<CoreResponseType>,
    pub client_id: ClientId,
    pub redirect_uri: Url,
    pub state: Option<CsrfToken>,
    pub nonce: Option<Nonce>,
    #[serde(flatten)]
    pub pkce_code_challenge: Option<PkceCodeChallenge>,
    pub response_mode: Option<CoreResponseMode>,
}
