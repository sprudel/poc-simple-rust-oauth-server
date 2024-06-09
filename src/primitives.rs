use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Deserialize;

#[derive(Hash, PartialEq, Eq, Deserialize)]
pub struct AuthCode(String);

impl AuthCode {
    pub fn new_random() -> Self {
        let auth_code: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32) // adjust the length to your needs
            .map(char::from)
            .collect();
        AuthCode(auth_code)
    }
}

#[derive(Deserialize)]
pub struct StateParam(String);
#[derive(Deserialize)]
pub struct NonceParam(String);
#[derive(Deserialize)]
pub struct CodeChallengeParam(String);
#[derive(Deserialize, Hash, PartialEq, Eq, Clone)]
pub struct ClientId(String);

impl ClientId {
    pub fn new<S: ToString>(id: S) -> Self {
        ClientId(id.to_string())
    }
}

#[derive(Deserialize, Default)]
pub enum CodeChallengeMethod {
    #[serde(rename = "plain")]
    #[default]
    Plain,
    #[serde(rename = "S256")]
    Sha256,
}

macro_rules! as_str {
    ($name:ident) => {
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
as_str!(AuthCode);
as_str!(StateParam);
as_str!(NonceParam);
as_str!(CodeChallengeParam);
as_str!(ClientId);
