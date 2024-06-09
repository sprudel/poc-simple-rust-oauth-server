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
