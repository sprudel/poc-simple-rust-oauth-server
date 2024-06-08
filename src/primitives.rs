use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::ops::Deref;

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

impl Deref for AuthCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}
