mod constants;
mod result;

// use std::io::Write;
use constants::DEFAULT_PASSWORD;
use result::{PasswordError::Read, PasswordResult};

use rpassword::read_password;

/// zeroize Entropy and Password
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
/// store mnemonic entropy safely
#[derive(Zeroize, Debug, Clone, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct Entropy(pub Vec<u8>);

/// store strings safely
#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Password(pub String);

/// Defines how the password for the kv-store will be retrieved
#[derive(Clone, Debug)]
pub enum PasswordMethod {
    DefaultPassword,
    Prompt,
}
impl PasswordMethod {
    pub fn get(&self) -> PasswordResult<Password> {
        let res = match self {
            Self::DefaultPassword => Password(DEFAULT_PASSWORD.to_owned()), // test password
            Self::Prompt => {
                println!("Please type in your password:");
                // TODO: KDF on password
                let password =
                    format!("{:0>32}", read_password().map_err(|e| Read(e.to_string()))?);
                Password(password)
            }
        };
        Ok(res)
    }
}
