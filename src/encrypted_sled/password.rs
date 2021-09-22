//! Handles the generation of an [Entropy] from user's password using [scrypt] pbkdf.

use super::{constants::UNSAFE_PASSWORD, result::EncryptedDbResult};

use rpassword::read_password;
use zeroize::Zeroize;

/// Safely store strings
// TODO use https://docs.rs/secrecy ?
#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Password(String);

impl AsRef<[u8]> for Password {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub type PasswordSalt = [u8; 32];

/// Specifies how [password] will be retrieved
#[derive(Clone, Debug)]
pub enum PasswordMethod {
    NoPassword,
    Prompt,
}
impl PasswordMethod {
    /// Execute the password method to retrieve a password
    pub fn execute(&self) -> EncryptedDbResult<Password> {
        Ok(match self {
            Self::NoPassword => Password(UNSAFE_PASSWORD.to_string()),
            Self::Prompt => {
                println!("Please type your tofnd password:");
                Password(read_password()?)
            }
        })
    }
}

#[cfg(test)]
impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}
