//! Handles the generation of an [Entropy] from user's password using [scrypt] pbkdf.

use super::{
    constants::*,
    result::{
        PasswordError::{InvalidOutputLen, InvalidParams},
        PasswordResult,
    },
    types::Password,
};

/// The entropy will be used for [crate::encrypted_sled::Db] which currently uses XChaCha20
use crate::encrypted_sled::Entropy;

use rpassword::read_password;
use scrypt::{scrypt, Params};

/// Defines how the [Entropy] will be retrieved
#[derive(Clone, Debug)]
pub enum PasswordMethod {
    NoPassword,
    Prompt,
}
impl PasswordMethod {
    pub fn get(&self) -> PasswordResult<Entropy> {
        let res = match self {
            Self::NoPassword => unsafe_entropy(),
            Self::Prompt => entropy_from_prompt()?,
        };
        Ok(res)
    }
}

/// Prompt for a password from stdin and create an [Entropy].
fn entropy_from_prompt() -> PasswordResult<Entropy> {
    println!("Please type your password:");
    let password = Password(read_password()?);
    entropy_from_password(password)
}

/// Create an [Entropy] using [scrypt] pbkdf.
fn entropy_from_password(password: Password) -> PasswordResult<Entropy> {
    let mut output = Entropy::default();
    // set log_n = 10 for better UX (~1 sec). Rest of params are the defaults.
    let params = Params::new(10, 8, 1).map_err(InvalidParams)?;
    scrypt(password.0.as_bytes(), DEFAULT_SALT, &params, &mut output.0)
        .map_err(InvalidOutputLen)?;
    Ok(output)
}

/// Get a default entropy. Attention: This is **NOT** safely generated.
fn unsafe_entropy() -> Entropy {
    Entropy(UNSAFE_ENTROPY.to_owned())
}
