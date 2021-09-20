use super::{
    constants::*,
    result::{
        PasswordError::{InvalidOutputLen, InvalidParams},
        PasswordResult,
    },
    Entropy, Password,
};

use rpassword::read_password;
use scrypt::{scrypt, Params};

/// Defines how the password for the kv-store will be retrieved
#[derive(Clone, Debug)]
pub enum PasswordMethod {
    DefaultPassword,
    Prompt,
}
impl PasswordMethod {
    pub fn get(&self) -> PasswordResult<Entropy> {
        let res = match self {
            Self::DefaultPassword => default_entropy(),
            Self::Prompt => entropy_from_prompt()?,
        };
        Ok(res)
    }
}

fn entropy_from_prompt() -> PasswordResult<Entropy> {
    println!("Please type your password:");
    let password = Password(read_password()?);
    entropy_from_pbkfd2(password)
}

fn entropy_from_pbkfd2(password: Password) -> PasswordResult<Entropy> {
    let mut output = Entropy(vec![0; 32]);
    // set log_n = 10 for better UX. Rest of params are the defaults.
    let params = Params::new(10, 8, 1).map_err(InvalidParams)?;
    scrypt(password.0.as_bytes(), DEFAULT_SALT, &params, &mut output.0)
        .map_err(InvalidOutputLen)?;
    Ok(output)
}

fn default_entropy() -> Entropy {
    Entropy(DEFAULT_ENTROPY.to_vec())
}
