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
            Self::DefaultPassword => default_password(),
            Self::Prompt => password_from_prompt()?,
        };
        Ok(res)
    }
}

fn password_from_prompt() -> PasswordResult<Entropy> {
    println!("Please type your password:");
    let password = Password(read_password()?);
    let mut output = Entropy(vec![0; 32]);
    // log_n = 10 to instantly get the entropy; rest params are defaults
    let params = Params::new(10, 8, 1).map_err(InvalidParams)?;
    scrypt(password.0.as_bytes(), DEFAULT_SALT, &params, &mut output.0)
        .map_err(InvalidOutputLen)?;
    Ok(output)
}

fn default_password() -> Entropy {
    Entropy(DEFAULT_PASSWORD.to_vec())
}
