use super::{
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

// I have nothing up my sleeve: sha3 hash of "tofnd"
const DEFAULT_SALT: &[u8] = b"f0e740929cd80bdf1a672567874d997a36463b85aa53ae37ab0f7840c657f05de7c4e71a28f53e6a8d6e78a8ba654424627ff0218bb87ba33b66c9d4e6d15fbc";
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

const DEFAULT_PASSWORD: &[u8; 32] = b"12345678901234567890123456789012";
fn default_password() -> Entropy {
    Entropy(DEFAULT_PASSWORD.to_vec())
}
