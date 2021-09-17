mod result;

// use std::io::Write;
const DEFAULT_PASSWORD: &[u8; 32] = b"12345678901234567890123456789012";
use result::{
    PasswordError::{InvalidOutputLen, Read},
    PasswordResult,
};

use rpassword::read_password;
use scrypt::Params;

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
    pub fn get(&self) -> PasswordResult<Entropy> {
        let res = match self {
            Self::DefaultPassword => Entropy(DEFAULT_PASSWORD.to_vec()), // test password
            Self::Prompt => {
                println!("Please type your password:");
                let password = Password(read_password().map_err(|e| Read(e.to_string()))?);
                let mut output = Entropy(vec![0; 32]);
                scrypt::scrypt(
                    password.0.as_bytes(),
                    b"",
                    &Params::default(),
                    &mut output.0,
                )
                .map_err(InvalidOutputLen)?;
                output
            }
        };
        Ok(res)
    }
}
