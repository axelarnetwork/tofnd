//! Encryption module. ChaCha20 is used to encrypt the kvstore

// zeroize Entropy and Password
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};

use crate::kv_manager::error::{
    KvError::{EncryptionErr, PasswordErr},
    KvResult,
};

/// Mnemonic type needs to be known globaly to create/access the mnemonic kv store
#[derive(Zeroize, Debug, Clone, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct Entropy(pub Vec<u8>);

/// Store passwords strings safely
#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Password(pub String);

pub enum PasswordMethod {
    #[cfg(test)]
    TestPassword, // use default password
    Prompt, // prompt user for password
}

/// Defines how the password will be retireved
impl PasswordMethod {
    pub fn get(&self) -> KvResult<Password> {
        match self {
            #[cfg(test)]
            Self::TestPassword => Ok(Password(DEFAULT_PASSWORD.to_owned())),
            Self::Prompt => prompt("Type password"),
        }
    }
}

/// default nonce is 12 digits because encrypted_sled uses ChaCha20<R20, C32>
const DEFAULT_NONCE: &str = "123456789012"; // 12 digits

/// alias for encryption cipher
type ChaCha20EncryptionCipher = encrypted_sled::EncryptionCipher<chacha20::ChaCha20>;

/// alias for encrypted kv database
pub type EncryptedDb = encrypted_sled::Db<ChaCha20EncryptionCipher>;

/// prompt user for password
pub(super) fn prompt(msg: &str) -> KvResult<Password> {
    println!("{}", msg);
    Ok(Password(
        rpassword::read_password().map_err(|err| PasswordErr(err.to_string()))?,
    ))
}

/// get encryption cipher
pub(super) fn encryption_cipher(password: Password) -> KvResult<ChaCha20EncryptionCipher> {
    ChaCha20EncryptionCipher::new_from_slices(
        password.0.as_bytes(),
        DEFAULT_NONCE.as_bytes(),
        encrypted_sled::EncryptionMode::default(),
    )
    .map_err(|err| EncryptionErr(err.to_string()))
}

#[cfg(test)]
/// default password is 32 digits because encrypted_sled uses ChaCha20<R20, C32>
const DEFAULT_PASSWORD: &str = "12345678901234567890123456789012"; // 32 digits
