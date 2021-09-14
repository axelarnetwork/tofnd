//! Encryption module. [chacha20::ChaCha20] is used to encrypt the kvstore

/// Encryption errors
#[derive(thiserror::Error, Debug)]
pub enum EncryptionErr {
    #[error("Read error: {0}")]
    Read(String),
    #[error("Cipher error: {0}")]
    Cipher(String),
}
pub type EncryptionResult<Success> = Result<Success, EncryptionErr>;
use EncryptionErr::*;

/// use [sha3_hash] as hashing algorithm
type HashAlgo = sha3_hash::Hash;

// zeroize Entropy and Password
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
pub enum PasswordMethod {
    #[cfg(test)]
    TestPassword, // use test password
    Prompt, // prompt user for password
}
impl PasswordMethod {
    pub fn get(&self) -> EncryptionResult<Password> {
        match self {
            #[cfg(test)]
            Self::TestPassword => Ok(Password(DEFAULT_PASSWORD.to_owned())), // test password
            Self::Prompt => prompt("Type password", PASSWORD_LENGTH),
        }
    }
}

/// Password should be 32 digits because encrypted_sled uses [chacha20::ChaCha20<R20, C32>]
const PASSWORD_LENGTH: usize = 32;
/// default nonce is 12 digits because encrypted_sled uses [chacha20::ChaCha20<R20, C32>]
const DEFAULT_NONCE: &str = "123456789012"; // 12 digits

/// alias for encryption cipher to be used by [encrypted_sled]
type ChaCha20EncryptionCipher = encrypted_sled::EncryptionCipher<chacha20::ChaCha20>;

/// alias for encrypted_sled database
pub type EncryptedDb = encrypted_sled::Db<ChaCha20EncryptionCipher>;

/// prompt user for password. The password is hashed using [HashAlgo].
pub(super) fn prompt(msg: &str, length: usize) -> EncryptionResult<Password> {
    println!("{}", msg);
    // prompt user for a password and hash it
    let password = HashAlgo::hash_bytes(
        rpassword::read_password()
            .map_err(|e| Read(e.to_string()))?
            .as_bytes(),
    )
    .to_string();
    // keep 32 first characters because encrypted_sled uses ChaCha20<R20, C32>
    Ok(Password(password[..length].to_string()))
}

/// get encryption cipher
pub(super) fn encryption_cipher(password: Password) -> EncryptionResult<ChaCha20EncryptionCipher> {
    ChaCha20EncryptionCipher::new_from_slices(
        password.0.as_bytes(),
        DEFAULT_NONCE.as_bytes(),
        encrypted_sled::EncryptionMode::default(),
    )
    .map_err(|err| Cipher(err.to_string()))
}

/// we don't want tests to prompt for password
#[cfg(test)]
/// default password is 32 digits because encrypted_sled uses ChaCha20<R20, C32>
const DEFAULT_PASSWORD: &str = "12345678901234567890123456789012"; // 32 digits
