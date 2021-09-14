//! Encryption module. [chacha20::ChaCha20] is used to encrypt the kvstore

/// Encryption errors
#[derive(thiserror::Error, Debug)]
pub enum EncryptionErr {
    #[error("Read error: {0}")]
    Read(String),
    #[error("Cipher error: {0}")]
    Cipher(String),
    #[error("Wrong password. Password hash does not match with existing keyhash")]
    WrongPassword,
    #[error("File error: {0}")]
    File(#[from] std::io::Error),
    #[error("Reached max tries for sufficiently large password")]
    MaxTries,
}
pub type EncryptionResult<Success> = Result<Success, EncryptionErr>;

use std::io::Write;

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
            Self::Prompt => get_password("Type your password:"),
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

const DEFAULT_KEYHASH_FILE: &str = "keyhash";

/// Minimum length of user's password
const MINIMUM_LENGTH: usize = 8;
/// Max tries to input a sufficiently large password
const MAX_TRIES: usize = 3;

/// prompt user for a password and hash it. Password needs to be at least
/// [MINIMUM_LENGTH] characters. The user has [MAX_TRIES] to provide a valid
/// password. The password is hashed using [HashAlgo].
fn prompt(msg: &str) -> EncryptionResult<String> {
    println!("{}", msg);

    let mut password = Password(rpassword::read_password().map_err(|e| Read(e.to_string()))?);
    let mut tries = 1;
    while password.0.len() < MINIMUM_LENGTH && tries < MAX_TRIES {
        println!("Please use at least {} characters", MINIMUM_LENGTH);
        password = Password(rpassword::read_password().map_err(|e| Read(e.to_string()))?);
        tries += 1;
    }

    // if we didn't get a password of at least MINIMUM_LENGTH chars after MAX_TRIES, return a `MaxTries` error
    if password.0.len() < MINIMUM_LENGTH && tries >= MAX_TRIES {
        return Err(MaxTries);
    }

    // prompt user for a password and hash it
    Ok(HashAlgo::hash_bytes(password.0.as_bytes()).to_string())
}

/// get a password from user
pub(super) fn get_password(msg: &str) -> EncryptionResult<Password> {
    let user_password_hash = prompt(msg)?;

    use crate::DEFAULT_PATH_ROOT;
    let keyhash_path = std::path::Path::new(DEFAULT_PATH_ROOT).join(DEFAULT_KEYHASH_FILE);

    match keyhash_path.exists() {
        true => {
            // if heyhash file exists, get the stored password hash
            let stored_password_hash = std::fs::read_to_string(keyhash_path)?;
            if stored_password_hash != user_password_hash {
                // if stored password hash and user's password hash differ return `WrongPassword` error
                return Err(WrongPassword);
            }
        }
        false => {
            // if keyhash file does not exist, prompt user for password again,
            let verify = prompt("Type your password again:")?;
            if verify != user_password_hash {
                // if passwords don't match, return `WrongPassword` error
                return Err(WrongPassword);
            }
            // if both passwords match, create the keyhash file with user's password hash
            std::fs::create_dir(DEFAULT_PATH_ROOT)?;
            let mut file = std::fs::File::create(keyhash_path)?;
            file.write_all(verify.as_bytes())?;
        }
    }

    // keep 32 first characters because encrypted_sled uses ChaCha20<R20, C32>
    Ok(Password(user_password_hash[..PASSWORD_LENGTH].to_string()))
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
