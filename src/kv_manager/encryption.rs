//! Encryption module. We use ChaCha20 to encrypt the kvstore

use super::error::{
    KvError::{EncryptionErr, PasswordErr},
    KvResult,
};
use crate::gg20::types::Password;

/// alias for encryption cipher
type ChaCha20EncryptionCipher = encrypted_sled::EncryptionCipher<chacha20::ChaCha20>;

/// alias for encrypted kv database
pub type EncryptedDb = encrypted_sled::Db<ChaCha20EncryptionCipher>;

pub(super) fn prompt(msg: &str) -> KvResult<Password> {
    println!("{}", msg);
    Ok(Password(
        rpassword::read_password().map_err(|err| PasswordErr(err.to_string()))?,
    ))
}

/// get encryption cipher
pub(super) fn encryption_cipher(
    password: Password,
    // nonce: Password, //TODO: remove nonce?
) -> KvResult<ChaCha20EncryptionCipher> {
    ChaCha20EncryptionCipher::new_from_slices(
        password.0.as_bytes(),
        "            ".as_bytes(), //TODO: replace dummy nonce
        // nonce.0.as_bytes(),
        // b"an example very very secret key.",
        // b"secret nonce",
        encrypted_sled::EncryptionMode::default(),
    )
    .map_err(|err| EncryptionErr(err.to_string()))
}
