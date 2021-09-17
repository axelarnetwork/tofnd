//! Custom error handling for [encrypted_kv]

#[derive(thiserror::Error, Debug)]
pub enum EncryptedDbError {
    #[error("Sled error: {0}")]
    SledError(#[from] sled::Error),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] bincode::Error),
    #[error("ChaCha20 encryption error: {0}")]
    Encryption(String),
    #[error("ChaCha20 decryption error: {0}")]
    Decryption(String),
    #[error("Wrong password")]
    WrongPassword,
}
pub type EncryptedDbResult<Success> = Result<Success, EncryptedDbError>;
