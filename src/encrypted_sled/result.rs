//! Custom error handling

#[derive(thiserror::Error, Debug)]
pub enum EncryptedDbError {
    #[error("Your kv store may be corrupted. Sled error: {0}")]
    CorruptedKv(sled::Error),
    #[error("Password read error: {0}")]
    PasswordRead(#[from] std::io::Error), // rpassword::read_password() Error
    #[error("Password scrypt params error: {0}")]
    PasswordScryptParams(#[from] scrypt::errors::InvalidParams),
    #[error("Password scrypt error: {0}")]
    PasswordScryptError(#[from] scrypt::errors::InvalidOutputLen),
    #[error("Sled error: {0}")]
    SledError(#[from] sled::Error),
    #[error("Serialization error: failed to serialize the encrypted record")]
    Serialization,
    #[error("Deserialization error: failed to deserialize encrypted record bytes")]
    Deserialization,
    #[error("ChaCha20 encryption error: {0}")]
    Encryption(String),
    #[error("ChaCha20 decryption error: {0}")]
    Decryption(String),
    #[error("Wrong password")]
    WrongPassword,
    #[error("Missing password salt")]
    MissingPasswordSalt,
    #[error("Malformed password salt: {0}")]
    MalformedPasswordSalt(#[from] std::array::TryFromSliceError),
}
pub type EncryptedDbResult<Success> = Result<Success, EncryptedDbError>;
