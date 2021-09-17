//! Password errors

#[derive(thiserror::Error, Debug)]
pub enum PasswordError {
    #[error("Read error: {0}")]
    Read(String),
    #[error("Encrypt error: {0}")]
    InvalidOutputLen(scrypt::errors::InvalidOutputLen),
}
pub type PasswordResult<Success> = Result<Success, PasswordError>;
