//! Password errors

#[derive(thiserror::Error, Debug)]
pub enum PasswordError {
    #[error("Read error: {0}")]
    Read(#[from] std::io::Error), // rpassword::read_password() Error
    #[error("Encrypt error: {0}")]
    InvalidOutputLen(scrypt::errors::InvalidOutputLen),
    #[error("Params error: {0}")]
    InvalidParams(scrypt::errors::InvalidParams),
}
pub type PasswordResult<Success> = Result<Success, PasswordError>;
