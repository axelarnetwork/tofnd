//! Password errors

#[derive(thiserror::Error, Debug)]
pub enum PasswordError {
    #[error("Read error: {0}")]
    Read(String),
}
pub type PasswordResult<Success> = Result<Success, PasswordError>;
