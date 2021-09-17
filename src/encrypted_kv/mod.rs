//! Wrap a layer of encryption around [sled]. We use [chacha20poly1305] to encrypt/decrypt values.

pub mod error;
pub mod kv;
pub mod record;

pub use error::EncryptedDbError as Error;
pub use error::EncryptedDbResult as Result;
pub use kv::open;
pub use kv::open_no_password;
pub use kv::EncryptedDb as Db;

#[cfg(test)]
mod tests;
