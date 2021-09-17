//! Wrap a layer of encryption around [sled]. We use [chacha20poly1305] to encrypt/decrypt values.
//! We use [chacha20poly1305::XChaCha20] because the nonces are generated randomly.

mod constants;
pub mod error;
pub mod kv;
pub mod record;

// match the API of sled
pub use error::EncryptedDbError as Error;
pub use error::EncryptedDbResult as Result;
pub use kv::open;
pub use kv::open_without_password;
pub use kv::EncryptedDb as Db;

// type aliases
type XNonceArray = [u8; 24];
type BytesArray = Vec<u8>;

#[cfg(test)]
mod tests;
