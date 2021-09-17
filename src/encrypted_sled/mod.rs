//! Wrap a layer of encryption around [sled]. We use [chacha20poly1305] to encrypt/decrypt values.
//! We use [chacha20poly1305::XChaCha20] because the nonces are generated randomly.

mod constants;
pub mod kv;
pub mod record;
pub mod result;

// match the API of sled
pub use kv::open;
pub use kv::EncryptedDb as Db;
pub use result::EncryptedDbError as Error;
pub use result::EncryptedDbResult as Result;

// type aliases
type XNonceArray = [u8; 24];
type BytesArray = Vec<u8>;

#[cfg(test)]
mod tests;
