//! Wrap a layer of encryption around [sled]. We use [chacha20poly1305] to encrypt/decrypt values.
//! Specifically, use [chacha20poly1305::XChaCha20] because the nonces are generated randomly.
//! To create an new [Db], an [Entropy] needs to be provided.

mod constants;
mod kv;
mod record;
mod result;
mod types;

// match the API of sled
pub use kv::open;
pub use kv::EncryptedDb as Db;
pub use result::EncryptedDbError as Error;
pub use result::EncryptedDbResult as Result;

pub use types::EncryptedDbKey as Entropy;

#[cfg(test)]
mod tests;
