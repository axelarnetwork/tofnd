//! Wrap a layer of encryption around [sled]. We use [chacha20poly1305] to encrypt/decrypt values.

pub mod error;
pub mod kv;
pub mod record;

#[cfg(test)]
mod tests;
