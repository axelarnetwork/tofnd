//! Key-Value Store service. We use [sled] for the underlying db implementation.
//! For every kvstore initialized, a daemon is spawned that serves basic
//! database functionality using the "actor" pattern ([kv::Kv] is the "handle"): https://ryhl.io/blog/actors-with-tokio/
//! See https://tokio.rs/tokio/tutorial/channels for tokio channels
//! See [kv] module for the public API.

/// Custom error types for [kv] and [sled_bindings]
pub mod error;
/// public API of kv manager
mod kv;
/// sled bindings for basic kv operations
pub mod sled_bindings;
/// definition of kv_manager types and default paths
mod types;
/// wrapers for values stored by tofnd services
mod value;

pub use types::KeyReservation;
pub use value::KvManager;

// tests for low-level operations
#[cfg(test)]
mod tests;
