//! types and aliases
use zeroize::Zeroize;

/// Safely store entropy to initialize XChaCha20 cipher
#[derive(Zeroize, Clone, Default)]
#[zeroize(drop)]
pub struct XChaCha20Entropy(pub [u8; 32]);

/// Nonce is public, no need to zeroize
pub(super) type XChaCha20Nonce = [u8; 24];
pub(super) type BytesArray = Vec<u8>;
