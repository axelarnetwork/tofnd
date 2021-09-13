//! Encryption module
/// We use ChaCha20 to encrypt the kvstore

/// alias for encryption cipher
type ChaCha20EncryptionCipher = encrypted_sled::EncryptionCipher<chacha20::ChaCha20>;

/// alias for encrypted kv database
pub type EncryptedDb = encrypted_sled::Db<ChaCha20EncryptionCipher>;

/// get encryption cipher
pub(super) fn encryption_cipher(
) -> Result<ChaCha20EncryptionCipher, chacha20::cipher::errors::InvalidLength> {
    ChaCha20EncryptionCipher::new_from_slices(
        b"an example very very secret key.",
        b"secret nonce",
        encrypted_sled::EncryptionMode::default(),
    )
}
