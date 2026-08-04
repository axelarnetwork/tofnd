//! Wrap [sled] with [chacha20poly1305] encryption. An [XChaCha20Entropy] is
//! used as [XChaCha20Poly1305] cipher key to create an [EncryptedDb].
//! A new random [XChaCha20Nonce] is created every time a new value needs to be
//! inserted, forming a [EncryptedRecord]:<encrypted value, nonce>. The nonce is later
//! used to decrypt and retrieve the originally inserted value.

use std::convert::TryInto;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{self, XChaCha20Poly1305};
use rand::RngCore;

use sled::IVec;
use zeroize::Zeroize;

use super::constants::*;
use super::password::{Password, PasswordSalt};
use super::record::EncryptedRecord;
use super::result::{EncryptedDbError::*, EncryptedDbResult};

/// A [sled] kv store with [XChaCha20Poly1305] value encryption.
pub struct EncryptedDb {
    kv: sled::Db,
    cipher: XChaCha20Poly1305,
}

impl EncryptedDb {
    /// create a new [EncryptedDb] that wraps sled::open(db_name).
    /// Retrieves [XChaCha20Entropy] from a password-based-key-derivation-function and
    /// verifies that the password is valid.
    /// See [crate::password] for more info on pdkdf.
    pub fn open<P>(db_name: P, password: Password) -> EncryptedDbResult<Self>
    where
        P: AsRef<std::path::Path>,
    {
        let kv = sled::open(db_name).map_err(CorruptedKv)?;

        let password_salt: PasswordSalt = if kv.was_recovered() {
            // existing kv: get the existing password salt
            kv.get(PASSWORD_SALT_KEY)?
                .ok_or(MissingPasswordSalt)?
                .try_into()?
        } else {
            // new kv: choose a new password salt and store it
            let mut password_salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut password_salt);
            kv.insert(PASSWORD_SALT_KEY, &password_salt)?;
            password_salt.into()
        };

        // zeroize key since we are no longer using it after creating cipher
        let mut key = Self::chacha20poly1305_kdf(password, password_salt)?;
        let cipher = XChaCha20Poly1305::new(&key);
        key.zeroize();

        let encrypted_db = EncryptedDb { kv, cipher };

        // verify that [password] is correct
        if encrypted_db.kv.was_recovered() {
            // existing kv: can we decrypt the verification value?
            encrypted_db
                .get(PASSWORD_VERIFICATION_KEY)
                .map_err(|_| WrongPassword)?;
        } else {
            // new kv: encrypt the verification value
            encrypted_db.insert(PASSWORD_VERIFICATION_KEY, PASSWORD_VERIFICATION_VALUE)?;
        }

        Ok(encrypted_db)
    }

    /// Recommended default params. Should NOT be changed without a migration of the kvstore.
    /// See [scrypt::Params] for more info. These are fixed instead of using [scrypt::Params::default()]
    /// to avoid regression if the default recommendation changes.
    fn scrypt_params() -> EncryptedDbResult<scrypt::Params> {
        scrypt::Params::new(15, 8, 1, 32).map_err(PasswordScryptParams)
    }

    fn chacha20poly1305_kdf(
        password: Password,
        salt: PasswordSalt,
    ) -> EncryptedDbResult<chacha20poly1305::Key> {
        let mut output = chacha20poly1305::Key::default();

        scrypt::scrypt(
            password.as_ref(),
            salt.as_ref(),
            &Self::scrypt_params()?,
            output.as_mut_slice(),
        )?;

        Ok(output)
    }

    /// get a new random nonce to use for value encryption using [rand::thread_rng]
    fn generate_nonce() -> chacha20poly1305::XNonce {
        let mut bytes = chacha20poly1305::XNonce::default();
        rand::thread_rng().fill_bytes(bytes.as_mut_slice());
        bytes
    }

    /// create a new [EncryptedRecord] containing an encrypted value and a newly derived random nonce.
    /// `aad` is bound into the AEAD (typically the sled key) so ciphertext cannot be swapped across keys.
    fn encrypt<V>(&self, value: V, aad: &[u8]) -> EncryptedDbResult<EncryptedRecord>
    where
        V: Into<IVec>,
    {
        let nonce = Self::generate_nonce();

        self.encrypt_with_nonce(value, nonce, aad)
    }

    /// create a new [EncryptedRecord] containing an encrypted value and a given nonce.
    fn encrypt_with_nonce<V>(
        &self,
        value: V,
        nonce: chacha20poly1305::XNonce,
        aad: &[u8],
    ) -> EncryptedDbResult<EncryptedRecord>
    where
        V: Into<IVec>,
    {
        let mut value = value.into().to_vec();

        // encrypt value — AAD binds ciphertext to the store key / uid
        self.cipher
            .encrypt_in_place(&nonce, aad, &mut value)
            .map_err(|e| Encryption(e.to_string()))?;

        // return record
        Ok(EncryptedRecord::new(value, nonce))
    }

    /// derive a decrypted value from a [EncryptedRecord] containing an encrypted value and a random nonce.
    /// Tries `aad` first; falls back to empty AAD for records written before key-binding.
    fn decrypt_record_value(&self, record: EncryptedRecord, aad: &[u8]) -> EncryptedDbResult<IVec> {
        let (value, nonce) = record.into();

        let mut with_aad = value.clone();
        if self.cipher.decrypt_in_place(&nonce, aad, &mut with_aad).is_ok() {
            return Ok(with_aad.into());
        }

        let mut legacy = value;
        self.cipher
            .decrypt_in_place(&nonce, b"", &mut legacy)
            .map_err(|e| Decryption(e.to_string()))?;
        Ok(legacy.into())
    }

    /// derive a decrypted value from [EncryptedRecord] bytes
    fn decrypt(&self, record_bytes: Option<IVec>, aad: &[u8]) -> EncryptedDbResult<Option<IVec>> {
        let res = match record_bytes {
            Some(record_bytes) => {
                let record = EncryptedRecord::from_bytes(&record_bytes)?;
                let decrypted_value_bytes = self.decrypt_record_value(record, aad)?;
                Some(decrypted_value_bytes)
            }
            None => None,
        };
        Ok(res)
    }

    /// Insert a key to a new encrypted value, returning and decrypting the last value if it was set.
    pub fn insert<K, V>(&self, key: K, value: V) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
        V: Into<IVec>,
    {
        let key_ref = key.as_ref();
        let record = self.encrypt(value, key_ref)?;
        let prev_record_bytes_opt = self.kv.insert(key_ref, record.to_bytes()?)?;
        self.decrypt(prev_record_bytes_opt, key_ref)
    }

    /// Retrieve and decrypt a value from the `Tree` if it exists.
    pub fn get<K>(&self, key: K) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
    {
        let key_ref = key.as_ref();
        let bytes_opt = self.kv.get(key_ref)?;
        self.decrypt(bytes_opt, key_ref)
    }

    /// Returns `true` if the `Tree` contains a value for the specified key.
    pub fn contains_key<K>(&self, key: K) -> EncryptedDbResult<bool>
    where
        K: AsRef<[u8]>,
    {
        Ok(self.kv.contains_key(&key)?)
    }

    /// Delete a value, decrypting and returning the old value if it existed.
    pub fn remove<K>(&self, key: K) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
    {
        let key_ref = key.as_ref();
        let prev_val = self.kv.remove(key_ref)?;
        self.decrypt(prev_val, key_ref)
    }

    /// Returns true if the database was recovered from a previous process.
    pub fn was_recovered(&self) -> bool {
        self.kv.was_recovered()
    }

    #[cfg(test)]
    pub fn flush(&self) -> EncryptedDbResult<usize> {
        Ok(self.kv.flush()?)
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

    use super::EncryptedDb;
    use crate::encrypted_sled::{password::PasswordSalt, Password};

    #[test]
    fn chacha20poly1305_kdf_known_vector() {
        let password = Password::from("test_password");
        let salt = PasswordSalt::from([2; 32]);

        let key = hex::encode(EncryptedDb::chacha20poly1305_kdf(password, salt).unwrap());

        goldie::assert_json!(key);
    }

    #[test]
    fn encrypt_with_nonce_known_vector() {
        // Create a mock EncryptedDb with a deterministic cipher
        let mock_db = EncryptedDb {
            kv: sled::Config::new().temporary(true).open().unwrap(),
            cipher: XChaCha20Poly1305::new(&chacha20poly1305::Key::from([5u8; 32])),
        };

        let value = b"test_value";
        let nonce = XNonce::from([1u8; 24]);

        let aad = b"test_key";
        let encrypted_record = mock_db.encrypt_with_nonce(value, nonce, aad).unwrap();

        goldie::assert_json!(&encrypted_record);

        let decrypted_value = mock_db.decrypt_record_value(encrypted_record, aad).unwrap();
        assert_eq!(decrypted_value.as_ref(), value);
    }

    #[test]
    fn ciphertext_bound_to_key_aad() {
        let mock_db = EncryptedDb {
            kv: sled::Config::new().temporary(true).open().unwrap(),
            cipher: XChaCha20Poly1305::new(&chacha20poly1305::Key::from([5u8; 32])),
        };
        let value = b"share_material";
        let nonce = XNonce::from([1u8; 24]);
        let record_wrong = mock_db
            .encrypt_with_nonce(value, nonce, b"key-a")
            .unwrap();
        assert!(mock_db
            .decrypt_record_value(record_wrong, b"key-b")
            .is_err());
        let record_ok = mock_db
            .encrypt_with_nonce(value, nonce, b"key-a")
            .unwrap();
        assert_eq!(
            mock_db.decrypt_record_value(record_ok, b"key-a").unwrap().as_ref(),
            value
        );
    }
}

