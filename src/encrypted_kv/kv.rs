use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use sled::IVec;

use super::error::{
    EncryptedDbError::{Decryption, Encryption, WrongPassword},
    EncryptedDbResult,
};
use super::record::Record;

// TODO: change location of Password?
use crate::gg20::types::Password;

const VERIFICATION_KEY: &str = "tofnd";
const VERIFICATION_VALUE: &str = "tofnd";

/// create a new [EncryptedDb]
/// wraps sled::open(db_name) and passes password from a key derivation function
pub fn open(db_name: &str, password: Password) -> EncryptedDbResult<EncryptedDb> {
    // use password to create a key for cipher

    // Create cipher from password
    // TODO: pass password from KDF
    let key = Key::from_slice(password.0[0..32].as_ref());
    let cipher = ChaCha20Poly1305::new(key);

    // open kv
    let kv = sled::open(db_name)?;
    let was_recovered = kv.was_recovered();
    let encrypted_kv = EncryptedDb { kv, cipher };
    match was_recovered {
        true => {
            let _ = encrypted_kv
                .get(VERIFICATION_KEY)
                .map_err(|_| WrongPassword)?;
        }
        false => {
            let _ = encrypted_kv.insert(VERIFICATION_KEY, VERIFICATION_VALUE)?;
        }
    }

    Ok(encrypted_kv)
}

// TODO: pass cipher as a templated parameter?
// TODO: pass random seed?
pub struct EncryptedDb {
    kv: sled::Db,
    cipher: ChaCha20Poly1305,
}

impl EncryptedDb {
    fn get_random_nonce() -> [u8; 12] {
        rand::random()
    }

    fn encrypt(&self, value: &[u8]) -> EncryptedDbResult<Record> {
        let random_nonce = Self::get_random_nonce();
        let nonce = Nonce::from_slice(&random_nonce);

        let mut buffer: Vec<u8> = Vec::with_capacity(128);
        buffer.extend_from_slice(value.as_ref());

        // Q: need to fill accossiated data?
        self.cipher
            .encrypt_in_place(&nonce, b"", &mut buffer)
            .map_err(|e| Encryption(e.to_string()))?;

        Ok(Record::new(buffer, random_nonce))
    }

    fn decrypt_record_value(&self, record: &Record) -> EncryptedDbResult<Vec<u8>> {
        let nonce = Nonce::from_slice(&record.nonce);

        let mut buffer: Vec<u8> = Vec::with_capacity(128);
        buffer.extend_from_slice(record.encrypted_value.as_ref());

        self.cipher
            .decrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|e| Decryption(e.to_string()))?;

        Ok(buffer)
    }

    fn decrypt(&self, record_bytes: Option<IVec>) -> EncryptedDbResult<Option<IVec>> {
        let res = match record_bytes {
            Some(record_bytes) => {
                let record = Record::from_bytes(&record_bytes)?;
                let decrypted_value_bytes = self.decrypt_record_value(&record)?.into();
                Some(decrypted_value_bytes)
            }
            None => None,
        };
        Ok(res)
    }

    pub fn insert<K, V>(&self, key: K, encrypted_value: V) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let record = self.encrypt(encrypted_value.as_ref())?;
        let prev_record_bytes_opt = self.kv.insert(&key, record.as_bytes()?)?;
        self.decrypt(prev_record_bytes_opt)
    }

    pub fn get<K>(&self, key: K) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
    {
        let bytes_opt = self.kv.get(&key)?;
        self.decrypt(bytes_opt)
    }

    pub fn contains_key<K>(&self, key: K) -> EncryptedDbResult<bool>
    where
        K: AsRef<[u8]>,
    {
        Ok(self.kv.contains_key(&key)?)
    }

    pub fn remove<K>(&self, key: K) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
    {
        let prev_val = self.kv.remove(&key)?;
        self.decrypt(prev_val)
    }

    pub fn was_recovered(&self) -> bool {
        self.kv.was_recovered()
    }
}
