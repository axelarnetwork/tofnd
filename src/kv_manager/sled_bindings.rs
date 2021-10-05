//! Bindings for [sled::Db] operations. Errors are mapped to [super::error::InnerKvError].

use serde::{de::DeserializeOwned, Serialize};
use tofn::sdk::api::{deserialize, serialize};

use super::error::{InnerKvError::*, InnerKvResult};
use super::types::{KeyReservation, DEFAULT_RESERV};

use crate::encrypted_sled;

/// Reserves a key. New's key value is [DEFAULT_RESERV].
/// Returns [SledErr] of [LogicalErr] on failure.
pub(super) fn handle_reserve(
    kv: &encrypted_sled::Db,
    key: String,
) -> InnerKvResult<KeyReservation> {
    // search key in kv store.
    // If reserve key already exists inside our database, return an error
    if kv.contains_key(&key)? {
        return Err(LogicalErr(format!(
            "kv_manager key <{}> already reserved",
            key
        )));
    }

    // try to insert the new key with default value
    kv.insert(&key, DEFAULT_RESERV)?;

    // return key reservation
    Ok(KeyReservation { key })
}

/// Inserts a value to an existing key.
/// Returns [SledErr] of [LogicalErr] on failure.
pub(super) fn handle_put<V>(
    kv: &encrypted_sled::Db,
    reservation: KeyReservation,
    value: V,
) -> InnerKvResult<()>
where
    V: Serialize,
{
    // check if key holds the default reserve value. If not, send an error.
    // Explanation of code ugliness: that's the standard way to compare a
    // sled retrieved value with a local value:
    // https://docs.rs/sled/0.34.6/sled/struct.Tree.html#examples-4
    if kv.get(&reservation.key)? != Some(sled::IVec::from(DEFAULT_RESERV)) {
        return Err(LogicalErr(format!(
            "did not find reservation for key <{}> in kv store",
            reservation.key
        )));
    }

    // convert value into bytes
    let bytes = serialize(&value).map_err(|_| SerializationErr)?;

    // insert new value
    kv.insert(&reservation.key, bytes)?;

    Ok(())
}

/// Get the value of an existing key.
/// Returns [SledErr] of [LogicalErr] on failure.
pub(super) fn handle_get<V>(kv: &encrypted_sled::Db, key: String) -> InnerKvResult<V>
where
    V: DeserializeOwned,
{
    // try to get value of 'key'
    let value = match kv.get(&key)? {
        Some(bytes) => deserialize(&bytes).ok_or(DeserializationErr)?,
        None => {
            return Err(LogicalErr(format!("key <{}> does not have a value", key)));
        }
    };

    // return value
    Ok(value)
}

/// Checks if a key exists in the kvstore.
/// Returns [SledErr] of [LogicalErr] on failure.
pub(super) fn handle_exists(kv: &encrypted_sled::Db, key: &str) -> InnerKvResult<bool> {
    kv.contains_key(key).map_err(|err| {
        LogicalErr(format!(
            "Could not perform 'contains_key' for key <{}> due to error: {}",
            key, err
        ))
    })
}

/// Deletes the key and it's value from the kv store.
/// Returns [SledErr] of [LogicalErr] on failure.
pub(super) fn handle_remove<V>(kv: &encrypted_sled::Db, key: String) -> InnerKvResult<V>
where
    V: DeserializeOwned,
{
    // try to remove value of 'key'
    let value = match kv.remove(&key)? {
        Some(bytes) => deserialize(&bytes).ok_or(DeserializationErr)?,
        None => {
            return Err(LogicalErr(format!("key <{}> does not have a value", key)));
        }
    };

    // return value
    Ok(value)
}
