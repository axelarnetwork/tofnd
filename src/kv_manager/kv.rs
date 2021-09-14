//! Public API for kvstore operations
//! Errors are mapped to [super::error::KvError]

use super::{
    error::{KvError::*, KvResult},
    sled_bindings::{handle_exists, handle_get, handle_put, handle_remove, handle_reserve},
    types::{
        Command::{self, *},
        KeyReservation, DEFAULT_KV_PATH,
    },
};
use crate::encryption::{encryption_cipher, EncryptedDb, Password};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, path::PathBuf};
use tokio::sync::{mpsc, oneshot};

// logging
use tracing::{info, warn};

#[derive(Clone)]
pub struct Kv<V> {
    sender: mpsc::UnboundedSender<Command<V>>,
}

// database functionality using the "actor" pattern (Kv is the "handle"): https://ryhl.io/blog/actors-with-tokio/
// see also https://tokio.rs/tokio/tutorial/channels
impl<V: 'static> Kv<V>
where
    V: Debug + Send + Sync + Serialize + DeserializeOwned,
{
    /// Creates a new kv service. Returns [InitErr] on failure.
    pub fn new(kv_name: &str, password: Password) -> KvResult<Self> {
        let kv_path = PathBuf::from(crate::DEFAULT_PATH_ROOT)
            .join(DEFAULT_KV_PATH)
            .join(kv_name);
        // use to_string_lossy() instead of to_str() to avoid handling Option<&str>
        let kv_path = kv_path.to_string_lossy().to_string();
        Self::with_db_name(kv_path, password)
    }

    /// Spawns a new kv_manager. Returns [InitErr] on failure.
    pub fn with_db_name(db_name: String, password: Password) -> KvResult<Self> {
        let (sender, rx) = mpsc::unbounded_channel();

        // get kv store from db name before entering the kv_cmd_handler because
        // it's more convenient to return an error from outside of a tokio::span
        let kv = get_kv_store(&db_name, password)?;

        tokio::spawn(kv_cmd_handler(rx, kv));
        Ok(Self { sender })
    }

    /// Reserves a key in the kvstore with [super::types::DEFAULT_RESERV] value.
    /// Returns [ReserveErr] or [SendErr] on failure.
    pub async fn reserve_key(&self, key: String) -> KvResult<KeyReservation> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(ReserveKey { key, resp: resp_tx })
            .map_err(|err| SendErr(err.to_string()))?;
        resp_rx.await?.map_err(ReserveErr)
    }

    /// Unreserves an existing reservation
    pub async fn unreserve_key(&self, reservation: KeyReservation) {
        let _ = self.sender.send(UnreserveKey { reservation });
    }

    /// Puts a new value given a [super::types::KeyReservation]
    /// Returns [PutErr] or [SendErr] on failure.
    pub async fn put(&self, reservation: KeyReservation, value: V) -> KvResult<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Put {
                reservation,
                value,
                resp: resp_tx,
            })
            .map_err(|e| SendErr(e.to_string()))?;
        resp_rx.await?.map_err(PutErr)
    }

    /// Gets a value given a key
    /// Returns [GetErr] or [SendErr] on failure.
    pub async fn get(&self, key: &str) -> KvResult<V> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Get {
                key: key.to_string(),
                resp: resp_tx,
            })
            .map_err(|e| SendErr(e.to_string()))?;
        resp_rx.await?.map_err(GetErr)
    }

    /// Checks if a key exists in the kvstore
    /// Returns [ExistsErr] or [SendErr] on failure.
    pub async fn exists(&self, key: &str) -> KvResult<bool> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Exists {
                key: key.to_string(),
                resp: resp_tx,
            })
            .map_err(|e| SendErr(e.to_string()))?;
        resp_rx.await?.map_err(ExistsErr)
    }

    /// Removes a key and its corresponding value from the kvstore
    /// Returns [RemoveErr] or [SendErr] on failure.
    pub async fn remove(&self, key: &str) -> KvResult<V> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Remove {
                key: key.to_string(),
                resp: resp_tx,
            })
            .map_err(|e| SendErr(e.to_string()))?;
        resp_rx.await?.map_err(RemoveErr)
    }

    #[cfg(test)]
    pub fn get_db_path(name: &str) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(name);
        path
    }
}

/// Returns the db with name `db_name`, or creates a new if such DB does not exist
/// Returns [encrypted_sled::Error] on failure.
/// Default path DB path is the executable's directory; The caller can specify a
/// full path followed by the name of the DB
/// Usage:
///  let my_db = get_kv_store(&"my_current_dir_db")?;
///  let my_db = get_kv_store(&"/tmp/my_tmp_bd")?;
pub fn get_kv_store(db_name: &str, password: Password) -> KvResult<EncryptedDb> {
    // get encryption cipher
    let cipher = encryption_cipher(password).map_err(|err| EncryptionErr(err.to_string()))?;

    // create/open encrypted database
    let kv = encrypted_sled::open(db_name, cipher)?;

    // log whether the DB was newly created or not
    if kv.was_recovered() {
        info!("kv_manager found existing db [{}]", db_name);
    } else {
        info!(
            "kv_manager cannot open existing db [{}]. creating new db",
            db_name
        );
    }
    Ok(kv)
}

// private handler function to process commands as per the "actor" pattern (see above)
async fn kv_cmd_handler<V: 'static>(mut rx: mpsc::UnboundedReceiver<Command<V>>, kv: EncryptedDb)
where
    V: Serialize + DeserializeOwned,
{
    // if resp.send() fails then log a warning and continue
    // see discussion https://github.com/axelarnetwork/tofnd/pull/15#discussion_r595426775
    while let Some(cmd) = rx.recv().await {
        // TODO better error handling and logging: we should log when `handle_*` fails
        // TODO refactor repeated code
        match cmd {
            ReserveKey { key, resp } => {
                if resp.send(handle_reserve(&kv, key)).is_err() {
                    warn!("receiver dropped");
                }
            }
            UnreserveKey { reservation } => {
                let _ = kv.remove(&reservation.key);
            }
            Put {
                reservation,
                value,
                resp,
            } => {
                if resp.send(handle_put(&kv, reservation, value)).is_err() {
                    warn!("receiver dropped");
                }
            }
            Get { key, resp } => {
                if resp.send(handle_get(&kv, key)).is_err() {
                    warn!("receiver dropped");
                }
            }
            Exists { key, resp } => {
                if resp.send(handle_exists(&kv, &key)).is_err() {
                    warn!("receiver dropped");
                }
            }
            Remove { key, resp } => {
                if resp.send(handle_remove(&kv, key)).is_err() {
                    warn!("receiver dropped");
                }
            }
        }
    }
    info!("kv_manager stop");
}
