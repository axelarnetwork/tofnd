//! Handles KvStore operations. We use [sled] as the underlying db implementation.

use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;

use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::{mpsc, oneshot};

use tracing::{info, warn};

// Provided by the requester and used by the manager task to send the command response back to the requester.
// TODO make a custom error type https://github.com/tokio-rs/mini-redis/blob/c3bc304ac9f4b784f24b7f7012ed5a320594eb69/src/lib.rs#L58-L69
type Responder<T> = oneshot::Sender<Result<T, Box<dyn Error + Send + Sync>>>;

// default value for reserved key
const DEFAULT_RESERV: &str = "";

// default kv path
const DEFAULT_KV_PATH: &str = "kvstore";

// "actor" pattern (KV is the "handle"): https://ryhl.io/blog/actors-with-tokio/
// see also https://tokio.rs/tokio/tutorial/channels
#[derive(Clone)]
pub struct Kv<V> {
    sender: mpsc::UnboundedSender<Command<V>>,
}

pub type KvError = Box<dyn Error + Send + Sync>;
type KvResult<Success> = Result<Success, KvError>;

impl<V: 'static> Kv<V>
where
    V: Debug + Send + Sync + Serialize + DeserializeOwned,
{
    pub fn new(kv_name: &str) -> sled::Result<Self> {
        let kv_path = PathBuf::from(DEFAULT_PATH_ROOT)
            .join(DEFAULT_KV_PATH)
            .join(kv_name);
        // use to_string_lossy() instead of to_str() to avoid handling Option<&str>
        let kv_path = kv_path.to_string_lossy().to_string();
        Self::with_db_name(kv_path)
    }
    pub fn with_db_name(db_name: String) -> sled::Result<Self> {
        let (sender, rx) = mpsc::unbounded_channel();

        // get kv store from db name before entering the kv_cmd_handler because
        // it's more convenient to return an error from outside of a tokio::span
        let kv = get_kv_store(&db_name)?;

        tokio::spawn(kv_cmd_handler(rx, kv));
        Ok(Self { sender })
    }
    pub async fn reserve_key(&self, key: String) -> KvResult<KeyReservation> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender.send(ReserveKey { key, resp: resp_tx })?;
        resp_rx.await?
    }
    pub async fn unreserve_key(&self, reservation: KeyReservation) {
        let _ = self.sender.send(UnreserveKey { reservation });
    }
    pub async fn put(&self, reservation: KeyReservation, value: V) -> KvResult<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender.send(Put {
            reservation,
            value,
            resp: resp_tx,
        })?;
        resp_rx.await?
    }
    pub async fn get(&self, key: &str) -> KvResult<V> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender.send(Get {
            key: key.to_string(),
            resp: resp_tx,
        })?;
        resp_rx.await?
    }
    pub async fn exists(&self, key: &str) -> KvResult<bool> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender.send(Exists {
            key: key.to_string(),
            resp: resp_tx,
        })?;
        resp_rx.await?
    }
    pub async fn remove(&self, key: &str) -> KvResult<V> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender.send(Remove {
            key: key.to_string(),
            resp: resp_tx,
        })?;
        resp_rx.await?
    }

    #[cfg(test)]
    pub fn get_db_path(name: &str) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::new();
        path.push(name);
        path
    }
}

/// Returned from a successful `ReserveKey` command
#[derive(Debug)] // do not derive Clone, Copy
pub struct KeyReservation {
    key: String,
}

#[derive(Debug)]
enum Command<V> {
    ReserveKey {
        key: String,
        resp: Responder<KeyReservation>,
    },
    UnreserveKey {
        reservation: KeyReservation,
    },
    Put {
        reservation: KeyReservation,
        value: V,
        resp: Responder<()>,
    },
    Get {
        key: String, // TODO should be &str except lifetimes...
        resp: Responder<V>,
    },
    Exists {
        key: String, // TODO should be &str except lifetimes...
        resp: Responder<bool>,
    },
    Remove {
        key: String, // TODO should be &str except lifetimes...
        resp: Responder<V>,
    },
}
use Command::*;

use crate::DEFAULT_PATH_ROOT;

/// Returns the db with name `db_name`, or creates a new if such DB does not exist
/// Default path DB path is the executable's directory; The caller can specify a
/// full path followed by the name of the DB
/// Usage:
///  let my_db = get_kv_store(&"my_current_dir_db")?;
///  let my_db = get_kv_store(&"/tmp/my_tmp_bd")?;
fn get_kv_store(db_name: &str) -> sled::Result<sled::Db> {
    // create/open DB
    let kv = sled::open(db_name)?;

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
async fn kv_cmd_handler<V: 'static>(mut rx: mpsc::UnboundedReceiver<Command<V>>, kv: sled::Db)
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

// helper function to reserve a key
fn handle_reserve(kv: &sled::Db, key: String) -> KvResult<KeyReservation> {
    // search key in kv store.
    // If reserve key already exists inside our database, return an error
    if kv.contains_key(&key)? {
        return Err(From::from(format!(
            "kv_manager key <{}> already reserved",
            key
        )));
    }

    // try to insert the new key with default value
    kv.insert(&key, DEFAULT_RESERV)?;

    // return key reservation
    Ok(KeyReservation { key })
}

// helper function to insert a value
fn handle_put<V>(kv: &sled::Db, reservation: KeyReservation, value: V) -> KvResult<()>
where
    V: Serialize,
{
    // check if key holds the default reserve value. If not, send an error.
    // Explanation of code ugliness: that's the standard way to compare a
    // sled retrieved value with a local value:
    // https://docs.rs/sled/0.34.6/sled/struct.Tree.html#examples-4
    if kv.get(&reservation.key)? != Some(sled::IVec::from(DEFAULT_RESERV)) {
        return Err(From::from("Serialization of value failed"));
    }

    // convert value into bytes
    let bytes = bincode::serialize(&value)?;

    // insert new value
    kv.insert(&reservation.key, bytes)?;

    Ok(())
}

// helper function to get a value
fn handle_get<V>(kv: &sled::Db, key: String) -> KvResult<V>
where
    V: DeserializeOwned,
{
    // try to get value of 'key'
    let value = match kv.get(&key)? {
        Some(bytes) => bincode::deserialize(&bytes)?,
        None => {
            return Err(From::from(format!("key {} does not have a value", key)));
        }
    };

    // return value
    Ok(value)
}

fn handle_exists(kv: &sled::Db, key: &str) -> KvResult<bool> {
    kv.contains_key(key).map_err(|err| {
        From::from(format!(
            "Could not perform 'contains_key' for {}: {}",
            key, err
        ))
    })
}

// helper function to delete a value
fn handle_remove<V>(kv: &sled::Db, key: String) -> KvResult<V>
where
    V: DeserializeOwned,
{
    // try to remove value of 'key'
    let value = match kv.remove(&key)? {
        Some(bytes) => bincode::deserialize(&bytes)?,
        None => {
            return Err(From::from(format!("key {} did not have a value", key)));
        }
    };

    // return value
    Ok(value)
}

#[cfg(test)]
mod tests;
