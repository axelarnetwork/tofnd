use std::error::Error;
use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::{mpsc, oneshot};

// Provided by the requester and used by the manager task to send the command response back to the requester.
// TODO make a custom error type https://github.com/tokio-rs/mini-redis/blob/c3bc304ac9f4b784f24b7f7012ed5a320594eb69/src/lib.rs#L58-L69
type Responder<T> = oneshot::Sender<Result<T, Box<dyn Error + Send + Sync>>>;

// default value for reserved key
const DEFAULT_RESERV: &str = "";

// "actor" pattern (KV is the "handle"): https://ryhl.io/blog/actors-with-tokio/
// see also https://tokio.rs/tokio/tutorial/channels
#[derive(Clone)]
pub struct Kv<V> {
    sender: mpsc::UnboundedSender<Command<V>>,
}
impl<V: 'static> Kv<V>
where
    V: Debug + Send + Sync + Serialize + DeserializeOwned,
{
    pub fn new() -> Self {
        Self::with_db_name(".kvstore")
    }
    pub fn with_db_name(db_name: &str) -> Self {
        let (sender, rx) = mpsc::unbounded_channel();
        tokio::spawn(kv_cmd_handler(rx, db_name.to_string()));
        Self { sender }
    }
    pub async fn reserve_key(
        &mut self,
        key: String,
    ) -> Result<KeyReservation, Box<dyn Error + Send + Sync>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender.send(ReserveKey { key, resp: resp_tx })?;
        resp_rx.await?
    }
    pub async fn unreserve_key(&mut self, reservation: KeyReservation) {
        let _ = self.sender.send(UnreserveKey { reservation });
    }
    pub async fn put(
        &mut self,
        reservation: KeyReservation,
        value: V,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender.send(Put {
            reservation,
            value,
            resp: resp_tx,
        })?;
        resp_rx.await?
    }
    pub async fn get(&self, key: &str) -> Result<V, Box<dyn Error + Send + Sync>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender.send(Get {
            key: key.to_string(),
            resp: resp_tx,
        })?;
        resp_rx.await?
    }
    pub async fn remove(&mut self, key: &str) -> Result<V, Box<dyn Error + Send + Sync>> {
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
    Remove {
        key: String, // TODO should be &str except lifetimes...
        resp: Responder<V>,
    },
}
use Command::*;

// Returns the db with name `db_name`, or creates a new if such DB does not exist
// Default path DB path is the executable's directory; The caller can specify a
// full path followed by the name of the DB
// Usage:
//  let my_db = get_kv_store(&"my_current_dir_db").unwrap();
//  let my_db = get_kv_store(&"/tmp/my_tmp_bd").unwrap();
fn get_kv_store(db_name: String) -> sled::Db {
    // create/open DB
    let kv = sled::open(&db_name).unwrap();
    // print whether the DB was newly created or not
    if kv.was_recovered() {
        println!("kv_manager found existing db [{}]", db_name);
    } else {
        println!(
            "kv_manager cannot open existing db [{}]. creating new db",
            db_name
        );
    }
    kv
}

// private handler function to process commands as per the "actor" pattern (see above)
async fn kv_cmd_handler<V: 'static>(mut rx: mpsc::UnboundedReceiver<Command<V>>, db_name: String)
where
    V: Serialize + DeserializeOwned,
{
    // if resp.send() fails then log a warning and continue
    // see discussion https://github.com/axelarnetwork/tofnd/pull/15#discussion_r595426775
    let kv = get_kv_store(db_name);
    while let Some(cmd) = rx.recv().await {
        // TODO better error handling and logging: we should log when `handle_*` fails
        // TODO refactor repeated code
        match cmd {
            ReserveKey { key, resp } => {
                if resp.send(handle_reserve(&kv, key)).is_err() {
                    println!("WARN: the receiver dropped");
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
                    println!("WARN: the receiver dropped");
                }
            }
            Get { key, resp } => {
                if resp.send(handle_get(&kv, key)).is_err() {
                    println!("WARN: the receiver dropped");
                }
            }
            Remove { key, resp } => {
                if resp.send(handle_remove(&kv, key)).is_err() {
                    println!("WARN: the receiver dropped");
                }
            }
        }
    }
    println!("kv_manager stop");
}

// helper function to make actions regarding reserve key
fn handle_reserve(
    kv: &sled::Db,
    key: String,
) -> Result<KeyReservation, Box<dyn Error + Send + Sync>> {
    // search key in kv store.
    // If reserve key already exists inside our database, return an error
    if kv.contains_key(&key)? {
        return Err(From::from(format!(
            "kv_manager key {} already reserved",
            key
        )));
    }

    // try to insert the new key with default value
    kv.insert(&key, DEFAULT_RESERV)?;

    // return key reservation
    Ok(KeyReservation { key })
}

// helper function to make actions regarding value insertion
fn handle_put<V>(
    kv: &sled::Db,
    reservation: KeyReservation,
    value: V,
) -> Result<(), Box<dyn Error + Send + Sync>>
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

    // try to flash and print a warning if failed
    // TODO: The sole purpose of flushing is to facititate tests :(
    // We want clean-up for each test; this means that when tests finish,
    // databases need to be deleted. Because database deletion can interfere with
    // pending transactions to the database causing errors at tests, we choose to
    // flush after every time we insert a value. This is a temporary solution and
    // should be handled accordingly by having tests using their own sub-space.
    if kv.flush().is_err() {
        println!("WARN: flush failed");
    }
    Ok(())
}

// helper function to make actions regarding value retrieve
fn handle_get<V>(kv: &sled::Db, key: String) -> Result<V, Box<dyn Error + Send + Sync>>
where
    V: DeserializeOwned,
{
    // try to get value of 'key'
    let bytes = kv.get(&key)?;

    // check if key is valid
    if bytes.is_none() {
        return Err(From::from(format!("key {} did not have a value", key)));
    }

    // try to convert bytes to V
    let value = bincode::deserialize(&bytes.unwrap())?;

    // return value
    Ok(value)
}

// helper function to delete values
fn handle_remove<V>(kv: &sled::Db, key: String) -> Result<V, Box<dyn Error + Send + Sync>>
where
    V: DeserializeOwned,
{
    // try to remove value of 'key'
    let bytes = kv.remove(&key)?;

    // check if result was valid
    if bytes.is_none() {
        return Err(From::from(format!("key {} did not have a value", key)));
    }

    // try to convert bytes to V
    let value = bincode::deserialize(&bytes.unwrap())?;

    // return value
    Ok(value)
}

#[cfg(test)]
mod tests;
