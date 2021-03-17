use std::error::Error;
use std::fmt::Debug;

use std::path::PathBuf;

use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::{mpsc, oneshot};

// Provided by the requester and used by the manager task to send the command response back to the requester.
// TODO make a custom error type https://github.com/tokio-rs/mini-redis/blob/c3bc304ac9f4b784f24b7f7012ed5a320594eb69/src/lib.rs#L58-L69
type Responder<T> = oneshot::Sender<Result<T, Box<dyn Error + Send + Sync>>>;

// default value for reserved key 
const DEFAULT_RESERV: &str = "";

// "actor" pattern (KV is the "handle"): https://draft.ryhl.io/blog/actors-with-tokio/
// see also https://tokio.rs/tokio/tutorial/channels
#[derive(Clone)]
pub struct KV<V> {
    sender: mpsc::Sender<Command<V>>,
}
impl<V: 'static> KV<V>
where
    V: Debug + Send + Sync + Serialize + DeserializeOwned,
{
    pub fn new() -> Self {
        Self::with_db_name("keys")
    }
    pub fn with_db_name(db_name: &str) -> Self {
        let (sender, rx) = mpsc::channel(4); // TODO buffer size?
        tokio::spawn(kv_cmd_handler(rx, db_name.to_string()));
        Self { sender }
    }
    pub async fn reserve_key(
        &mut self,
        key: String,
    ) -> Result<KeyReservation, Box<dyn Error + Send + Sync>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender.send(ReserveKey { key, resp: resp_tx }).await?;
        resp_rx.await?
    }
    pub async fn unreserve_key(&mut self, reservation: KeyReservation) {
        let _ = self.sender.send(UnreserveKey { reservation }).await;
    }
    pub async fn put(
        &mut self,
        reservation: KeyReservation,
        value: V,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Put {
                reservation,
                value,
                resp: resp_tx,
            })
            .await?;
        resp_rx.await?
    }
    pub async fn get(&mut self, key: &str) -> Result<V, Box<dyn Error + Send + Sync>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Get {
                key: key.to_string(),
                resp: resp_tx,
            })
            .await?;
        resp_rx.await?
    }

    #[cfg(test)]
    pub fn get_db_path(name: &str) -> std::path::PathBuf {
        let mut path = PathBuf::new();
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
            "kv_manager cannot open existing db [{}]. creating new db", db_name
        );
    }
    kv
}

// kv_cmd_handler is called from _within_ tofnd to return results of a Command.
// Because we are are using the async tokio lib (and the "actor" patern) which 
// is build on async calls, this handler also needs to be an async function. 
// Notice the pattern: `let _ = resp.send(res);`. Here, we deliberately choose 
// to ignore the response of resp.send(). After discusion, we came to the 
// conclusion that we should treat `kv_cmd_handler` as a conventional Rust fn
// to avoid complexity in the code. See discusion here:
// https://github.com/axelarnetwork/tofnd/pull/15/files#r595303423
async fn kv_cmd_handler<V: 'static>(mut rx: mpsc::Receiver<Command<V>>, db_name: String)
where
    V: Serialize + DeserializeOwned,
{
    let kv = get_kv_store(db_name);
    while let Some(cmd) = rx.recv().await {
        match cmd {
            ReserveKey { key, resp } => {
                // make reserve actions
                let res = handle_reserve(&kv, key);
                if let Err(_) = resp.send(res) {
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
                let res = handle_put(&kv, reservation, value);
                if let Err(_) = resp.send(res) {
                    println!("WARN: the receiver dropped");
                }
            }
            Get { key, resp } => {
                let res = handle_get(&kv, key);
                if let Err(_) = resp.send(res) {
                    println!("WARN: the receiver dropped");
                }
            }
        }
    }
    println!("kv_manager stop");
}

// helper function to make actions regarding reserve key
fn handle_reserve(kv: &sled::Db, key: String) -> Result<KeyReservation, Box<dyn Error + Send + Sync>> {
    // insert ('key', "") and get previous value of 'key'
    match kv.insert(&key, DEFAULT_RESERV) {
        // if insertion was successful, check previous value of 'key'
        Ok(previous_value) => {
            // if previous value is None it means that we had no 
            // reservations for this key. that's the happy path 
            if previous_value.is_none() {
                Ok(KeyReservation { key })
            } else {
                // if some value was already reserved for that key, 
                // return an error 
                Err(From::from(format!(
                    "kv_manager key {} already reserved",
                    key
                )))
            }
        },
        // if inseriton was unsuccessful, we have a problem
        Err(reserve_attempt_err) => {
            Err(From::from(reserve_attempt_err))
        }
    }
}

// helper function to make actions regarding value insertion
fn handle_put<V>(kv: &sled::Db, reservation: KeyReservation, value: V) -> Result<(), Box<dyn Error + Send + Sync>> 
where
    V: Serialize,
{
    // check if key holds the default reserve value. If not, send an error.
    // Explanation of code ugliness: that's the standard way to compare a 
    // sled retrieved value with a local value: 
    // https://docs.rs/sled/0.34.6/sled/struct.Tree.html#examples-4
    if kv.get(&reservation.key)? != Some(sled::IVec::from(DEFAULT_RESERV)) {
        return Err(From::from(format!(
            "Serialization of value failed"
        )))
    }

    // convert value into bytes
    let bytes = bincode::serialize(&value)?;

    // insert new value
    kv.insert(&reservation.key, bytes)?;

    // try to flash and print a warning if failed
    // Note: The sole purpose of flushing is to facititate tests :( 
    // see documentation in tests/mods.rs for more info
    if let Err(_) = kv.flush() {
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
    match kv.get(&key) {
        // if get was successful
        Ok(bytes) => {
            // if key did not have a value, return error
            if bytes.is_none() {
                return Err(From::from(format!(
                        "key {} did not have a value", key
                       )))
            } 
            // try to convert bytes to V
            let bytes = bytes.unwrap();
            // let codec = bincode::config();
            let res = bincode::deserialize(&bytes);
            // if deserialization failed, return error
            if res.is_err() {
                return Err(From::from(format!(
                        "value cannot be deserialized" 
                    )))
            } 
            // return value
            let value = res.unwrap();
            Ok(value)
        },
        // if get failed, return an error
        Err(err) => {
            Err(From::from(format!(
                    "cannot rerieve value for key {} : {}", key, err 
            )))
        }
    }
}