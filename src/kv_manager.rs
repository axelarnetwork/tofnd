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

                // Question: Is this needed? And, if yes, should we check responses for the other commands as well?
                // send and check response
                let resp_attempt = resp.send(res);
                if resp_attempt.is_err() {
                    // unreserve the key --- no one was listening to our response
                    let key = resp_attempt.unwrap_err().unwrap().key;
                    println!(
                        "WARN: kv_manager unreserving key [{}], fail to respond to ReserveKey (is no one listening for my response?)",
                        key
                    );
                    let _ = kv.remove(&key);
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
                let _ = resp.send(res);
            }
            Get { key, resp } => {
                let res = handle_get(&kv, key);
                let _ = resp.send(res);
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
    // convert value into bytes
    let bytes = bincode::serialize(&value);
    // check if serialization failed
    if bytes.is_err() {
    // check if key holds the default reserve value. If not, send an error.
    if kv.get(&reservation.key)? != Some(sled::IVec::from(DEFAULT_RESERV)) {
        return Err(From::from(format!(
            "Serialization of value failed"
        )))
    }
    let bytes = bytes.unwrap();

    match kv.insert(&reservation.key, bytes) {
        // insertion succeeded
        Ok(reserved_val) => {
            // key should exist with value ""; that's how we reserve keys
            // warn but do not abort if this check fails
            if reserved_val != Some(sled::IVec::from("")) {
                let reserved_val = sled::IVec::from(&reserved_val.unwrap());
                let reserved_val = std::str::from_utf8(&reserved_val).unwrap();
                println!(
                    "WARN: kv_manager overwriting nonempty value [{}] for reserved key [{}]",
                    reserved_val,
                    &reservation.key
                );
            }
            // try to flash and print a warning in failed
            match kv.flush() {
                Err(err) => {
                    println!("WARN: Flush failed: {}", err);
                },
                _ => ()
            }
        },
        // insertion failed
        Err(err) => {
            return Err(From::from(format!(
                "Could not insert value: {}", err
            )))
        }
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