use std::error::Error;
use std::fmt::Debug;

use std::path::PathBuf;

// use sled;
// use microkv::MicroKV;
// use sled::Db;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::{mpsc, oneshot};

// TODO don't use microkv---it's too new and we don't need the concurrency safety because we're taking care of that ourselves

// Provided by the requester and used by the manager task to send the command response back to the requester.
// TODO make a custom error type https://github.com/tokio-rs/mini-redis/blob/c3bc304ac9f4b784f24b7f7012ed5a320594eb69/src/lib.rs#L58-L69
type Responder<T> = oneshot::Sender<Result<T, Box<dyn Error + Send + Sync>>>;

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
        // TODO: fix db path
        let mut path = PathBuf::new();
        let mut p: String = "/Users/steliosdaveas/Projects/axelar/tofnd/".to_owned();
        p.push_str(name);
        path.push(p.clone());
        println!("Trying to delete {:?}", p);
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
                let exists = kv.contains_key(&key);
                // we only care about resp.send failure after a successful kv.put
                if exists.is_err() {
                    let _ = resp.send(Err(From::from(exists.unwrap_err())));
                    continue; // TODO handle each cmd in a separate fn, return here instead of continue
                }
                let exists = exists.unwrap();
                if exists {
                    let _ = resp.send(Err(From::from(format!(
                        "kv_manager key {} already reserved",
                        key
                    ))));
                    continue;
                }
                let reserve_attempt = kv.insert(&key, ""); // "" value marks key as reserved
                if reserve_attempt.is_err() {
                    let _ = resp.send(Err(From::from(reserve_attempt.unwrap_err())));
                    continue;
                }
                let resp_attempt = resp.send(Ok(KeyReservation { key }));
                if resp_attempt.is_err() {
                    // unreserve the key---no one was listening to our response
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
                // key should exist with value ""; that's how we reserve keys
                // warn but do not abort if this check fails
                let bytes = bincode::serialize(&value);
                if bytes.is_ok() {
                    println!("  Bytes ok");
                } else {
                    println!("  Bytes NOT ok");
                }
                let bytes = bytes.unwrap();

                match kv.insert(&reservation.key, bytes) {
                    Ok(reserved_val) => {
                        if reserved_val != Some(sled::IVec::from("")) {
                            let reserved_val = sled::IVec::from(&reserved_val.unwrap());
                            let reserved_val = std::str::from_utf8(&reserved_val).unwrap();
                            println!(
                                "WARN: kv_manager overwriting nonempty value [{}] for reserved key [{}]",
                                reserved_val,
                                &reservation.key
                            );
                        }
                        let _ = resp.send(Ok(()));
                    },
                    Err(_) => {
                        println!(
                            "WARN: kv_manager failure to get reserved key [{}]",
                            &reservation.key
                        );
                    }
                }
                // let reserved_val = kv.insert(&reservation.key, bytes.unwrap());
                // if reserved_val.is_err() {
                //     println!(
                //         "WARN: kv_manager failure to add value to reserved key [{}]",
                //         &reservation.key
                //     );
                // } else {
                //     let reserved_val = reserved_val.unwrap();
                //     if reserved_val != Some(sled::IVec::from("")) {
                //         let reserved_val = sled::IVec::from(&reserved_val.unwrap());
                //         let reserved_val = std::str::from_utf8(&reserved_val).unwrap();
                //         println!(
                //             "WARN: kv_manager overwriting nonempty value [{}] for reserved key [{}]",
                //             reserved_val,
                //             &reservation.key
                //         );
                //     }
                // }
                // let _ = resp.send(Ok(()));
            }
            Get { key, resp } => {
                match kv.get(&key) {
                    Ok(bytes) => {
                        let v = bincode::deserialize(&bytes.unwrap()).unwrap();
                        let _ = resp.send(Ok(v));
                    },
                    Err(err) => {
                        let _ = resp.send(Err(From::from(err)));
                    },
                }
            }
        }
    }
    println!("kv_manager stop");
}
