use std::error::Error;
use std::fmt::Debug;

use microkv::MicroKV;
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
        MicroKV::get_db_path(name)
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

async fn kv_cmd_handler<V: 'static>(mut rx: mpsc::Receiver<Command<V>>, db_name: String)
where
    V: Serialize + DeserializeOwned,
{
    let kv = MicroKV::new(&db_name).with_pwd_clear("unsafe_pwd".to_string());
    while let Some(cmd) = rx.recv().await {
        match cmd {
            ReserveKey { key, resp } => {
                let exists = kv.exists(&key);

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
                let reserve_attempt = kv.put(&key, &""); // "" value marks key as reserved
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
                    let _ = kv.delete(&key);
                }
            }
            UnreserveKey { reservation } => {
                let _ = kv.delete(&reservation.key);
            }
            Put {
                reservation,
                value,
                resp,
            } => {
                // key should exist with value ""; that's how we reserve keys
                // warn but do not abort if this check fails
                let reserve_val = kv.get::<String>(&reservation.key);
                if reserve_val.is_err() {
                    println!(
                        "WARN: kv_manager failure to get reserved key [{}]",
                        &reservation.key
                    );
                } else {
                    let reserve_val = reserve_val.unwrap();
                    if !reserve_val.is_empty() {
                        println!(
                            "WARN: kv_manager overwriting nonempty value [{}] for reserved key [{}]",
                            reserve_val,
                            &reservation.key
                        );
                    }
                }

                // attempt to add result to the kv store
                let put_attempt = kv.put(&reservation.key, &value);
                if put_attempt.is_err() {
                    let _ = resp.send(Err(From::from(put_attempt.unwrap_err())));
                    continue;
                }

                // attempt to persist the kv store to disk
                let persist_attempt = kv.commit();
                if persist_attempt.is_err() {
                    let _ = resp.send(Err(From::from(persist_attempt.unwrap_err())));
                    continue;
                }

                let _ = resp.send(Ok(()));
            }
            Get { key, resp } => {
                let _ = resp.send(kv.get(&key).map_err(From::from));
            }
        }
    }
    println!("kv_manager stop");
}
