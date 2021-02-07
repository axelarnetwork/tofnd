use std::error::Error;
use std::fmt::Debug;

use microkv::MicroKV;
use tokio::sync::{mpsc, oneshot};

// TODO don't use microkv---it's too new and we don't need the concurrency safety because we're taking care of that ourselves

// Provided by the requester and used by the manager task to send the command response back to the requester.
// TODO make a custom error type https://github.com/tokio-rs/mini-redis/blob/c3bc304ac9f4b784f24b7f7012ed5a320594eb69/src/lib.rs#L58-L69
type Responder<T> = oneshot::Sender<Result<T, Box<dyn Error + Send + Sync>>>;

// "actor" pattern: https://draft.ryhl.io/blog/actors-with-tokio/
// KV is the "handle"
// see also     // https://tokio.rs/tokio/tutorial/channels
#[derive(Clone)]
pub struct KV<V> {
    sender: mpsc::Sender<Command<V>>,
}
impl<V: 'static> KV<V>
where
    V: Debug + Send + Sync,
{
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(4);
        tokio::spawn(run(receiver));
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
        Ok(())
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
}
use Command::*;

async fn run<V>(mut rx: mpsc::Receiver<Command<V>>) {
    let kv = MicroKV::new("keys").with_pwd_clear("unsafe_pwd".to_string());
    while let Some(cmd) = rx.recv().await {
        match cmd {
            ReserveKey { key, resp } => {
                let exists = kv.exists::<()>(&key); // need ::<()> due to https://github.com/ex0dus-0x/microkv/issues/6

                // we don't care if resp.send() fails when we're sending an Error
                // ignore send errors via `let _` in failure paths
                if exists.is_err() {
                    let _ = resp.send(Err(From::from(exists.unwrap_err())));
                    continue;
                }
                let exists = exists.unwrap();
                if exists {
                    let _ = resp.send(Err(From::from(format!(
                        "kv_manager key {} already reserved",
                        key
                    ))));
                    continue;
                }
                let success = kv.put(&key, ""); // "" value marks key as reserved
                if success.is_err() {
                    let _ = resp.send(Err(From::from(success.unwrap_err())));
                    continue;
                }
                let success = resp.send(Ok(KeyReservation { key }));
                if success.is_err() {
                    // unreserve the key---no one was listening to our response
                    let key = success.unwrap_err().unwrap().key;
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
            } => {}
        }
    }
    println!("kv_manager stop");
}
