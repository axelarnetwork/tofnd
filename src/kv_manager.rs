use std::{error::Error, print};

use microkv::MicroKV;
use tokio::{
    sync::{mpsc, oneshot},
    time::delay_queue::Key,
};

// Provided by the requester and used by the manager task to send the command response back to the requester.
// TODO make a custom error type https://github.com/tokio-rs/mini-redis/blob/c3bc304ac9f4b784f24b7f7012ed5a320594eb69/src/lib.rs#L58-L69
type Responder<T> = oneshot::Sender<Result<T, Box<dyn Error + Send + Sync>>>;

/// Instantible only by acquiring a key lock
// do not derive Clone, Copy
pub struct KeyReservation {
    key: String,
}

pub enum Command {
    ReserveKey {
        key: String,
        resp: Responder<KeyReservation>,
    },
}
use Command::*;

pub async fn run(mut rx: mpsc::Receiver<Command>) {
    let kv = MicroKV::new("keys").with_pwd_clear("unsafe_pwd".to_string());
    while let Some(cmd) = rx.recv().await {
        match cmd {
            ReserveKey { key, resp } => {
                let exists = kv.exists::<()>(&key); // need ::<()> due to https://github.com/ex0dus-0x/microkv/issues/6
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
                        "WARN: kv_manager fail to respond to ReserveKey, unreserving key [{}]",
                        key
                    );
                    let _ = kv.delete(&key);
                }
            }
        }
    }
    println!("kv_manager stop");
}
