//! useful types and default paths for the kv_manager

use std::fmt::Debug;

// default KV store names
pub const DEFAULT_KV_NAME: &str = "kv";

/// default path of kv store
/// the full name of the kv store is "DEFAULT_KV_PATH/kv_name"
pub(super) const DEFAULT_KV_PATH: &str = "kvstore";

/// default value for reserved key
pub(super) const DEFAULT_RESERVE: &str = "";

/// Returned from a successful `ReserveKey` command
#[derive(Debug)] // disallow derive Clone, Copy
pub struct KeyReservation {
    pub(super) key: String,
}
/// kv store needs PartialEq to complare values
impl PartialEq for KeyReservation {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

// Provided by the requester and used by the manager task to send the command response back to the requester.
type Responder<T> = tokio::sync::oneshot::Sender<super::error::InnerKvResult<T>>;

#[derive(Debug)]
pub(super) enum Command<V> {
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
    Delete {
        key: String,
        resp: Responder<()>,
    },
}
