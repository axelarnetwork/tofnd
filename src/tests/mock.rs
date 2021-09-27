use crate::proto;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::error;

use super::{GrpcKeygenResult, GrpcSignResult};

#[tonic::async_trait]
pub(super) trait Party: Sync + Send {
    async fn execute_keygen(
        &mut self,
        init: proto::KeygenInit,
        channels: SenderReceiver,
        delivery: Deliverer,
    ) -> GrpcKeygenResult;
    async fn execute_recover(
        &mut self,
        keygen_init: proto::KeygenInit,
        keygen_output: proto::KeygenOutput,
    );
    async fn execute_key_presence(&mut self, key_uid: String) -> bool;
    async fn execute_sign(
        &mut self,
        init: proto::SignInit,
        channels: SenderReceiver,
        delivery: Deliverer,
        my_uid: &str,
    ) -> GrpcSignResult;
    async fn shutdown(mut self);
    fn get_root(&self) -> std::path::PathBuf;
}

pub(super) type SenderReceiver = (
    mpsc::UnboundedSender<proto::MessageIn>,
    mpsc::UnboundedReceiver<proto::MessageIn>,
);
#[derive(Clone)]
pub(super) struct Deliverer {
    senders: HashMap<String, mpsc::UnboundedSender<proto::MessageIn>>, // (party_uid, sender)
}
impl Deliverer {
    pub(super) fn with_party_ids(party_ids: &[String]) -> (Self, Vec<SenderReceiver>) {
        let channels: Vec<SenderReceiver> = (0..party_ids.len())
            .map(|_| mpsc::unbounded_channel())
            .collect();
        let senders = party_ids
            .iter()
            .cloned()
            .zip(channels.iter().map(|(tx, _)| tx.clone()))
            .collect();
        (Deliverer { senders }, channels)
    }
    pub fn deliver(&self, msg: &proto::MessageOut, from: &str) {
        let msg = msg.data.as_ref().expect("missing data");
        let msg = match msg {
            proto::message_out::Data::Traffic(t) => t,
            _ => {
                panic!("msg must be traffic out");
            }
        };

        // simulate wire transmission: translate proto::MessageOut to proto::MessageIn
        let msg_in = proto::MessageIn {
            data: Some(proto::message_in::Data::Traffic(proto::TrafficIn {
                from_party_uid: from.to_string(),
                is_broadcast: msg.is_broadcast,
                payload: msg.payload.clone(),
            })),
        };

        // deliver all msgs to all parties (even p2p msgs)
        for (_, sender) in self.senders.iter() {
            // we need to catch for errors in case the receiver's channel closes unexpectedly
            if let Err(err) = sender.send(msg_in.clone()) {
                error!("Error in deliverer while sending message: {:?}", err);
            }
        }
    }
    pub fn send_timeouts(&self, secs: u64) {
        let abort = proto::message_in::Data::Abort(false);
        let msg_in = proto::MessageIn { data: Some(abort) };

        // allow honest parties to exchange messages for this round
        let t = std::time::Duration::from_secs(secs);
        std::thread::sleep(t);

        // deliver to all parties
        for (_, sender) in self.senders.iter() {
            sender.send(msg_in.clone()).unwrap();
        }
    }
}
