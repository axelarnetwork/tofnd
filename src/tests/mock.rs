use crate::proto;
use proto::message_out::SignResult;
use std::collections::HashMap;
use tokio::sync::mpsc;

#[tonic::async_trait]
pub(super) trait Party: Sync + Send {
    async fn execute_keygen(
        &mut self,
        init: proto::KeygenInit,
        channels: SenderReceiver,
        delivery: Deliverer,
    );
    async fn execute_sign(
        &mut self,
        init: proto::SignInit,
        channels: SenderReceiver,
        delivery: Deliverer,
        my_uid: &str,
    ) -> SignResult;
    async fn shutdown(mut self);
    fn get_db_path(&self) -> std::path::PathBuf;
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
    pub async fn deliver(&mut self, msg: &proto::MessageOut, from: &str) {
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
        for (_, sender) in self.senders.iter_mut() {
            sender.send(msg_in.clone()).unwrap();
        }
    }
}
