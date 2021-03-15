use crate::proto;
use std::collections::HashMap;
use tokio::sync::mpsc::{channel, Receiver, Sender};

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
    );
    async fn shutdown(mut self);
    fn get_db_path(&self) -> std::path::PathBuf;
}

pub(super) type SenderReceiver = (Sender<proto::MessageIn>, Receiver<proto::MessageIn>);
#[derive(Clone)]
pub(super) struct Deliverer {
    senders: HashMap<String, Sender<proto::MessageIn>>, // (party_uid, sender)
}
impl Deliverer {
    // fn new(party_count: usize) -> (Self, Vec<SenderReceiver>) {
    //     Self::with_party_ids(
    //         &(0..party_count)
    //             .map(|i| format!("{}", (b'A' + i as u8) as char))
    //             .collect::<Vec<String>>(),
    //     )
    // }
    pub(super) fn with_party_ids(party_ids: &[String]) -> (Self, Vec<SenderReceiver>) {
        let channels: Vec<SenderReceiver> = (0..party_ids.len()).map(|_| channel(4)).collect();
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
        // println!(
        //     "deliver from [{}] to [{}] broadcast? [{}]",
        //     from, msg.to_party_uid, msg.is_broadcast,
        // );

        // simulate wire transmission: translate proto::MessageOut to proto::MessageIn
        let msg_in = proto::MessageIn {
            data: Some(proto::message_in::Data::Traffic(proto::TrafficIn {
                from_party_uid: from.to_string(),
                is_broadcast: msg.is_broadcast,
                payload: msg.payload.clone(),
            })),
        };

        // p2p message
        if !msg.is_broadcast {
            self.senders
                .get_mut(&msg.to_party_uid)
                .unwrap()
                .send(msg_in)
                .await
                .unwrap();
            return;
        }

        // broadcast message
        for (id, sender) in self.senders.iter_mut() {
            if id == from {
                continue; // don't broadcast to myself
            }
            sender.send(msg_in.clone()).await.unwrap();
        }
    }
}
