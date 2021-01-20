//! Traits for mock tests
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

use super::proto;

pub type MutexPartyMap = HashMap<String, Sender<proto::MessageIn>>;
pub type PartyMap = Arc<MutexPartyMap>;

#[tonic::async_trait]
pub trait Party: Sync + Send {
    // pub trait Party {
    fn get_id(&self) -> &str;
    fn get_tx(&self) -> Sender<proto::MessageIn>;
    fn set_party_map(&mut self, party_map: PartyMap);
    async fn execute(&mut self);
    async fn msg_in(&mut self, msg: &proto::MessageIn);
    async fn close(&mut self);
}

#[tonic::async_trait]
pub trait Deliverer: Sync + Send {
    // pub trait Deliverer {
    async fn deliver(&self, msg: &proto::MessageOut, from: &str);
}

pub async fn deliver(party_map: PartyMap, msg: &proto::MessageOut, from: &str) {
    let msg = msg.data.as_ref().expect("missing data");
    let msg = match msg {
        proto::message_out::Data::Traffic(t) => t,
        _ => {
            panic!("msg must be traffic out");
        }
    };
    println!(
        "deliver from [{}] to [{}] broadcast? [{}]",
        from, msg.to_party_uid, msg.is_broadcast,
    );

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
        party_map
            .get(&msg.to_party_uid)
            .unwrap()
            .clone()
            .send(msg_in)
            .await
            .unwrap();
        return;
    }

    // broadcast message
    for (id, recipient) in party_map.iter() {
        if id == from {
            continue; // don't broadcast to myself
        }
        recipient.clone().send(msg_in.clone()).await.unwrap();
    }
}
