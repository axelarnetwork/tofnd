//! Traits for mock tests
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;

use super::proto;

pub type MutexPartyMap = HashMap<String, Arc<Mutex<dyn Party>>>;
pub type WeakPartyMap = Weak<MutexPartyMap>;
pub type PartyMap = Arc<MutexPartyMap>;

#[tonic::async_trait]
pub trait Party: Sync + Send {
    // pub trait Party {
    fn get_id(&self) -> &str;
    fn set_party_map(&mut self, party_map: WeakPartyMap);
    async fn execute(&mut self);
    async fn msg_in(&mut self, msg: &proto::MessageIn);
    async fn close(&mut self);
}

#[tonic::async_trait]
pub trait Deliverer: Sync + Send {
    // pub trait Deliverer {
    async fn deliver(&self, msg: &proto::MessageOut, from: &str);
}

pub async fn execute_all(party_map: PartyMap) {
    // TODO does each execution need to be started before any await???
    // let mut join_handles = Vec::<_>::with_capacity(party_map.len());
    // for (_id, party) in party_map.iter() {
    //     let handle = async move { party.lock().await.execute().await };
    //     join_handles.push(handle);
    // }
    // for h in join_handles {
    //     h.await;
    // }
    for (_id, party) in party_map.iter() {
        party.lock().await.execute().await;
    }
}

pub async fn close_all(party_map: PartyMap) {
    for (_id, party) in party_map.iter() {
        party.lock().await.close().await;
    }
}

pub async fn deliver(party_map: WeakPartyMap, msg: &proto::MessageOut, from: &str) {
    let party_map = party_map.upgrade().unwrap();
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
            .lock()
            .await
            .msg_in(&msg_in)
            .await;
        return;
    }

    // broadcast message
    for (id, recipient) in party_map.iter() {
        if id == from {
            continue; // don't broadcast to myself
        }
        recipient.lock().await.msg_in(&msg_in).await;
    }
}
