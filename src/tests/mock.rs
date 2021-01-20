//! Traits for mock tests
use std::collections::HashMap;
use tokio::sync::Mutex;
// use std::sync::Mutex;

use super::proto;

#[tonic::async_trait]
pub trait Party: Sync + Send {
    // pub trait Party {
    fn get_id(&self) -> &str;
    async fn execute(&mut self);
    async fn msg_in(&mut self, msg: &proto::MessageIn);
    async fn close(&mut self);
}

#[tonic::async_trait]
pub trait Deliverer: Sync + Send {
    // pub trait Deliverer {
    async fn deliver(&self, msg: &proto::MessageOut, from: &str);
}

#[tonic::async_trait]
pub trait Transport: Deliverer {
    async fn add_party(&mut self, p: Box<dyn Party>);
    async fn execute_all(&mut self);
    async fn close_all(&mut self);
}

pub struct DefaultTransport {
    parties: Mutex<HashMap<String, Box<dyn Party>>>,
}

impl DefaultTransport {
    pub fn new() -> Self {
        Self::with_capacity(0)
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            parties: Mutex::new(HashMap::with_capacity(capacity)),
        }
    }
}

#[tonic::async_trait]
impl Transport for DefaultTransport {
    async fn add_party(&mut self, p: Box<dyn Party>) {
        // `expect_none`, `unwrap_none` are unstable https://github.com/rust-lang/rust/issues/62633#issuecomment-629670374
        let old_value = self.parties.lock().await.insert(p.get_id().to_string(), p); // TODO clone
        assert!(old_value.is_none());
    }
    async fn execute_all(&mut self) {
        let mut parties = self.parties.lock().await;
        let mut join_handles = Vec::<_>::with_capacity(parties.len());
        for (_id, party) in parties.iter_mut() {
            let handle = party.execute();
            join_handles.push(handle);
        }
        for h in join_handles {
            h.await;
        }
    }
    async fn close_all(&mut self) {
        let mut parties = self.parties.lock().await;
        for (_id, party) in parties.iter_mut() {
            party.close().await;
        }
    }
}

#[tonic::async_trait]
impl<'a> Deliverer for DefaultTransport {
    async fn deliver(&self, msg: &proto::MessageOut, from: &str) {
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

        // simulate wire transmission: translate pb.MessageOut to pb.MessageIn
        let msg_in = proto::MessageIn {
            data: Some(proto::message_in::Data::Traffic(proto::TrafficIn {
                from_party_uid: from.to_string(),
                is_broadcast: msg.is_broadcast,
                payload: msg.payload.clone(),
            })),
        };

        // TODO broadcast
        if !msg.is_broadcast {
            let recipient = self
                .parties
                .lock()
                .await
                .get_mut(&msg.to_party_uid)
                .unwrap()
                .msg_in(&msg_in)
                .await;
            return;
        }

        let mut parties = self.parties.lock().await;
        for (_id, recipient) in parties.iter_mut() {
            recipient.msg_in(&msg_in).await;
        }
    }
}
