//! Traits for mock tests
use std::{collections::HashMap, fmt::Debug};

use super::proto;

#[tonic::async_trait]
pub trait Party: Sync + Send {
    fn get_id(&self) -> &str;
    async fn execute(&mut self);
    async fn msg_in(&mut self, msg: &proto::MessageIn);
    async fn close(&mut self);
}

pub trait Deliverer: Sync {
    fn deliver(&self, msg: &proto::MessageOut, from: &str);
}

#[tonic::async_trait]
pub trait Transport<'a>: Deliverer {
    fn add_party(&mut self, p: &'a mut impl Party);
    async fn execute_all(&mut self);
    async fn close_all(&mut self);
}

pub struct DefaultTransport<'a> {
    parties: HashMap<String, &'a mut dyn Party>,
}

impl DefaultTransport<'_> {
    pub fn new() -> Self {
        Self {
            parties: HashMap::new(),
        }
    }
}

#[tonic::async_trait]
impl<'a> Transport<'a> for DefaultTransport<'a> {
    fn add_party(&mut self, p: &'a mut impl Party) {
        // `expect_none`, `unwrap_none` are unstable https://github.com/rust-lang/rust/issues/62633#issuecomment-629670374
        let old_value = self.parties.insert(p.get_id().to_string(), p);
        assert!(old_value.is_none());
    }
    async fn execute_all(&mut self) {
        let mut join_handles = Vec::<_>::with_capacity(self.parties.len());
        for (_id, party) in self.parties.iter_mut() {
            let handle = party.execute();
            join_handles.push(handle);
        }
        for h in join_handles {
            h.await;
        }
    }
    async fn close_all(&mut self) {
        for (_id, party) in self.parties.iter_mut() {
            party.close().await;
        }
    }
}

impl<'a> Deliverer for DefaultTransport<'a> {
    fn deliver(&self, msg: &proto::MessageOut, from: &str) {
        let msg = msg.data.as_ref().expect("missing data");
        let msg = match msg {
            proto::message_out::Data::Traffic(t) => t,
            _ => {
                panic!("msg must be traffic out");
            }
        };
        println!(
            "TODO deliver from [{}] to [{}] broadcast? [{}]",
            from, msg.to_party_uid, msg.is_broadcast,
        )
    }
}
