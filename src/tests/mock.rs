//! Traits for mock tests
use super::proto;

#[tonic::async_trait]
pub trait Party {
    fn execute(&self);
    fn msg_in(&self, msg: &proto::MessageIn);
    async fn close(self);
}

pub trait Deliverer: Sync {
    fn deliver(&self, msg: &proto::MessageOut);
}

// pub trait Transport: Deliverer {
//     fn add_party(p: &impl Party);
//     fn execute_all();
// }

pub struct TestDeliverer {}
impl Deliverer for TestDeliverer {
    fn deliver(&self, msg: &proto::MessageOut) {}
}
