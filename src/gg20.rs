// use super::proto::gg20_server::{Gg20, Gg20Server};
use super::proto;

// tonic cruft
use tonic::{Request, Response, Status};
use std::pin::Pin;
use futures_core::Stream;

#[derive(Debug)]
pub struct GG20Service;

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for GG20Service {
    type KeygenStream = Pin<Box<dyn Stream<Item = Result<proto::MessageOut, Status>> + Send + Sync + 'static>>;

    async fn keygen(
        &self,
        _request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        unimplemented!()
    }
}