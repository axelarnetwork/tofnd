// use crate::proto::{self, MessageOut};
// use super::proto::gg20_server::{Gg20, Gg20Server};
// use super::proto::{self, MessageOut};
use super::proto;
// use proto::message_out::Data;

// tonic cruft
use tonic::{Request, Response, Status};
use tokio::sync::mpsc;
// use std::pin::Pin;
// use futures_core::Stream;

#[derive(Debug)]
pub struct GG20Service;

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for GG20Service {
    // type KeygenStream = Pin<Box<dyn Stream<Item = Result<proto::MessageOut, Status>> + Send + Sync + 'static>>;
    type KeygenStream = mpsc::Receiver<Result<proto::MessageOut, Status>>;

    async fn get_key(&self, request: Request<proto::Uid>) -> Result<Response<proto::Bytes>, Status> {
        println!("get_key uid {:?}", request.get_ref());
        Ok(Response::new(proto::Bytes{payload: vec!(1,2,3)}))
    }

    async fn keygen(
        &self,
        _request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status>
    {
        let (mut tx, rx) = mpsc::channel(4);

        tokio::spawn(async move {
            // send a test dummy message
            let msg = proto::MessageOut {
                data: Some(proto::message_out::Data::Traffic(
                    proto::TrafficOut {
                        to_party_uid: String::from("test_id"),
                        payload: vec![5,6,7,8],
                        is_broadcast: true,
                    }
                )),
            };
            tx.send(Ok(msg)).await.unwrap();
        });
        Ok(Response::new(rx))
    }
}