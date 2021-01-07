// use crate::proto::{self, MessageOut};
// use super::proto::gg20_server::{Gg20, Gg20Server};
// use super::proto::{self, MessageOut};
use super::proto;
// use proto::message_out::Data;

// tonic cruft
use tonic::{Request, Response, Status};
use tokio::{
    sync::mpsc,
    stream::StreamExt, // TODO instead use futures_util::StreamExt; as recommended https://github.com/hyperium/tonic/blob/master/examples/routeguide-tutorial.md ?
};
// use futures_util::StreamExt;
// use std::pin::Pin;
// use futures_core::Stream;
use std::convert::TryFrom;

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
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status>
    {
        let mut stream = request.into_inner();
        let (mut tx, rx) = mpsc::channel(4);

        // the first message in the stream contains init data
	    // block on this message; we can't proceed without it
        let msg_init = stream.next().await
            .ok_or_else(|| Status::invalid_argument("stream closed by client before sending any messages"))??
            .data.ok_or_else(|| Status::invalid_argument("missing data for stream message"))?;
        let init = match msg_init {
            proto::message_in::Data::KeygenInit(k) => k,
            _ => return Err(Status::invalid_argument("first message must be keygen init data")),
        };
        keygen_check_args(&init)?;

        println!("received keygen init {:?}", init);

        // while let Some(point) = stream.next().await {
        // }
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

fn keygen_check_args(args : &proto::KeygenInit) -> Result<(), Status> {
    let my_index = usize::try_from(args.my_party_index)
        .map_err(|_| Status::invalid_argument("my_party_index can't convert to usize"))?;
    let threshold = usize::try_from(args.threshold)
        .map_err(|_| Status::invalid_argument("threshold can't convert to usize"))?;
    if my_index >= args.party_uids.len() {
        return Err(Status::invalid_argument(format!("my_party_index {} out of range for {} parties", my_index, args.party_uids.len())));
    }
    if threshold >= args.party_uids.len() {
        return Err(Status::invalid_argument(format!("threshold {} out of range for {} parties", threshold, args.party_uids.len())));
    }
    Ok(())
}
