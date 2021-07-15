use tofn::protocol::gg20::MessageDigest;
use tokio_stream::wrappers::UnboundedReceiverStream;

use super::proto;

// tonic cruft
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

// for routing messages
use crate::TofndError;

use tracing::{error, info, span, Level};

pub mod mnemonic;

mod recover;
mod routing;
pub mod types;
use types::*;
pub mod service;
use service::Gg20Service;
mod keygen;
pub mod proto_helpers;
mod protocol;
mod sign;

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for Gg20Service {
    // type KeygenStream = Pin<Box<dyn Stream<Item = Result<proto::MessageOut, Status>> + Send + Sync + 'static>>;
    type KeygenStream = UnboundedReceiverStream<Result<proto::MessageOut, tonic::Status>>;
    type SignStream = Self::KeygenStream;

    async fn recover(
        &self,
        request: tonic::Request<proto::RecoverRequest>,
    ) -> Result<Response<proto::RecoverResponse>, Status> {
        let request = request.into_inner();

        let mut gg20 = self.clone();
        let response = gg20.handle_recover(request).await;

        let response = match response {
            Ok(()) => {
                info!("Recovery completed successfully!");
                proto::recover_response::Response::Success
            }
            Err(err) => {
                error!("Unable to complete recovery: {}", err);
                proto::recover_response::Response::Fail
            }
        };

        Ok(Response::new(proto::RecoverResponse {
            // the prost way to convert enums to i32 https://github.com/danburkert/prost#enumerations
            response: response as i32,
        }))
    }

    async fn keygen(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        let stream_in = request.into_inner();
        let (msg_sender, rx) = mpsc::unbounded_channel();

        let span = span!(Level::INFO, "Keygen");
        let _enter = span.enter();
        let s = span.clone();
        let mut gg20 = self.clone();
        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = gg20.handle_keygen(stream_in, msg_sender, s).await {
                error!("keygen failure: {:?}", e);
                return;
            }
        });
        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }

    async fn sign(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::SignStream>, Status> {
        let stream = request.into_inner();
        let (msg_sender, rx) = mpsc::unbounded_channel();

        // span logs for sign
        let span = span!(Level::INFO, "Sign");
        let _enter = span.enter();
        let s = span.clone();
        let mut gg20 = self.clone();
        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = gg20.handle_sign(stream, msg_sender, s).await {
                error!("sign failure: {:?}", e);
                return;
            }
        });
        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }
}
