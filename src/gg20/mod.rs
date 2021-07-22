//! [proto::gg20_server::Gg20] gRPC server API
//! Available gRPCs are:
//!     [recover] - Recovers private data of a party provided a mnemonic.
//!     [keygen] - Starts keygen.
//!     [sign] - Starts sing.

// tonic cruft
use super::proto;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status};
pub mod proto_helpers;

// logging
use tracing::{error, info, span, Level};

// gRPC
mod keygen;
pub mod mnemonic;
mod protocol; // TODO delete this when no `map_tofn_to_tofnd` and `map_tofnd_to_tofn` is no longer needed
mod protocol_new;
mod recover;
mod routing;
pub mod service;
mod sign;
pub mod types;
use types::*;

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for service::Gg20Service {
    type KeygenStream = UnboundedReceiverStream<Result<proto::MessageOut, tonic::Status>>;
    type SignStream = Self::KeygenStream;

    /// Recover unary gRPC. See [recover].
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

    /// Keygen streaming gRPC. See [keygen].
    async fn keygen(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        let stream_in = request.into_inner();
        let (msg_sender, rx) = mpsc::unbounded_channel();

        // log span for keygen
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

    /// Sign sreaming gRPC. See [sign].
    async fn sign(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::SignStream>, Status> {
        let stream = request.into_inner();
        let (msg_sender, rx) = mpsc::unbounded_channel();

        // log span for sign
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
