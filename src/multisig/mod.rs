// tonic cruft
use crate::proto;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status};

// logging
use tracing::{error, info, span, Level};

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for ::Gg20Service {
    /// Keygen unary gRPC
    async fn keygen(
        &self,
        request: tonic::Request<proto::KeygenRequest>,
    ) -> Result<Response<proto::KeygenResponse>, Status> {
        let request = request.into_inner();

        let response = self.handle_keygen(request).await;
        let response = match response {
            Ok(()) => {
                info!("Keygen completed successfully!");
                proto::recover_response::Response::Success
            }
            Err(err) => {
                error!("Unable to complete multisig keygen: {}", err);
                proto::keygen_response::Response::Error("Err")
            }
        };

        Ok(Response::new(proto::RecoverResponse {
            // the prost way to convert enums to i32 https://github.com/danburkert/prost#enumerations
            response: response as i32,
        }))
    }
}

