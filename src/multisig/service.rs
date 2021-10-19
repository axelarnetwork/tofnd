use tonic::Response;
use tonic::Status;

use crate::kv_manager::KvManager;
use crate::proto;

/// Gg20Service
#[derive(Clone)]
pub struct MultisigService {
    pub(super) kv_manager: KvManager,
}

/// create a new Multisig gRPC server
pub fn new_service(kv_manager: KvManager) -> impl proto::multisig_server::Multisig {
    MultisigService { kv_manager }
}

#[tonic::async_trait]
impl proto::multisig_server::Multisig for MultisigService {
    async fn keygen(
        &self,
        request: tonic::Request<proto::KeygenRequest>,
    ) -> Result<Response<proto::KeygenResponse>, Status> {
        let result = match self.handle_keygen(request.into_inner()).await {
            Ok(pub_key) => proto::keygen_response::KeygenResponse::PubKey(pub_key),
            Err(err) => proto::keygen_response::KeygenResponse::Error(err.to_string()),
        };

        Ok(Response::new(proto::KeygenResponse {
            keygen_response: Some(result),
        }))
    }

    async fn sign(
        &self,
        request: tonic::Request<proto::SignRequest>,
    ) -> Result<Response<proto::SignResponse>, Status> {
        let result = match self.handle_sign(request.into_inner()).await {
            Ok(pub_key) => proto::sign_response::SignResponse::Signature(pub_key),
            Err(err) => proto::sign_response::SignResponse::Error(err.to_string()),
        };

        Ok(Response::new(proto::SignResponse {
            sign_response: Some(result),
        }))
    }
}
