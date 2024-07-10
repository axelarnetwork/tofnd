use tonic::Response;
use tonic::Status;

use crate::kv_manager::KvManager;
use crate::proto;

use tracing::{error, info};

/// `MultisigService` is a gRPC service wrapper around tofn's keygen and signing functions
#[derive(Clone)]
pub struct MultisigService {
    pub(super) kv_manager: KvManager,
}

/// Create a new Multisig gRPC server
impl MultisigService {
    pub fn new(kv_manager: KvManager) -> Self {
        Self { kv_manager }
    }
}

#[tonic::async_trait]
impl proto::multisig_server::Multisig for MultisigService {
    async fn key_presence(
        &self,
        request: tonic::Request<proto::KeyPresenceRequest>,
    ) -> Result<Response<proto::KeyPresenceResponse>, Status> {
        let request = request.into_inner();

        let response = match self.handle_key_presence(request).await {
            Ok(res) => {
                info!("Key presence check completed succesfully");
                res
            }
            Err(err) => {
                error!("Unable to complete key presence check: {}", err);
                proto::key_presence_response::Response::Fail
            }
        };

        Ok(Response::new(proto::KeyPresenceResponse {
            response: response as i32,
        }))
    }

    async fn keygen(
        &self,
        request: tonic::Request<proto::KeygenRequest>,
    ) -> Result<Response<proto::KeygenResponse>, Status> {
        let request = request.into_inner();
        let result = match self.handle_keygen(&request).await {
            Ok(pub_key) => {
                info!(
                    "[{}] Multisig Keygen with key id [{}] completed",
                    request.party_uid, request.key_uid
                );
                proto::keygen_response::KeygenResponse::PubKey(pub_key)
            }
            Err(err) => {
                error!(
                    "[{}] Multisig Keygen with key id [{}] failed: {}",
                    request.party_uid,
                    request.key_uid,
                    err.to_string()
                );
                proto::keygen_response::KeygenResponse::Error(err.to_string())
            }
        };

        Ok(Response::new(proto::KeygenResponse {
            keygen_response: Some(result),
        }))
    }

    async fn sign(
        &self,
        request: tonic::Request<proto::SignRequest>,
    ) -> Result<Response<proto::SignResponse>, Status> {
        let request = request.into_inner();
        let result = match self.handle_sign(&request).await {
            Ok(pub_key) => {
                info!(
                    "[{}] Multisig Sign with key id [{}] and message [{:?}] completed",
                    request.party_uid, request.key_uid, request.msg_to_sign,
                );
                proto::sign_response::SignResponse::Signature(pub_key)
            }
            Err(err) => {
                error!(
                    "[{}] Multisig sign with key id [{}] and message [{:?}] failed: {}",
                    request.party_uid,
                    request.key_uid,
                    request.msg_to_sign,
                    err.to_string()
                );
                proto::sign_response::SignResponse::Error(err.to_string())
            }
        };

        Ok(Response::new(proto::SignResponse {
            sign_response: Some(result),
        }))
    }
}
