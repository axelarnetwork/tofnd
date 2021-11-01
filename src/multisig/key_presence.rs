//! This module handles the key_presence gRPC.
//! Request includes [proto::message_in::Data::KeyPresenceRequest] struct and encrypted recovery info.
//! The recovery info is decrypted by party's mnemonic seed and saved in the KvStore.

use super::service::MultisigService;

// logging
use tracing::info;

// error handling
use crate::{proto, TofndResult};

impl MultisigService {
    pub(super) async fn handle_key_presence(
        &self,
        request: proto::KeyPresenceRequest,
    ) -> TofndResult<proto::key_presence_response::Response> {
        // check if mnemonic is available
        let _ = self.kv_manager.seed().await?;

        // check if requested key exists
        if self.kv_manager.kv().exists(&request.key_uid).await? {
            info!(
                "Found session-id {} in kv store during multisig key presence check",
                request.key_uid
            );
            Ok(proto::key_presence_response::Response::Present)
        } else {
            info!(
                "Did not find session-id {} in kv store during multisig key presence check",
                request.key_uid
            );
            Ok(proto::key_presence_response::Response::Absent)
        }
    }
}
