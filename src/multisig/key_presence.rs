//! This module handles the key_presence gRPC.
//! Request includes [proto::message_in::Data::KeyPresenceRequest] struct and encrypted recovery info.

use super::service::MultisigService;

// logging
use tracing::debug;

// error handling
use crate::{proto, TofndResult};

impl MultisigService {
    pub(super) async fn handle_key_presence(
        &self,
        request: proto::KeyPresenceRequest,
    ) -> TofndResult<proto::key_presence_response::Response> {
        // check if mnemonic is available
        let _ = self.kv_manager.seed().await?;

        // key presence for multisig always returns `Present`.
        // this is done in order to not break compatibility with axelar-core
        // TODO: better handling for multisig key presence.
        debug!(
            "[{}] key presence check for multisig always return Present",
            request.key_uid
        );
        Ok(proto::key_presence_response::Response::Present)
    }
}
