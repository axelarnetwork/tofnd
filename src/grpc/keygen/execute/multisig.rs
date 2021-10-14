//! This module creates and executes the keygen protocol
//! On success it returns [super::TofnKeygenOutput]. A successful [Keygen] can produce either an Ok(SecretKeyShare) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [anyhow!] error if [Keygen] struct cannot be instantiated.

use crate::grpc::keygen::types::common::MultisigTofndKeygenOutput;
use crate::grpc::keygen::types::multisig::MultisigContext;
use crate::grpc::{proto, service::Service, ProtocolCommunication};
use crate::{grpc::protocol, TofndResult};
use tofn::multisig::keygen::{new_keygen, KeygenProtocol};

// logging
use tracing::{info, Span};

// error handling
use anyhow::anyhow;

impl Service {
    /// create a new multisig keygen protocol.
    fn new_multisig_keygen(&self, ctx: &MultisigContext) -> TofndResult<KeygenProtocol> {
        new_keygen(
            ctx.share_counts()?,
            ctx.base.threshold,
            ctx.tofnd_index(),
            ctx.base.tofnd_subindex,
            &ctx.secret_recovery_key,
            &ctx.session_nonce,
        )
        .map_err(|_| anyhow!("gg20 keygen protocol instantiation failed"))
    }

    /// create and execute keygen protocol and returning the result.
    /// if the protocol cannot be instantiated, return an [anyhow!] error
    pub(in super::super) async fn execute_multisig_keygen(
        &self,
        chans: ProtocolCommunication<
            Option<proto::TrafficIn>,
            Result<proto::MessageOut, tonic::Status>,
        >,
        ctx: &MultisigContext,
        execute_span: Span,
    ) -> MultisigTofndKeygenOutput {
        // try to create keygen with context
        let keygen = self.new_multisig_keygen(ctx)?;

        // execute protocol and wait for completion
        let protocol_result = protocol::execute_protocol(
            keygen,
            chans,
            &ctx.base_uids(),
            &ctx.base_share_counts(),
            execute_span.clone(),
        )
        .await;

        let res = protocol_result
            .map_err(|err| anyhow!("Keygen was not completed due to error: {}", err))?;

        info!("Keygen completed");
        Ok(res)
    }
}