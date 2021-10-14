//! This module creates and executes the keygen protocol
//! On success it returns [super::TofnKeygenOutput]. A successful [Keygen] can produce either an Ok(SecretKeyShare) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [anyhow!] error if [Keygen] struct cannot be instantiated.

use crate::grpc::keygen::types::common::{
    Gg20TofndKeygenOutput, KeygenContext, MultisigTofndKeygenOutput,
};
use crate::grpc::{proto, service::Service, ProtocolCommunication};
use crate::TofndResult;

// logging
use tracing::{info, Span};

pub(in super::super) enum KeygenOutput {
    Gg20(Gg20TofndKeygenOutput),
    Multisig(MultisigTofndKeygenOutput),
}
pub(in super::super) type TofndKeygenOutput = TofndResult<KeygenOutput>;

impl Service {
    pub(in super::super) async fn execute_keygen(
        &self,
        chans: ProtocolCommunication<
            Option<proto::TrafficIn>,
            Result<proto::MessageOut, tonic::Status>,
        >,
        ctx: &KeygenContext,
        execute_span: Span,
    ) -> TofndKeygenOutput {
        // try to create keygen with context
        let res = match ctx {
            KeygenContext::Gg20(ctx) => {
                KeygenOutput::Gg20(self.execute_gg20_keygen(chans, ctx, execute_span).await)
            }
            KeygenContext::Multisig(ctx) => {
                KeygenOutput::Multisig(self.execute_multisig_keygen(chans, ctx, execute_span).await)
            }
        };

        info!("Keygen completed");
        Ok(res)
    }
}
