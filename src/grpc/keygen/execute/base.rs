use crate::grpc::{
    keygen::types::common::{KeygenContext, KeygenOutput, TofndKeygenOutput},
    proto,
    service::Service,
    types::common::ProtocolCommunication,
};

// logging
use tracing::{info, Span};

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
