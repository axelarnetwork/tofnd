//! This module creates and executes the sign protocol
//! On success it returns [super::TofndSignOutput]. A successful sign execution can produce either an Ok(Vec<u8>) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [super::TofndError] if [Sign] struct cannot be instantiated.

use super::{
    proto,
    types::{Context, TofndSignOutput},
    Gg20Service, ProtocolCommunication,
};
use crate::gg20::protocol;
use tofn::gg20::sign::new_sign;

// logging
use tracing::{info, Span};

impl Gg20Service {
    /// create and execute sign protocol and returning the result.
    /// if the protocol cannot be instantiated, return a TofndError
    pub(super) async fn execute_sign(
        &self,
        chans: ProtocolCommunication<
            Option<proto::TrafficIn>,
            Result<proto::MessageOut, tonic::Status>,
        >,
        ctx: &Context,
        execute_span: Span,
    ) -> TofndSignOutput {
        // try to create sign with context
        let sign = match new_sign(
            &ctx.group(),
            &ctx.share,
            &ctx.sign_parties,
            &ctx.msg_to_sign(),
            #[cfg(feature = "malicious")]
            self.behaviours.sign.clone(),
        ) {
            Ok(sign) => sign,
            Err(_) => {
                return Err(From::from("sign instantiation failed"));
            }
        };

        // execute protocol and wait for completion
        let protocol_result = protocol::execute_protocol(
            sign,
            chans,
            // &ctx.sign_init.participant_uids,
            &ctx.sign_uids(),
            &ctx.sign_share_counts,
            execute_span.clone(),
        )
        .await;

        match protocol_result {
            Ok(res) => {
                info!("Sign completed");
                Ok(res)
            }
            Err(err) => Err(From::from(format!(
                "Sign was not completed due to error: {}",
                err
            ))),
        }
    }
}
